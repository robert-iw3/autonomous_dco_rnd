"""
test_phase1_pipeline.py -- Offline validation tests for Phase 1 scripts.

Covers:
  06_sandbox_runner.py   -- atomic arg substitution, sensor capture parsing,
                           dry-run queue I/O, result schema
  07_feed_ingest.py      -- 4-stage atomic filter logic, query index generation,
                           kill chain parsing, sigma validate gap detection
  BeaconML.py (windows)  -- flow-stat field computation correctness

All tests are fully offline (no Firecracker, no network, no GPU).
"""

from __future__ import annotations

import json
import sys
import tempfile
import os
from pathlib import Path

import pytest

# ── Path helpers ───────────────────────────────────────────────────────────────
REPO = Path(__file__).parent.parent
MLOPS_SCRIPTS = REPO / "mlops" / "scripts"

# Ensure scripts are importable
sys.path.insert(0, str(MLOPS_SCRIPTS))
sys.path.insert(0, str(REPO.parent / "windows" / "prototypes" / "c2_sensor"))


# ══════════════════════════════════════════════════════════════════════════════
# BeaconML.py -- Windows WFP flow-stat computation (WS-1)
# ══════════════════════════════════════════════════════════════════════════════

class TestBeaconMLWindowsFlowStats:
    """WS-1: Validate that compute_flow_stats produces correct 8D c2_math fields."""

    def _import(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "BeaconML_win",
            str(REPO.parent / "windows" / "prototypes" / "c2_sensor" / "BeaconML.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _packets(self, n=5, interval=30.0, size=128, direction="out"):
        return [{"ts": i * interval, "size": size, "direction": direction,
                 "payload_bytes": bytes(range(32))} for i in range(n)]

    def test_field_names_match_c2_math_schema(self):
        """FlowStats namedtuple must have exactly the 8 c2_math fields in order."""
        bml = self._import()
        fs = bml.FlowStats
        expected = ["outbound_ratio", "packet_size_mean", "packet_size_std",
                    "interval", "cv", "entropy", "cmd_entropy", "score"]
        assert list(fs._fields) == expected, \
            f"FlowStats fields mismatch: {list(fs._fields)} != {expected}"

    def test_safe_zero_on_single_packet(self):
        """Fewer than 2 packets returns the _SAFE_ZERO default."""
        bml = self._import()
        stats = bml.compute_flow_stats([{"ts": 0.0, "size": 128, "direction": "out"}])
        assert stats == bml._SAFE_ZERO

    def test_outbound_ratio_all_outbound(self):
        bml = self._import()
        packets = self._packets(4, direction="out")
        stats = bml.compute_flow_stats(packets)
        assert stats.outbound_ratio == pytest.approx(1.0, abs=0.001)

    def test_outbound_ratio_mixed(self):
        bml = self._import()
        out = [{"ts": float(i), "size": 100, "direction": "out"} for i in range(4)]
        inp = [{"ts": float(i + 10), "size": 100, "direction": "in"} for i in range(4)]
        stats = bml.compute_flow_stats(out + inp)
        assert stats.outbound_ratio == pytest.approx(0.5, abs=0.001)

    def test_packet_size_mean_and_std(self):
        bml = self._import()
        packets = [{"ts": float(i), "size": 100 + i * 10,
                    "direction": "out"} for i in range(5)]
        stats = bml.compute_flow_stats(packets)
        # sizes: 100,110,120,130,140 -- mean=120, std≈14.14
        assert stats.packet_size_mean == pytest.approx(120.0, abs=0.1)
        assert stats.packet_size_std  == pytest.approx(14.14, abs=0.5)

    def test_interval_and_cv_regular_beacon(self):
        """Perfectly regular 30s intervals → cv ≈ 0, score = 0 (mechanical sync)."""
        bml = self._import()
        packets = self._packets(n=6, interval=30.0)
        stats = bml.compute_flow_stats(packets)
        assert stats.interval == pytest.approx(30.0, abs=0.1)
        assert stats.cv == pytest.approx(0.0, abs=0.01)

    def test_cv_jittered_intervals(self):
        """Jittered intervals (simulated C2 beacon) produce non-zero cv."""
        import statistics as _stats
        bml = self._import()
        intervals = [30.0, 32.1, 28.5, 31.0, 29.8, 30.7]
        ts = [sum(intervals[:i]) for i in range(len(intervals) + 1)]
        packets = [{"ts": t, "size": 128, "direction": "out"} for t in ts]
        stats = bml.compute_flow_stats(packets)
        assert 0.0 < stats.cv < 0.5   # jittered but regular

    def test_payload_entropy(self):
        """Uniform byte distribution → entropy ≈ 8 bits."""
        bml = self._import()
        packets = [{"ts": float(i), "size": 256, "direction": "out",
                    "payload_bytes": bytes(range(256))} for i in range(3)]
        stats = bml.compute_flow_stats(packets)
        assert stats.entropy == pytest.approx(8.0, abs=0.01)

    def test_cmd_entropy_empty(self):
        bml = self._import()
        stats = bml.compute_flow_stats(self._packets(), query_string="")
        assert stats.cmd_entropy == 0.0

    def test_cmd_entropy_nonzero(self):
        bml = self._import()
        stats = bml.compute_flow_stats(self._packets(), query_string="GET /beacon HTTP/1.1")
        assert stats.cmd_entropy > 0.0

    def test_score_range(self):
        """Score must always be in [0, 100]."""
        bml = self._import()
        stats = bml.compute_flow_stats(self._packets())
        assert 0.0 <= stats.score <= 100.0

    def test_detect_beaconing_wfp_returns_three_tuple(self):
        bml = self._import()
        result = bml.detect_beaconing_wfp(self._packets(n=6, interval=60.0))
        assert len(result) == 3
        stats, is_beacon, reason = result
        assert isinstance(is_beacon, bool)
        assert isinstance(reason, str)

    def test_all_fields_are_floats(self):
        bml = self._import()
        stats = bml.compute_flow_stats(self._packets())
        for field in bml.FlowStats._fields:
            assert isinstance(getattr(stats, field), float), \
                f"Field {field} is not float"


# ══════════════════════════════════════════════════════════════════════════════
# 06_sandbox_runner.py -- Queue I/O, arg substitution, capture parsing
# ══════════════════════════════════════════════════════════════════════════════

class TestSandboxRunner:
    """06_sandbox_runner.py: validate queue schema, arg substitution, capture parsing."""

    def _import(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "sandbox_runner",
            str(MLOPS_SCRIPTS / "06_sandbox_runner.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_arg_substitution_simple(self):
        sr = self._import()
        cmd = sr._substitute_args(
            "Invoke-Mimikatz -DumpCreds #{pid}",
            {"pid": {"default": "1234"}}
        )
        assert cmd == "Invoke-Mimikatz -DumpCreds 1234"

    def test_arg_substitution_multiple(self):
        sr = self._import()
        cmd = sr._substitute_args(
            "cmd.exe /c #{cmd} > #{out}",
            {"cmd": {"default": "whoami"}, "out": {"default": "C:\\tmp\\out.txt"}}
        )
        assert cmd == "cmd.exe /c whoami > C:\\tmp\\out.txt"

    def test_arg_substitution_no_match_preserves_template(self):
        sr = self._import()
        cmd = sr._substitute_args("echo hello", {})
        assert cmd == "echo hello"

    def test_parse_sensor_captures_empty(self):
        sr = self._import()
        result = sr._parse_sensor_captures("")
        assert result["verdict"] == "false_positive"
        assert result["captures"]["sysmon"] == []
        assert result["captures"]["network_tap"] == {}
        assert result["captures"]["auditd_delta"] == []

    def test_parse_sensor_captures_verdict_exploited(self):
        sr = self._import()
        raw = "some output\nNEXUS_VERDICT: exploited\nmore output"
        result = sr._parse_sensor_captures(raw)
        assert result["verdict"] == "exploited"

    def test_parse_sensor_captures_verdict_mitigated(self):
        sr = self._import()
        raw = "NEXUS_VERDICT: mitigated"
        assert sr._parse_sensor_captures(raw)["verdict"] == "mitigated"

    def test_parse_sensor_captures_unknown_verdict_is_fp(self):
        sr = self._import()
        raw = "NEXUS_VERDICT: unknown_tag"
        assert sr._parse_sensor_captures(raw)["verdict"] == "false_positive"

    def test_parse_sensor_captures_sysmon_json(self):
        sr = self._import()
        event = {"EventID": 10, "SourceImage": "cmd.exe", "TargetImage": "lsass.exe"}
        raw = f'NEXUS_SYSMON: {json.dumps(event)}\nNEXUS_VERDICT: exploited'
        result = sr._parse_sensor_captures(raw)
        assert result["captures"]["sysmon"] == [event]

    def test_parse_sensor_captures_multiple_sysmon_events(self):
        sr = self._import()
        raw = (
            'NEXUS_SYSMON: {"EventID": 1, "Image": "cmd.exe"}\n'
            'NEXUS_SYSMON: {"EventID": 3, "DestinationIp": "10.0.0.1"}\n'
            'NEXUS_VERDICT: exploited\n'
        )
        result = sr._parse_sensor_captures(raw)
        assert len(result["captures"]["sysmon"]) == 2

    def test_parse_sensor_captures_nettap_merges(self):
        sr = self._import()
        raw = 'NEXUS_NETTAP: {"dst_port": 443, "bytes_out": 9999}'
        result = sr._parse_sensor_captures(raw)
        assert result["captures"]["network_tap"]["dst_port"] == 443

    def test_parse_sensor_captures_malformed_json_skipped(self):
        sr = self._import()
        raw = "NEXUS_SYSMON: not valid json\nNEXUS_VERDICT: mitigated"
        result = sr._parse_sensor_captures(raw)
        assert result["captures"]["sysmon"] == []
        assert result["verdict"] == "mitigated"

    def test_dry_run_queue_i_o(self, tmp_path):
        """dry-run must iterate queue and log without writing results file."""
        sr = self._import()
        queue = tmp_path / "q.jsonl"
        queue.write_text(json.dumps({
            "atomic_guid":      "aaa-bbb",
            "attack_technique": "T1055",
            "display_name":     "Test Injection",
            "executor_type":    "bash",
            "executor_command": "echo exploit",
            "input_arguments":  {},
            "sigma_rule_ids":   [],
        }) + "\n")
        results = tmp_path / "results_v1.jsonl"
        # Patch RESULTS_FILE to tmp path
        sr.RESULTS_FILE = results
        sr.main(["--queue", str(queue), "--dry-run"])
        assert not results.exists(), "dry-run must not write results file"

    def test_result_schema(self, tmp_path):
        """_append_result must produce valid JSON with required keys."""
        sr = self._import()
        sr.RESULTS_FILE = tmp_path / "results_v1.jsonl"
        result = {
            "attack_technique": "T1055.001",
            "atomic_test_name": "Hollow Process",
            "atomic_guid":      "abc-123",
            "verdict":          "mitigated",
            "sensor_captures":  {"sysmon": [], "network_tap": {}, "auditd_delta": []},
            "sigma_rule_ids":   ["win_proc_inject"],
            "mitre_technique":  "T1055.001",
            "duration_secs":    12.5,
            "timestamp":        1700000000.0,
        }
        sr._append_result(result)
        written = json.loads((tmp_path / "results_v1.jsonl").read_text())
        for key in ("attack_technique", "verdict", "sensor_captures", "duration_secs"):
            assert key in written, f"result missing key: {key}"


# ══════════════════════════════════════════════════════════════════════════════
# 07_feed_ingest.py -- Four-stage filter, queue schema, kill chains, sigma validate
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedIngest:
    """07_feed_ingest.py: validate filter stages, output schemas, edge cases."""

    def _import(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "feed_ingest",
            str(MLOPS_SCRIPTS / "07_feed_ingest.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except ImportError:
            pytest.skip("PyYAML not installed -- 07_feed_ingest requires pyyaml")
        return mod

    # ── STIX helpers ──────────────────────────────────────────────────────────

    def test_load_attack_techniques_empty_on_missing(self, tmp_path):
        fi = self._import()
        tids = fi._load_attack_techniques(tmp_path / "nonexistent.json")
        assert tids == set()

    def test_load_attack_techniques_extracts_tids(self, tmp_path):
        fi = self._import()
        stix = {
            "objects": [
                {"external_references": [
                    {"external_id": "T1055"},
                    {"external_id": "T1055.001"},
                    {"external_id": "S0001"},   # should be ignored (not T-ID)
                ]}
            ]
        }
        f = tmp_path / "attack.json"
        f.write_text(json.dumps(stix))
        tids = fi._load_attack_techniques(f)
        assert "T1055" in tids
        assert "T1055.001" in tids
        assert "S0001" not in tids

    # ── KEV helpers ───────────────────────────────────────────────────────────

    def test_load_kev_ids_empty_on_missing(self, tmp_path):
        fi = self._import()
        assert fi._load_kev_ids(tmp_path / "nope.json") == set()

    def test_load_kev_ids_extracts_cves(self, tmp_path):
        fi = self._import()
        kev = {"vulnerabilities": [{"cveID": "CVE-2024-1234"}, {"cveID": "CVE-2023-9999"}]}
        f = tmp_path / "kev.json"
        f.write_text(json.dumps(kev))
        ids = fi._load_kev_ids(f)
        assert "CVE-2024-1234" in ids
        assert "CVE-2023-9999" in ids

    # ── SBOM helpers ──────────────────────────────────────────────────────────

    def test_load_sbom_cves_empty_on_missing(self, tmp_path):
        fi = self._import()
        assert fi._load_sbom_cves(tmp_path / "sbom.json") == set()

    def test_load_sbom_cves_extracts_cves(self, tmp_path):
        fi = self._import()
        sbom = {"components": [
            {"vulnerabilities": [{"id": "CVE-2024-5555"}]},
            {"vulnerabilities": [{"id": "cve-2023-7777"}]},  # lowercase
        ]}
        f = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))
        ids = fi._load_sbom_cves(f)
        assert "CVE-2024-5555" in ids
        assert "CVE-2023-7777" in ids  # normalised to upper

    # ── Corpus class helpers ──────────────────────────────────────────────────

    def test_corpus_classes_empty_on_missing_dir(self, tmp_path):
        fi = self._import()
        assert fi._corpus_classes(tmp_path / "nope") == set()

    def test_corpus_classes_reads_query_index(self, tmp_path):
        fi = self._import()
        staging = tmp_path / "staging"
        staging.mkdir()
        idx = {"tool_classes": {"ProcessHollowing": {}, "DLLInjection": {}}}
        (staging / "test_query_index.json").write_text(json.dumps(idx))
        classes = fi._corpus_classes(staging)
        assert "ProcessHollowing" in classes
        assert "DLLInjection" in classes

    # ── Four-stage filter ─────────────────────────────────────────────────────

    def test_stage1_rejects_manual_executor(self, tmp_path):
        """Atomics with executor.type=manual are rejected at Stage 1."""
        fi = self._import()
        atomic_dir = tmp_path / "atomics" / "T1055"
        atomic_dir.mkdir(parents=True)
        doc = {"atomic_tests": [{"name": "Manual inject",
                                  "auto_generated_guid": "abc123",
                                  "executor": {"type": "manual", "command": "do it yourself"}}]}
        (atomic_dir / "T1055.yaml").write_text(
            json.dumps(doc)  # Not proper YAML but _load_yaml handles json too via pyyaml
        )
        queue = fi.filter_atomics(
            tmp_path / "atomics", set(), set(), set(), set(), set()
        )
        assert queue == []

    def test_stage1_accepts_bash_executor(self, tmp_path):
        """Atomics with executor.type=bash pass Stage 1 when all other gates empty."""
        fi = self._import()
        atomic_dir = tmp_path / "atomics" / "T1059"
        atomic_dir.mkdir(parents=True)
        doc = {"atomic_tests": [{"name": "Bash exec",
                                  "auto_generated_guid": "def456",
                                  "executor": {"type": "bash", "command": "id"}}]}
        yaml_file = atomic_dir / "T1059.yaml"
        yaml_file.write_text(json.dumps(doc))
        # All gate sets empty → gates disabled, should pass
        queue = fi.filter_atomics(
            tmp_path / "atomics", set(), set(), set(), set(), set()
        )
        assert len(queue) == 1
        assert queue[0]["attack_technique"] == "T1059"
        assert queue[0]["executor_type"] == "bash"

    def test_queue_entry_schema(self, tmp_path):
        """Every queue entry must have the required keys."""
        fi = self._import()
        atomic_dir = tmp_path / "atomics" / "T1059"
        atomic_dir.mkdir(parents=True)
        doc = {"atomic_tests": [{"name": "Echo",
                                  "auto_generated_guid": "uuid-xyz",
                                  "executor": {"type": "sh", "command": "echo $USER"}}]}
        (atomic_dir / "T1059.yaml").write_text(json.dumps(doc))
        queue = fi.filter_atomics(
            tmp_path / "atomics", set(), set(), set(), set(), set()
        )
        assert len(queue) == 1
        entry = queue[0]
        for key in ("atomic_guid", "attack_technique", "display_name",
                    "executor_type", "executor_command", "input_arguments", "sigma_rule_ids"):
            assert key in entry, f"queue entry missing key: {key}"

    def test_stage4_skipped_for_atomics_without_cve(self, tmp_path):
        """Atomics with no cve field are NOT filtered by Stage 4."""
        fi = self._import()
        atomic_dir = tmp_path / "atomics" / "T1059"
        atomic_dir.mkdir(parents=True)
        doc = {"atomic_tests": [{"name": "No CVE",
                                  "auto_generated_guid": "g1",
                                  "executor": {"type": "bash", "command": "id"},
                                  "cve": None}]}
        (atomic_dir / "T1059.yaml").write_text(json.dumps(doc))
        # Non-empty KEV and SBOM -- but no CVE on atomic, so Stage 4 skipped
        queue = fi.filter_atomics(
            tmp_path / "atomics", set(), set(), set(),
            kev_ids={"CVE-9999-0000"}, sbom_cves={"CVE-9999-0000"},
        )
        assert len(queue) == 1

    def test_stage4_blocks_cve_not_in_kev(self, tmp_path):
        """CVE-mapped atomic is blocked when CVE is not in CISA KEV."""
        fi = self._import()
        atomic_dir = tmp_path / "atomics" / "T1190"
        atomic_dir.mkdir(parents=True)
        doc = {"atomic_tests": [{"name": "CVE exploit",
                                  "auto_generated_guid": "g2",
                                  "cve": "CVE-2024-9999",
                                  "executor": {"type": "bash", "command": "exploit"}}]}
        (atomic_dir / "T1190.yaml").write_text(json.dumps(doc))
        queue = fi.filter_atomics(
            tmp_path / "atomics", set(), set(), set(),
            kev_ids={"CVE-2024-0001"},  # different CVE
            sbom_cves={"CVE-2024-9999"},
        )
        assert queue == []

    def test_stage4_passes_cve_in_kev_and_sbom(self, tmp_path):
        fi = self._import()
        atomic_dir = tmp_path / "atomics" / "T1190"
        atomic_dir.mkdir(parents=True)
        doc = {"atomic_tests": [{"name": "KEV exploit",
                                  "auto_generated_guid": "g3",
                                  "cve": "CVE-2024-9999",
                                  "executor": {"type": "bash", "command": "exploit"}}]}
        (atomic_dir / "T1190.yaml").write_text(json.dumps(doc))
        queue = fi.filter_atomics(
            tmp_path / "atomics", set(), set(), set(),
            kev_ids={"CVE-2024-9999"}, sbom_cves={"CVE-2024-9999"},
        )
        assert len(queue) == 1
        assert queue[0]["cve"] == "CVE-2024-9999"

    # ── Track 6 query index ───────────────────────────────────────────────────

    def test_write_track6_index_creates_file(self, tmp_path):
        fi = self._import()
        staging = tmp_path / "staging"
        staging.mkdir()
        queue = [
            {"attack_technique": "T1059", "display_name": "Bash",
             "executor_type": "bash"},
            {"attack_technique": "T1055", "display_name": "Injection",
             "executor_type": "powershell"},
        ]
        fi.write_track6_index(queue, staging)
        idx_path = staging / "threat_feed_query_index.json"
        assert idx_path.exists()
        data = json.loads(idx_path.read_text())
        assert len(data) == 2

    def test_write_track6_index_bash_maps_to_linux_sentinel(self, tmp_path):
        fi = self._import()
        staging = tmp_path / "staging"
        staging.mkdir()
        queue = [{"attack_technique": "T1059", "display_name": "bash_exec",
                  "executor_type": "bash"}]
        fi.write_track6_index(queue, staging)
        data = json.loads((staging / "threat_feed_query_index.json").read_text())
        entry = list(data.values())[0]
        assert entry["sensor"] == "linux_sentinel"

    def test_write_track6_index_powershell_maps_to_sysmon(self, tmp_path):
        fi = self._import()
        staging = tmp_path / "staging"
        staging.mkdir()
        queue = [{"attack_technique": "T1055", "display_name": "ps_inject",
                  "executor_type": "powershell"}]
        fi.write_track6_index(queue, staging)
        data = json.loads((staging / "threat_feed_query_index.json").read_text())
        entry = list(data.values())[0]
        assert entry["sensor"] == "sysmon_sensor"

    # ── Sigma validate gap detection ──────────────────────────────────────────

    def test_sigma_validate_no_gaps_no_write(self, tmp_path):
        fi = self._import()
        # Sigma covers T1059; staging also covers T1059
        sigma_dir = tmp_path / "sigma" / "rules"
        sigma_dir.mkdir(parents=True)
        rule = {"id": "rule1", "tags": ["attack.t1059"]}
        (sigma_dir / "test.yml").write_text(json.dumps(rule))

        staging = tmp_path / "staging"
        staging.mkdir()
        (staging / "test_query_index.json").write_text(
            json.dumps({"T1059_BashExec": {"sensor": "linux_sentinel", "where": "comm IS NOT NULL"}})
        )
        todos_file = tmp_path / "todos.md"
        fi.TODOS_FILE = todos_file
        fi.run_sigma_validate(sigma_dir, staging)
        # T1059 covered by corpus -- no gap written
        if todos_file.exists():
            content = todos_file.read_text()
            assert "T1059" not in content

    def test_sigma_validate_writes_gap_for_uncovered_tid(self, tmp_path):
        fi = self._import()
        sigma_dir = tmp_path / "sigma" / "rules"
        sigma_dir.mkdir(parents=True)
        # Sigma has T1003 but corpus doesn't
        rule = {"id": "rule2", "tags": ["attack.t1003"]}
        (sigma_dir / "cred.yml").write_text(json.dumps(rule))

        staging = tmp_path / "staging"
        staging.mkdir()
        (staging / "test_query_index.json").write_text(
            json.dumps({"T1059_Bash": {}})  # T1059, not T1003
        )
        todos_file = tmp_path / "todos.md"
        fi.TODOS_FILE = todos_file
        fi.run_sigma_validate(sigma_dir, staging)
        assert todos_file.exists()
        content = todos_file.read_text()
        assert "T1003" in content
        assert "sigma_gap" in content

    # ── Kill chain parsing ────────────────────────────────────────────────────

    def test_kill_chain_empty_bundle_returns_none(self, tmp_path):
        fi = self._import()
        bundle = tmp_path / "AA00-000A.json"
        bundle.write_text(json.dumps({"objects": []}))
        result = fi._parse_stix_kill_chain(bundle, tmp_path / "atomics")
        assert result is None

    def test_kill_chain_with_attack_patterns(self, tmp_path):
        fi = self._import()
        bundle_data = {
            "objects": [
                {"type": "campaign", "name": "Test Campaign"},
                {
                    "type": "attack-pattern",
                    "external_references": [{"external_id": "T1566.001"}],
                },
                {
                    "type": "attack-pattern",
                    "external_references": [{"external_id": "T1059.001"}],
                },
            ]
        }
        bundle = tmp_path / "AA24-001A.json"
        bundle.write_text(json.dumps(bundle_data))
        result = fi._parse_stix_kill_chain(bundle, tmp_path / "atomics")
        assert result is not None
        assert result["campaign"] == "Test Campaign"
        assert len(result["kill_chain"]) == 2
        tids = [s["technique"] for s in result["kill_chain"]]
        assert "T1566.001" in tids
        assert "T1059.001" in tids
        assert "sft_prompt" in result
        assert "sft_completion" in result

    def test_kill_chain_sft_record_has_required_fields(self, tmp_path):
        fi = self._import()
        bundle_data = {
            "objects": [{
                "type": "attack-pattern",
                "external_references": [{"external_id": "T1055"}],
            }]
        }
        bundle = tmp_path / "AA24-999A.json"
        bundle.write_text(json.dumps(bundle_data))
        result = fi._parse_stix_kill_chain(bundle, tmp_path / "atomics")
        assert result is not None
        for field in ("advisory_id", "campaign", "kill_chain", "sft_prompt", "sft_completion"):
            assert field in result, f"kill chain record missing field: {field}"

    def test_run_kill_chains_writes_jsonl(self, tmp_path):
        fi = self._import()
        advisory_dir = tmp_path / "advisories"
        advisory_dir.mkdir()
        bundle_data = {"objects": [{"type": "attack-pattern",
                                     "external_references": [{"external_id": "T1055"}]}]}
        (advisory_dir / "AA24-001A.json").write_text(json.dumps(bundle_data))
        out = tmp_path / "kill_chain_sft_v1.jsonl"
        fi.run_kill_chains(advisory_dir, tmp_path / "atomics", out)
        assert out.exists()
        records = [json.loads(l) for l in out.read_text().strip().splitlines()]
        assert len(records) == 1


# ══════════════════════════════════════════════════════════════════════════════
# Script-level contract tests (source inspection)
# ══════════════════════════════════════════════════════════════════════════════

class TestPhase1ScriptContracts:
    """Source-level contract checks -- validate key structures are present."""

    SB = MLOPS_SCRIPTS / "06_sandbox_runner.py"
    FI = MLOPS_SCRIPTS / "07_feed_ingest.py"

    def test_sandbox_runner_has_result_schema_keys(self):
        src = self.SB.read_text()
        for key in ("attack_technique", "atomic_test_name", "atomic_guid",
                    "verdict", "sensor_captures", "sigma_rule_ids",
                    "mitre_technique", "duration_secs", "timestamp"):
            assert f'"{key}"' in src, \
                f"06_sandbox_runner.py: result schema key '{key}' missing"

    def test_sandbox_runner_dry_run_flag(self):
        src = self.SB.read_text()
        assert "--dry-run" in src, "06_sandbox_runner.py: --dry-run flag missing"

    def test_sandbox_runner_does_not_reference_poc_url(self):
        """Must use executor.command from Atomic Red Team, NOT GitHub PoC URLs."""
        src = self.SB.read_text()
        assert "poc_url" not in src, \
            "06_sandbox_runner.py: references poc_url -- should use Atomic Red Team executor.command"

    def test_feed_ingest_four_stage_filter_present(self):
        src = self.FI.read_text()
        assert "filter_atomics" in src, "07_feed_ingest.py: filter_atomics function missing"

    def test_feed_ingest_atomic_red_team_source(self):
        src = self.FI.read_text()
        assert "atomic-red-team" in src or "atomics" in src.lower(), \
            "07_feed_ingest.py: Atomic Red Team source not referenced"

    def test_feed_ingest_no_nomi_sec(self):
        """Must not reference the old nomi-sec/PoC-in-GitHub source."""
        src = self.FI.read_text()
        assert "nomi-sec" not in src, \
            "07_feed_ingest.py: still references nomi-sec -- must use Atomic Red Team"

    def test_feed_ingest_kill_chains_mode(self):
        src = self.FI.read_text()
        assert "kill-chains" in src or "kill_chains" in src, \
            "07_feed_ingest.py: kill-chains mode missing"

    def test_feed_ingest_sigma_validate_mode(self):
        src = self.FI.read_text()
        assert "sigma-validate" in src or "sigma_validate" in src, \
            "07_feed_ingest.py: sigma-validate mode missing"

    def test_feed_ingest_local_mirror_paths(self):
        src = self.FI.read_text()
        assert "ti_feeds" in src, \
            "07_feed_ingest.py: local TI mirror path (ti_feeds) not referenced"

    def test_feed_ingest_cisa_advisory_dir(self):
        src = self.FI.read_text()
        assert "cisa_advisories" in src, \
            "07_feed_ingest.py: CISA advisory dir not referenced"

    def test_beacon_ml_windows_file_exists(self):
        path = REPO.parent / "windows" / "prototypes" / "c2_sensor" / "BeaconML.py"
        assert path.exists(), "BeaconML.py not found at windows/prototypes/c2_sensor/BeaconML.py"

    def test_beacon_ml_integration_point_documented(self):
        path = REPO.parent / "windows" / "prototypes" / "c2_sensor" / "BeaconML.py"
        src = path.read_text()
        assert "c2_ledger_queue" in src, \
            "BeaconML.py: integration point with c2_ledger_queue not documented"
        assert "compute_flow_stats" in src, \
            "BeaconML.py: compute_flow_stats function missing"
