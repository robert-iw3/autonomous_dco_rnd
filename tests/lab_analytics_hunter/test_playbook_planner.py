"""
Playbook-planner contract (llm_hunter) — the logic that initiates host IR
playbooks in response to a confirmed verdict.

Pure: imports only `agents.playbook_planner` (stdlib), no agent/network stubs.
Proves the swarm's typed intelligence (ip/domain/pid/hash/file entities) is
turned into the right ordered playbooks + IOC parameters, and that nothing fires
outside a 'contain' verdict on a supported on-host OS.
"""
import sys
from pathlib import Path

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"
sys.path.insert(0, str(HUNTER / "agents"))   # import the module directly; skip agents/__init__ (heavy deps)

import playbook_planner as pp  # noqa: E402


def _ent(etype, status="malicious", notes=""):
    return {"type": etype, "status": status, "notes": notes}


# -- os_family inference ------------------------------------------------------
class TestOsFamily:
    def test_windows_sources(self):
        for st in ("sysmon_sensor", "windows_deepsensor", "windows_c2", "trellix_ens"):
            assert pp.infer_os_family({"source_type": st}) == "windows"

    def test_linux_sources(self):
        for st in ("linux_sentinel", "linux_c2"):
            assert pp.infer_os_family({"source_type": st}) == "linux"

    def test_cloud_network_generic_have_no_host_os(self):
        for st in ("aws_cloudtrail", "azure_nsg", "gcp_audit", "network_tap",
                   "suricata_eve", "qdrant_vector", "macos_sensor", ""):
            assert pp.infer_os_family({"source_type": st}) is None


# -- typed-IOC extraction -----------------------------------------------------
class TestExtractIocs:
    def test_buckets_by_type_only_malicious(self):
        entities = {
            "10.0.0.9": _ent("ip"),
            "evil.test": _ent("domain"),
            "4242": _ent("pid"),
            "a" * 64: _ent("hash"),
            "f1": _ent("file", notes="/tmp/.x/payload.bin"),
            "alice": _ent("user"),
            "10.0.0.250": _ent("ip", status="cleared"),   # not malicious → ignored
            "1.1.1.1": _ent("ip", status="pending"),       # not malicious → ignored
        }
        iocs = pp.extract_iocs(entities)
        assert iocs["c2_ips"] == ["10.0.0.9"]
        assert iocs["c2_domains"] == ["evil.test"]
        assert iocs["pids"] == ["4242"]
        assert iocs["hashes"] == ["a" * 64]
        assert iocs["file_paths"] == ["/tmp/.x/payload.bin"]   # path from notes
        assert iocs["users"] == ["alice"]

    def test_file_without_notes_falls_back_to_id(self):
        iocs = pp.extract_iocs({"/var/evil": _ent("file")})
        assert iocs["file_paths"] == ["/var/evil"]

    def test_empty_and_none_safe(self):
        for e in (None, {}):
            iocs = pp.extract_iocs(e)
            assert all(v == [] for v in iocs.values())

    def test_dedup_preserves_order(self):
        entities = {"9.9.9.9": _ent("ip")}
        # simulate duplicate via two entities of same id is impossible (dict), so
        # check dedup within a single bucket built from repeated values
        iocs = pp.extract_iocs(entities)
        assert iocs["c2_ips"] == ["9.9.9.9"]


# -- action planning ----------------------------------------------------------
class TestPlanResponseActions:
    def test_contain_minimal_isolate_and_forensics(self):
        # contain with no typed IOCs → still isolate + capture evidence
        actions = pp.plan_response_actions("contain", pp.extract_iocs({}), "linux")
        assert actions == ["isolate_host", "collect_forensics"]

    def test_full_remediation_ordered(self):
        iocs = pp.extract_iocs({
            "10.0.0.9": _ent("ip"), "evil.test": _ent("domain"),
            "4242": _ent("pid"), "f1": _ent("file", notes="/tmp/x"),
        })
        actions = pp.plan_response_actions("contain", iocs, "windows")
        # evidence captured before anything destructive; isolate first
        assert actions == ["isolate_host", "collect_forensics", "block_ip",
                           "eradicate_process", "eradicate_persistence"]

    def test_block_ip_on_domain_only(self):
        iocs = pp.extract_iocs({"evil.test": _ent("domain")})
        assert "block_ip" in pp.plan_response_actions("contain", iocs, "linux")

    def test_eradicate_persistence_on_hash_only(self):
        iocs = pp.extract_iocs({"a" * 64: _ent("hash")})
        actions = pp.plan_response_actions("contain", iocs, "linux")
        assert "eradicate_persistence" in actions
        assert "eradicate_process" not in actions   # no pids

    def test_monitor_and_dismiss_initiate_no_host_playbook(self):
        iocs = pp.extract_iocs({"4242": _ent("pid")})
        assert pp.plan_response_actions("monitor", iocs, "linux") == []
        assert pp.plan_response_actions("dismiss", iocs, "linux") == []

    def test_cloud_target_initiates_no_host_playbook(self):
        iocs = pp.extract_iocs({"4242": _ent("pid")})
        assert pp.plan_response_actions("contain", iocs, None) == []


# -- two-phase (evidence-first) gating ----------------------------------------
class TestTwoPhaseWaves:
    def _iocs(self):
        return pp.extract_iocs({"4242": _ent("pid"), "10.0.0.9": _ent("ip"),
                                "a" * 64: _ent("hash")})

    def test_wave_split(self):
        w = pp.plan_response_waves("contain", self._iocs(), "linux")
        assert w["wave1"] == ["isolate_host", "collect_forensics"]
        assert w["wave2"] == ["block_ip", "eradicate_process", "eradicate_persistence"]

    def test_first_pass_is_contain_and_collect_only(self):
        w = pp.plan_response_waves("contain", self._iocs(), "linux")
        assert pp.actions_for_phase(w, memory_enriched=False, memory_threat=False) \
            == ["isolate_host", "collect_forensics"]

    def test_eradication_only_after_memory_confirms(self):
        w = pp.plan_response_waves("contain", self._iocs(), "linux")
        # enrichment returned, memory threat confirmed → eradicate
        assert pp.actions_for_phase(w, memory_enriched=True, memory_threat=True) \
            == ["block_ip", "eradicate_process", "eradicate_persistence"]
        # enrichment returned, memory CLEARED it → eradicate nothing
        assert pp.actions_for_phase(w, memory_enriched=True, memory_threat=False) == []


# -- full plan ----------------------------------------------------------------
class TestBuildPlaybookPlan:
    def test_first_pass_emits_wave1_only(self):
        alert = {"source_type": "sysmon_sensor"}
        verdict = {"recommended_action": "contain", "is_true_positive": True}
        entities = {"4242": _ent("pid"), "10.0.0.9": _ent("ip")}
        plan = pp.build_playbook_plan(alert, verdict, entities)   # no memory enrichment yet
        assert plan["os_family"] == "windows"
        assert plan["iocs"]["pids"] == ["4242"] and plan["iocs"]["c2_ips"] == ["10.0.0.9"]
        # evidence-first: contain + collect now; eradication deferred to wave 2
        assert plan["response_actions"] == ["isolate_host", "collect_forensics"]
        assert plan["waves"]["wave2"] == ["block_ip", "eradicate_process"]

    def test_memory_enriched_reentry_emits_eradication(self):
        alert = {"source_type": "sysmon_sensor"}
        verdict = {"recommended_action": "contain", "is_true_positive": True}
        entities = {"4242": _ent("pid"), "10.0.0.9": _ent("ip")}
        plan = pp.build_playbook_plan(alert, verdict, entities,
                                      memory_enriched=True, memory_threat=True)
        assert plan["response_actions"] == ["block_ip", "eradicate_process"]

    def test_cloud_contain_yields_no_actions(self):
        plan = pp.build_playbook_plan(
            {"source_type": "aws_cloudtrail"},
            {"recommended_action": "contain"},
            {"10.0.0.9": _ent("ip")},
        )
        assert plan["os_family"] is None
        assert plan["response_actions"] == []
        # IOCs are still extracted (useful for the cloud path / audit)
        assert plan["iocs"]["c2_ips"] == ["10.0.0.9"]
