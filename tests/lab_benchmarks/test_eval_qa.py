"""
Eval-QA gates: the evaluations get the same QA discipline as the pipeline.

Proves the three gates offline:
  * leakage - a bench case near-duplicating a training record is detected and
    its dataset registration fails (exit 1 from the CLI);
  * dataset integrity - SHA-384 manifests round-trip, tampering is caught, and
    the balance/coverage audit reports class balance + MITRE coverage;
  * judge calibration - Cohen's kappa over banded rubric scores, with the
    freeze state that blocks judge-weighted promotion, wired into the RSI loop
    as an inert-when-absent gate.
"""
import importlib.util as ilu
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent.parent / "mlops" / "scripts"


def _load(modname, filename):
    spec = ilu.spec_from_file_location(modname, str(SCRIPTS / filename))
    mod = ilu.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


qa = _load("eval_qa", "12_eval_qa.py")


def _sft_record(prompt: str, cls="true_positive", techniques=("T1059",)):
    return {
        "classification": cls,
        "source_type": "sysmon_sensor",
        "mitre_techniques": list(techniques),
        "messages": [
            {"role": "system", "content": "You are the endpoint expert."},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": "verdict"},
        ],
    }


PROMPT = ("Spatial Anomaly Detected. Source: sysmon_sensor Hostname: WS01 "
          "EventID: 1 Raw Payload: {\"Image\":\"C:\\\\tools\\\\psexec.exe\","
          "\"CommandLine\":\"psexec -s cmd.exe\"}")


# ── leakage gate ─────────────────────────────────────────────────────────────

class TestLeakageScan:
    def test_near_duplicate_of_training_record_is_leaked(self):
        train = [qa.record_text(_sft_record(PROMPT))]
        bench = [{**_sft_record(PROMPT), "case_id": "bench-1"}]
        leaked = qa.scan_leakage(bench, train)
        assert [l["case_id"] for l in leaked] == ["bench-1"]

    def test_dissimilar_case_is_clean(self):
        train = [qa.record_text(_sft_record(PROMPT))]
        other = ("Spatial Anomaly Detected. Source: aws_cloudtrail Account: 42 "
                 "Raw Payload: {\"event_name\":\"AssumeRole\",\"source_ip\":\"10.9.8.7\"}")
        bench = [{**_sft_record(other), "case_id": "bench-2"}]
        assert qa.scan_leakage(bench, train) == []

    def test_replay_case_text_uses_alert_and_slice(self):
        case = {"case_id": "r1", "alert": {"event_id": "e1"},
                "data_slice": [{"id": "row1"}], "adjudicated": {"is_tp": True}}
        text = qa.record_text(case)
        assert "row1" in text and "e1" in text

    def test_threshold_is_the_dedup_default(self):
        assert qa.LEAKAGE_THRESHOLD == 0.92

    def test_cli_registration_fails_on_leaked_dataset(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()
        (staging / "corpus_v1.jsonl").write_text(
            json.dumps(_sft_record(PROMPT)) + "\n")
        dataset = tmp_path / "bench" / "v1"
        dataset.mkdir(parents=True)
        (dataset / "cases.jsonl").write_text(
            json.dumps({**_sft_record(PROMPT), "case_id": "leak-1"}) + "\n")
        rc = qa.main(["scan-leakage", "--dataset", str(dataset),
                      "--staging-dir", str(staging)])
        assert rc == 1, "registering a leaked dataset must fail CI"

    def test_cli_passes_clean_dataset(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()
        (staging / "corpus_v1.jsonl").write_text(
            json.dumps(_sft_record(PROMPT)) + "\n")
        dataset = tmp_path / "bench" / "v1"
        dataset.mkdir(parents=True)
        clean = ("Completely different governance determinism scenario about "
                 "SOAR action approval thresholds and quorum rules.")
        (dataset / "cases.jsonl").write_text(
            json.dumps({**_sft_record(clean), "case_id": "ok-1"}) + "\n")
        assert qa.main(["scan-leakage", "--dataset", str(dataset),
                        "--staging-dir", str(staging)]) == 0


# ── dataset manifests + balance audit ────────────────────────────────────────

class TestDatasetManifest:
    def _dataset(self, tmp_path):
        d = tmp_path / "bench" / "v1"
        d.mkdir(parents=True)
        rows = [_sft_record(PROMPT + " a", "true_positive", ("T1059", "T1021")),
                _sft_record(PROMPT + " b", "false_positive", ("T1059",))]
        (d / "cases.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        return d

    def test_manifest_roundtrip_verifies(self, tmp_path):
        d = self._dataset(tmp_path)
        manifest = qa.write_dataset_manifest(d)
        assert manifest["schema"] == qa.DATASET_MANIFEST_SCHEMA
        ok, errors = qa.verify_dataset_manifest(d)
        assert ok, errors

    def test_tampering_is_caught(self, tmp_path):
        d = self._dataset(tmp_path)
        qa.write_dataset_manifest(d)
        with open(d / "cases.jsonl", "a") as fh:
            fh.write(json.dumps(_sft_record("injected case")) + "\n")
        ok, errors = qa.verify_dataset_manifest(d)
        assert not ok and any("mismatch" in e for e in errors)

    def test_missing_manifest_fails(self, tmp_path):
        d = self._dataset(tmp_path)
        ok, errors = qa.verify_dataset_manifest(d)
        assert not ok and errors == ["manifest.json missing"]

    def test_balance_audit_contents(self, tmp_path):
        d = self._dataset(tmp_path)
        manifest = qa.write_dataset_manifest(d)
        audit = manifest["audit"]
        assert audit["count"] == 2
        assert audit["class_balance"] == {"true_positive": 0.5, "false_positive": 0.5}
        assert audit["per_source_type"] == {"sysmon_sensor": 2}
        assert audit["mitre_techniques"] == ["T1021", "T1059"]

    def test_replay_freezer_manifest_verifies(self, tmp_path):
        freezer = _load("freeze_replay_case_qa", "10_freeze_replay_case.py")
        record = {"event_id": "e1", "source_type": "sysmon_sensor",
                  "verdict": {"is_tp": True, "confidence": 0.9},
                  "outcome": {"operator_action": "dismissed"}}
        case = freezer.build_case(record, {"a": 1}, {}, [{"id": "r1"}], "override")
        d = tmp_path / "replay" / "v1"
        freezer.write_cases([case], d)
        ok, errors = qa.verify_dataset_manifest(d)
        assert ok, errors


# ── judge calibration ────────────────────────────────────────────────────────

class TestJudgeCalibration:
    def _pair(self, judge, operator):
        mk = lambda s: {"report_quality": s, "evidence_grounding": s,
                        "action_appropriateness": s}
        return {"judge": mk(judge), "operator": mk(operator)}

    def test_rubric_weights_sum_to_one(self):
        assert abs(sum(qa.RUBRIC_WEIGHTS.values()) - 1.0) < 1e-9
        assert qa.RUBRIC_WEIGHTS["evidence_grounding"] == 0.40

    def test_perfect_agreement_not_frozen(self):
        pairs = [self._pair(0.9, 0.9), self._pair(0.2, 0.2),
                 self._pair(0.5, 0.5), self._pair(0.95, 0.85)]
        result = qa.judge_calibration(pairs)
        assert result["kappa"] == 1.0 and not result["frozen"]

    def test_systematic_disagreement_freezes(self):
        pairs = [self._pair(0.9, 0.2), self._pair(0.85, 0.3),
                 self._pair(0.95, 0.1), self._pair(0.9, 0.35),
                 self._pair(0.2, 0.9), self._pair(0.3, 0.95)]
        result = qa.judge_calibration(pairs)
        assert result["kappa"] < 0.6 and result["frozen"]

    def test_kappa_chance_agreement_is_zero_not_positive(self):
        labels_a = ["high", "high", "low", "low"]
        labels_b = ["high", "low", "high", "low"]
        assert qa.cohens_kappa(labels_a, labels_b) == 0.0

    def test_kappa_rejects_mismatched_lengths(self):
        with pytest.raises(ValueError):
            qa.cohens_kappa(["high"], [])

    def test_cli_writes_freeze_state(self, tmp_path):
        pairs_file = tmp_path / "pairs.jsonl"
        pairs = [self._pair(0.9, 0.1), self._pair(0.9, 0.2),
                 self._pair(0.1, 0.9), self._pair(0.2, 0.95)]
        pairs_file.write_text("\n".join(json.dumps(p) for p in pairs) + "\n")
        out = tmp_path / "judge_calibration.json"
        rc = qa.main(["judge-calibration", "--pairs", str(pairs_file),
                      "--out", str(out)])
        state = json.loads(out.read_text())
        assert rc == 1 and state["frozen"]


# ── the freeze state gates the RSI loop's promotion path ─────────────────────

class TestRsiJudgeGate:
    def _rsi(self, tmp_path, monkeypatch, state: "dict | None"):
        cal = tmp_path / "judge_calibration.json"
        if state is not None:
            cal.write_text(json.dumps(state))
        monkeypatch.setenv("RSI_JUDGE_CALIBRATION_FILE", str(cal))
        return _load("rsi_loop_judge_gate", "08_rsi_loop.py")

    def test_absent_file_is_inert(self, tmp_path, monkeypatch):
        rsi = self._rsi(tmp_path, monkeypatch, None)
        ok, reason = rsi._judge_calibration_gate()
        assert ok and "inert" in reason

    def test_frozen_state_blocks_promotion(self, tmp_path, monkeypatch):
        rsi = self._rsi(tmp_path, monkeypatch,
                        {"kappa": 0.31, "threshold": 0.6, "frozen": True})
        ok, reason = rsi._judge_calibration_gate()
        assert not ok and "0.31" in reason

    def test_calibrated_state_passes(self, tmp_path, monkeypatch):
        rsi = self._rsi(tmp_path, monkeypatch,
                        {"kappa": 0.82, "threshold": 0.6, "frozen": False})
        ok, _ = rsi._judge_calibration_gate()
        assert ok

    def test_unreadable_file_fails_closed(self, tmp_path, monkeypatch):
        cal = tmp_path / "judge_calibration.json"
        cal.write_text("{not json")
        monkeypatch.setenv("RSI_JUDGE_CALIBRATION_FILE", str(cal))
        rsi = _load("rsi_loop_judge_gate_bad", "08_rsi_loop.py")
        ok, reason = rsi._judge_calibration_gate()
        assert not ok and "failing closed" in reason
