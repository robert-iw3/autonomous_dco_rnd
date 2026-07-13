"""
Lab 10 -- NIST AI 600-1 controls, wave 4. Runs the *control jobs* end to end
(over injected data), not just the pure analytics, so a regression in a
ledger/corpus writer surfaces here.

  NC-7  Automation-bias / over-reliance ledger  (agents/calibration_ledger.py)
  NC-8  Active-learning failure capture         (agents/active_learning.py)
  NC-9  Tamper-evident verdict ledger           (agents/verdict_ledger.py)
  NC-10 Per-run inference energy accounting     (agents/energy_accounting.py)
"""
import json
import sys
import types
from pathlib import Path

import pytest

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"

# the wave-4 agent modules import only `agents.controls` (stdlib). Stub the agents
# package so they import without the heavy node __init__.
_agents = types.ModuleType("agents")
_agents.__path__ = [str(HUNTER / "agents")]
sys.modules["agents"] = _agents
sys.path.insert(0, str(HUNTER))

import importlib
for m in ("agents.active_learning", "agents.verdict_ledger", "agents.energy_accounting",
          "agents.calibration_ledger", "agents.endpoint_abuse_monitor"):
    sys.modules.pop(m, None)
al = importlib.import_module("agents.active_learning")
vl = importlib.import_module("agents.verdict_ledger")
en = importlib.import_module("agents.energy_accounting")
cal = importlib.import_module("agents.calibration_ledger")
eam = importlib.import_module("agents.endpoint_abuse_monitor")


# -- NC-8 active-learning failure capture -------------------------------------
class TestActiveLearning:
    def test_captures_a_misclassification(self, tmp_path):
        corpus = str(tmp_path / "fail.jsonl")
        rec = al.capture({"is_true_positive": True, "confidence": 0.9},
                         operator_disposition="false_positive", event_id="e1",
                         artifacts=["203.0.113.7"], corpus_path=corpus)
        assert rec is not None and rec["reason"] == "misclassification"
        assert "ts" in rec
        assert al.load_corpus(corpus) == [rec]

    def test_correct_verdict_writes_nothing(self, tmp_path):
        corpus = str(tmp_path / "fail.jsonl")
        rec = al.capture({"is_true_positive": True, "confidence": 0.9},
                         operator_disposition="true_positive", corpus_path=corpus)
        assert rec is None
        assert al.load_corpus(corpus) == []

    def test_grounding_violation_is_captured(self, tmp_path):
        corpus = str(tmp_path / "fail.jsonl")
        rec = al.capture({"is_true_positive": True, "confidence": 0.8},
                         operator_disposition="true_positive", grounding_violation=True,
                         corpus_path=corpus)
        assert rec["reason"] == "ungrounded_evidence"


# -- NC-9 tamper-evident verdict ledger --------------------------------------
class TestVerdictLedger:
    def test_append_builds_a_verifiable_chain(self, tmp_path):
        ledger = str(tmp_path / "verdicts.jsonl")
        vl.append_verdict({"event_id": "a", "verdict": "tp"}, ledger)
        vl.append_verdict({"event_id": "b", "verdict": "fp"}, ledger)
        res = vl.verify_ledger(ledger)
        assert res["valid"] is True and len(vl.load_ledger(ledger)) == 2

    def test_links_across_separate_calls(self, tmp_path):
        ledger = str(tmp_path / "verdicts.jsonl")
        e1 = vl.append_verdict({"i": 1}, ledger)
        e2 = vl.append_verdict({"i": 2}, ledger)
        assert e2["prev_hash"] == e1["entry_hash"]

    def test_tampering_a_persisted_record_is_detected(self, tmp_path):
        ledger = Path(tmp_path / "verdicts.jsonl")
        vl.append_verdict({"event_id": "a", "verdict": "fp"}, str(ledger))
        vl.append_verdict({"event_id": "b", "verdict": "fp"}, str(ledger))
        # an attacker edits the first verdict in place
        lines = ledger.read_text().splitlines()
        first = json.loads(lines[0])
        first["record"]["verdict"] = "tp"
        lines[0] = json.dumps(first)
        ledger.write_text("\n".join(lines) + "\n")
        res = vl.verify_ledger(str(ledger))
        assert res["valid"] is False and res["broken_at"] == 0

    def test_empty_ledger_is_valid(self, tmp_path):
        assert vl.verify_ledger(str(tmp_path / "none.jsonl"))["valid"] is True


# -- NC-10 per-run inference energy accounting --------------------------------
class TestEnergyAccounting:
    def test_record_and_totals(self, tmp_path):
        ledger = str(tmp_path / "energy.jsonl")
        en.record_run(3600, 300, event_id="e1", pue=1.5, ledger_path=ledger)
        en.record_run(1800, 300, event_id="e2", pue=1.5, ledger_path=ledger)
        recs = en.load_ledger(ledger)
        assert len(recs) == 2 and all("ts" in r for r in recs)
        tot = en.totals(recs)
        assert tot["n"] == 2
        assert tot["energy_wh"] == pytest.approx(450.0 + 225.0, abs=1e-6)
        assert tot["co2e_g"] == pytest.approx((450.0 + 225.0) / 1000.0 * 400.0, abs=1e-6)

    def test_totals_of_empty_is_zero(self):
        assert en.totals([]) == {"n": 0, "energy_wh": 0.0, "co2e_g": 0.0}


# -- NC-7 over-reliance ledger -----------------------------------------------
class TestRelianceLedger:
    def test_record_and_report_flags_automation_bias(self, tmp_path):
        ledger = str(tmp_path / "reliance.jsonl")
        # 5 wrong AI calls accepted (rubber-stamped), 1 caught
        for i in range(5):
            cal.record_reliance({"is_true_positive": True, "confidence": 0.95},
                                "accept", "false_positive", f"w{i}", ledger)
        cal.record_reliance({"is_true_positive": True, "confidence": 0.95},
                            "override", "false_positive", "c1", ledger)
        recs = cal.load_ledger(ledger)
        assert len(recs) == 6 and all("ts" in r for r in recs)
        rep = cal.over_reliance(recs, min_support=3)
        assert rep["n_ai_wrong"] == 6
        assert rep["automation_bias"] == pytest.approx(5 / 6, abs=1e-3)
        assert rep["flagged"] is True

    def test_empty_reliance_is_safe(self, tmp_path):
        assert cal.over_reliance(cal.load_ledger(str(tmp_path / "none.jsonl")))["flagged"] is False


# -- NC-7 inference-endpoint abuse / model-extraction monitor -----------------
class TestEndpointAbuseMonitor:
    def _abuser_records(self):
        recs = [{"caller": "svc-x", "query": f"score host 10.0.0.{i%4} malicious?"}
                for i in range(80)]
        recs += [{"caller": "analyst", "query": q} for q in
                 ["failed logins db01", "egress to 8.8.8.8", "new admin audit"]]
        return recs

    def test_flags_abuser_and_writes_report(self, tmp_path):
        audit = eam.run_endpoint_abuse_audit(
            self._abuser_records(),
            baseline={"svc-x": 5.0, "analyst": 3.0},
            quota=50, volume_factor=3.0, volume_floor=20,
            sim_threshold=0.5, min_queries=10)
        assert audit["flagged"] is True
        path = eam.write_report(audit, report_dir=str(tmp_path))
        on_disk = json.loads(Path(path).read_text())
        flagged = {c["caller"] for c in on_disk["report"]["flagged"]}
        assert "svc-x" in flagged and "analyst" not in flagged

    def test_clean_traffic_not_flagged(self, tmp_path):
        recs = [{"caller": "analyst", "query": q} for q in
                ["a b c", "d e f", "g h i"]]
        audit = eam.run_endpoint_abuse_audit(recs, baseline={"analyst": 100.0}, quota=1000)
        assert audit["flagged"] is False

    def test_collect_and_monitor_uses_injected_collector(self, tmp_path):
        recs = self._abuser_records()
        audit = eam.collect_and_monitor(
            collector=lambda c, s, lim: recs,
            baseline={"svc-x": 5.0, "analyst": 3.0},
            report_dir=str(tmp_path),
            quota=50, volume_factor=3.0, volume_floor=20,
            sim_threshold=0.5, min_queries=10)
        assert audit["flagged"] is True
        assert Path(audit["report_path"]).exists()

    def test_next_baseline_feeds_forward(self, tmp_path):
        recs = [{"caller": "svc-x", "query": "q"} for _ in range(30)]
        audit = eam.run_endpoint_abuse_audit(recs, baseline={})
        assert audit["next_baseline"]["svc-x"] == 30.0

    def test_access_log_collector_reads_jsonl(self, tmp_path):
        log = tmp_path / "access.jsonl"
        log.write_text('{"caller":"a","query":"x"}\n{"caller":"b","query":"y"}\n')
        recs = eam._read_access_log(None, str(log), 100)
        assert {r["caller"] for r in recs} == {"a", "b"}

    def test_baseline_loaded_from_last_report(self, tmp_path):
        first = eam.run_endpoint_abuse_audit(
            [{"caller": "svc-x", "query": "q"} for _ in range(40)], baseline={})
        eam.write_report(first, report_dir=str(tmp_path))
        loaded = eam._load_baseline(str(tmp_path))
        assert loaded.get("svc-x") == 40.0


# -- POA&M-1 scheduled governance-audit runner --------------------------------
class TestScheduledAudits:
    def _mod(self):
        import importlib
        sys.modules.pop("agents.scheduled_audits", None)
        return importlib.import_module("agents.scheduled_audits")

    def test_all_jobs_run_and_summarize(self):
        sa = self._mod()
        jobs = {"a": lambda: {"flagged": False},
                "b": lambda: {"flagged": True}}
        summary = sa.run_all(jobs)
        assert summary["n_jobs"] == 2 and summary["n_failed"] == 0
        assert summary["n_flagged"] == 1

    def test_one_failing_job_does_not_sink_others(self):
        sa = self._mod()
        def boom(): raise RuntimeError("collector down")
        jobs = {"good": lambda: {"flagged": False}, "bad": boom}
        summary = sa.run_all(jobs)
        assert summary["n_failed"] == 1
        results = {r["job"]: r for r in summary["results"]}
        assert results["good"]["ok"] is True
        assert results["bad"]["ok"] is False and "collector down" in results["bad"]["error"]

    def test_main_writes_status_and_exit_code(self, tmp_path, monkeypatch):
        sa = self._mod()
        # inject a clean job set (no infra) via default_jobs monkeypatch
        monkeypatch.setattr(sa, "default_jobs",
                            lambda: {"x": lambda: {"flagged": False}})
        status = tmp_path / "last_run.json"
        rc = sa.main(["--status-file", str(status)])
        assert rc == 0
        data = json.loads(status.read_text())
        assert data["n_jobs"] == 1 and data["n_failed"] == 0

    def test_main_returns_nonzero_when_a_job_errors(self, tmp_path, monkeypatch):
        sa = self._mod()
        def boom(): raise RuntimeError("x")
        monkeypatch.setattr(sa, "default_jobs", lambda: {"x": boom})
        rc = sa.main(["--status-file", str(tmp_path / "s.json")])
        assert rc == 1
