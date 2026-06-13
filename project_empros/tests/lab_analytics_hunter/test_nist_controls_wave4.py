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
          "agents.calibration_ledger"):
    sys.modules.pop(m, None)
al = importlib.import_module("agents.active_learning")
vl = importlib.import_module("agents.verdict_ledger")
en = importlib.import_module("agents.energy_accounting")
cal = importlib.import_module("agents.calibration_ledger")


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
