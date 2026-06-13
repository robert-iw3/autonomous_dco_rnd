"""
Lab 10 -- NIST AI 600-1 controls, wave 2 (NC-1 bias audit, NC-2 calibration
ledger, NC-3 frontier-pin enforcement).

These run the *control jobs* end to end (over injected data) -- not just the pure
analytics -- so a regression in the collector/ledger/gate surfaces here.
"""
import sys
import types
from pathlib import Path

import pytest

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"

# bias_audit + calibration_ledger import only `agents.controls` (stdlib). Stub the
# agents package so they import without the heavy node __init__.
_agents = types.ModuleType("agents")
_agents.__path__ = [str(HUNTER / "agents")]
sys.modules["agents"] = _agents
sys.path.insert(0, str(HUNTER))

import importlib
sys.modules.pop("agents.bias_audit", None)
sys.modules.pop("agents.calibration_ledger", None)
ba = importlib.import_module("agents.bias_audit")
cal = importlib.import_module("agents.calibration_ledger")


# -- NC-1 bias / homogenization audit ----------------------------------------
def _recs(source, n, contained, vector="v"):
    return [{"source_type": source, "vector_name": vector,
             "is_true_positive": i < contained,
             "action": "contain" if i < contained else "monitor"} for i in range(n)]


class TestBiasAudit:
    def test_balanced_history_is_not_flagged(self):
        recs = _recs("linux_sentinel", 10, 5, "a") + _recs("windows_c2", 10, 5, "b")
        audit = ba.run_bias_audit(recs)
        assert audit["flagged"] is False
        assert audit["n_records"] == 20

    def test_containment_disparity_is_flagged(self):
        recs = _recs("linux_sentinel", 10, 1, "a") + _recs("windows_c2", 10, 9, "b")
        audit = ba.run_bias_audit(recs)
        assert audit["flagged"] is True
        assert any("disparity" in r for r in audit["flagged_reasons"])

    def test_memory_homogenization_is_flagged(self):
        # one signature dominates the immunity memory -> collapse risk
        recs = _recs("windows_c2", 90, 45, "v") + _recs("linux_sentinel", 5, 2, "x") \
            + _recs("aws_vpc", 5, 2, "y")
        audit = ba.run_bias_audit(recs)
        assert audit["homogenization"]["homogenized"] is True
        assert audit["flagged"] is True

    def test_collect_and_audit_uses_injected_collector_and_writes(self, tmp_path):
        recs = _recs("linux_sentinel", 10, 1, "a") + _recs("windows_c2", 10, 9, "b")
        audit = ba.collect_and_audit(collector=lambda c, coll, lim: recs,
                                     report_dir=str(tmp_path))
        assert audit["flagged"] is True
        assert Path(audit["report_path"]).exists()

    def test_scroll_qdrant_collector_reads_payloads(self):
        class _Pt:
            def __init__(self, pl): self.payload = pl

        class _Client:
            def scroll(self, collection_name, with_payload, limit, offset):
                return [_Pt({"source_type": "aws_vpc", "vector_name": "cloud_flow",
                             "is_true_positive": True, "action": "contain"})], None
        recs = ba._scroll_qdrant(_Client(), "nexus_swarm_memory", 10)
        assert recs == [{"source_type": "aws_vpc", "vector_name": "cloud_flow",
                         "is_true_positive": True, "action": "contain"}]


# -- NC-2 calibration ledger -------------------------------------------------
class TestCalibrationLedger:
    def test_record_and_trend_roundtrip(self, tmp_path):
        ledger = str(tmp_path / "cal.jsonl")
        # 3 well-calibrated, 1 over-confident miss
        cal.record_disposition({"is_true_positive": True, "confidence": 0.9}, "true_positive",
                               "e1", ledger)
        cal.record_disposition({"is_true_positive": False, "confidence": 0.85}, "false_positive",
                               "e2", ledger)
        cal.record_disposition({"is_true_positive": True, "confidence": 0.95}, "false_positive",
                               "e3", ledger)  # confident miss
        recs = cal.load_ledger(ledger)
        assert len(recs) == 3
        trend = cal.brier_trend(recs)
        assert trend["n"] == 3
        assert 0.0 <= trend["mean_brier"] <= 1.0
        assert trend["accuracy"] == pytest.approx(2 / 3, abs=1e-3)
        assert trend["over_confidence"] > 0, "a confident miss must raise over-confidence"

    def test_empty_ledger_is_safe(self, tmp_path):
        assert cal.load_ledger(str(tmp_path / "none.jsonl")) == []
        assert cal.brier_trend([])["mean_brier"] is None


# -- NC-3 frontier-pin enforcement (source contract; pure logic in controls) --
class TestFrontierPinEnforcement:
    SRC = (HUNTER / "agents/llm_providers.py").read_text()

    def test_build_chain_refuses_floating_frontier(self):
        assert "def frontier_pin_allowed(" in self.SRC
        assert "frontier_pin_allowed(name, cfg)" in self.SRC, "build_failover_chain must call the gate"
        assert "is_floating_model" in self.SRC
        assert "NEXUS_ALLOW_FLOATING_FRONTIER" in self.SRC  # explicit opt-out
        # the gate must `continue` (skip) a refused provider, not build it
        seg = self.SRC.split("ok, reason = frontier_pin_allowed", 1)[1][:200]
        assert "continue" in seg
