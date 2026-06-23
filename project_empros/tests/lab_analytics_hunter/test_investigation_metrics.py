"""
WS-A B0 / M-27a — InvestigationMetrics record builder (pure).

The measurement plane's per-investigation record (plan §3.4), built from the swarm
state at the end of trigger_swarm. Pure (stdlib only) so the embedded-metrics logic
is verified without the orchestrator; the NATS emit + parquet ledger are thin IO.
"""
import sys
from pathlib import Path

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"
sys.path.insert(0, str(HUNTER))

import investigation_metrics as im  # noqa: E402


def _state(**over):
    s = {
        "verdict": {"is_true_positive": True, "confidence": 0.91, "recommended_action": "contain"},
        "analysis_complete": True,
        "gate_overrides": 1,
        "entities_of_interest": {
            "10.0.0.9": {"type": "ip", "status": "malicious"},
            "evil.test": {"type": "domain", "status": "malicious"},
            "1.2.3.4": {"type": "ip", "status": "cleared"},
            "host-7": {"type": "ip", "status": "investigating"},
        },
        "memory_enrichment": {},
    }
    s.update(over)
    return s


def _alert(**over):
    a = {"event_id": "evt-1", "source_type": "sysmon_sensor",
         "vector_name": "windows_math", "anomaly_score": 0.93}
    a.update(over)
    return a


class TestBuildRecord:
    def test_core_fields(self):
        r = im.build_record(_alert(), _state(),
                            efficiency={"turns": 6, "llm_calls": 9, "wall_ms": 4200},
                            model_versions={"model_c": "20260609T2200-c41"})
        assert r["event_id"] == "evt-1" and r["source_type"] == "sysmon_sensor"
        assert r["anomaly_score"] == 0.93
        assert r["verdict"] == {"is_tp": True, "confidence": 0.91, "action": "contain"}
        assert r["analysis_complete"] is True and r["gate_overrides_used"] == 1
        assert r["model_versions"]["model_c"] == "20260609T2200-c41"
        assert r["efficiency"]["turns"] == 6 and r["efficiency"]["wall_ms"] == 4200
        assert "ts" in r

    def test_entity_rollup(self):
        e = im.build_record(_alert(), _state())["entities"]
        assert e["seeded"] == 4
        assert e["malicious"] == 2 and e["cleared"] == 1
        assert e["resolved"] == 3          # malicious + cleared (not pending/investigating)

    def test_outcome_empty_until_joined(self):
        # §3.4: outcome is joined later by 11_join_outcomes; absent at emit time
        r = im.build_record(_alert(), _state())
        assert r["outcome"] == {}

    def test_defensive_on_sparse_state(self):
        r = im.build_record({"event_id": "e"}, {})
        assert r["event_id"] == "e"
        assert r["verdict"]["is_tp"] is False and r["entities"]["seeded"] == 0
        assert r["efficiency"]["turns"] == 0

    def test_critic_and_immunity_flags(self):
        s = _state(critic={"invoked": True, "overrode": True, "direction": "TP->FP"},
                   immunity_hit=True, immunity_point_id="pt-9")
        r = im.build_record(_alert(), s)
        assert r["critic"]["invoked"] is True and r["critic"]["overrode"] is True
        assert r["immunity"]["hit"] is True and r["immunity"]["point_id"] == "pt-9"

    def test_record_is_json_serializable(self):
        import json
        json.dumps(im.build_record(_alert(), _state(), efficiency={"turns": 3}))


class TestOrchestratorEmitWiring:
    """The orchestrator emits the record fire-and-forget at the end of trigger_swarm
    (source-contract: the emit is thin IO; the builder logic is unit-tested above)."""

    def _src(self):
        return (HUNTER / "orchestrator.py").read_text()

    def test_builds_and_publishes_metrics(self):
        src = self._src()
        assert "build_investigation_metrics" in src
        assert "nexus.metrics.investigation" in src

    def test_emit_is_fire_and_forget(self):
        src = self._src()
        emit = src[src.find("async def _emit_investigation_metrics"):]
        emit = emit[:emit.find("\n\nasync def", 1)] if "\n\nasync def" in emit[1:] else emit[:800]
        assert "try:" in emit and "except" in emit and "non-fatal" in emit
        # called after SOAR dispatch, not before (must never block containment)
        assert src.find("_dispatch_soar(alert, action") < src.find("_emit_investigation_metrics(")
