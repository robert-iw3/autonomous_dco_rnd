"""
WS-A B0 / M-27b — 11_join_outcomes.py outcome join.

Verifies the delayed-ground-truth join (plan §3.4): per-investigation metrics
records get their `outcome{operator_action, soar_status, reinfection_24h,
label_latency_s}` filled from the RLHF operator labels, SOAR callbacks, and the
24h re-infection check — keyed by event_id. Pure; loaded via importlib.
"""
import importlib.util as ilu
import sys
from pathlib import Path

SCRIPTS = Path(__file__).parent.parent.parent / "mlops" / "scripts"


def _load(modname, filename):
    spec = ilu.spec_from_file_location(modname, str(SCRIPTS / filename))
    mod = ilu.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


jo = _load("join_outcomes", "11_join_outcomes.py")


def _metric(eid, ts):
    return {"event_id": eid, "ts": ts, "verdict": {"is_tp": True}, "outcome": {}}


class TestJoinOutcomes:
    def test_full_join_fills_outcome_and_latency(self):
        metrics = [_metric("e1", 1000.0)]
        labels = [{"event_id": "e1", "operator_action": "confirm", "ts": 1900.0}]
        callbacks = [{"incident_id": "e1", "status": "COMPLETED"}]
        reinfections = {"e1": True}
        out = jo.join_outcomes(metrics, labels, callbacks, reinfections)
        o = out[0]["outcome"]
        assert o["operator_action"] == "confirm"
        assert o["soar_status"] == "COMPLETED"
        assert o["reinfection_24h"] is True
        assert o["label_latency_s"] == 900.0     # label ts - investigation ts

    def test_unlabelled_investigation_has_empty_outcome(self):
        out = jo.join_outcomes([_metric("e2", 10.0)], [], [], {})
        o = out[0]["outcome"]
        assert o["operator_action"] == "" and o["label_latency_s"] is None
        assert o["soar_status"] == "" and o["reinfection_24h"] is False

    def test_join_is_keyed_by_event_id(self):
        metrics = [_metric("a", 1.0), _metric("b", 2.0)]
        labels = [{"event_id": "b", "operator_action": "dismiss", "ts": 5.0}]
        out = {r["event_id"]: r["outcome"] for r in jo.join_outcomes(metrics, labels, [], {})}
        assert out["a"]["operator_action"] == ""
        assert out["b"]["operator_action"] == "dismiss" and out["b"]["label_latency_s"] == 3.0

    def test_does_not_mutate_input(self):
        metrics = [_metric("e1", 1.0)]
        jo.join_outcomes(metrics, [{"event_id": "e1", "operator_action": "x", "ts": 2.0}], [], {})
        assert metrics[0]["outcome"] == {}, "join returns new records; inputs untouched"

    def test_label_index_helpers(self):
        idx = jo.index_by(["event_id"], [{"event_id": "e1", "v": 1}, {"event_id": "e2", "v": 2}])
        assert idx["e1"]["v"] == 1 and idx["e2"]["v"] == 2
