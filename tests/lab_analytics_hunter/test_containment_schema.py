"""
ContainmentStep / ContainmentProtocol schemas + SoarExecutionSchema
generalization (target_class / environment / containment_steps), back-compat kept.
"""
import sys
import types
from pathlib import Path

import pytest
from pydantic import ValidationError

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"

# state.py imports langchain_core.messages - stub it (same pattern as siblings).
_lc = types.ModuleType("langchain_core")
_msg = types.ModuleType("langchain_core.messages")
_msg.BaseMessage = type("BaseMessage", (),  {})
_msg.RemoveMessage = type("RemoveMessage", (),  {})
_lc.messages = _msg
sys.modules.setdefault("langchain_core", _lc)
sys.modules.setdefault("langchain_core.messages", _msg)
sys.path.insert(0, str(HUNTER))

import state  # noqa: E402


def _step(**over):
    base = dict(target="dc-prod-01", target_class="endpoint", environment="windows",
                action="isolate_host", executor="agent_task_v1", wave=1,
                certainty=0.95, certainty_level="confirmed", gate="auto")
    base.update(over)
    return state.ContainmentStep(**base)


class TestContainmentStep:
    def test_valid(self):
        s = _step()
        assert s.action == "isolate_host" and s.gate == "auto"

    def test_gate_is_constrained(self):
        with pytest.raises(ValidationError):
            _step(gate="just_do_it")

    def test_wave_bounds(self):
        with pytest.raises(ValidationError):
            _step(wave=3)


class TestContainmentProtocol:
    def test_holds_steps_and_coverage(self):
        p = state.ContainmentProtocol(
            incident_id="evt-1", steps=[_step(), _step(action="collect_forensics", wave=1)],
            coverage={"tp_entities": 2, "covered": 2, "uncovered": []},
            kill_chain_closed=True)
        assert len(p.steps) == 2 and p.kill_chain_closed is True

    def test_escalations_default_empty(self):
        p = state.ContainmentProtocol(incident_id="evt-2")
        assert p.steps == [] and p.escalations == [] and p.kill_chain_closed is False


class TestSoarSchemaGeneralization:
    def test_back_compat_minimal_payload(self):
        # an old-shape payload (no new fields) must still validate
        s = state.SoarExecutionSchema(incident_id="e", action_type="isolate_host",
                                      target_sensor="h", reason="x")
        assert s.environment is None and s.target_class is None and s.containment_steps == []

    def test_accepts_new_fields(self):
        s = state.SoarExecutionSchema(
            incident_id="e", action_type="isolate_host", target_sensor="h", reason="x",
            environment="aws", target_class="cloud_instance",
            containment_steps=[_step(target_class="cloud_instance", environment="aws",
                                     executor="aws_containment_v1")])
        assert s.environment == "aws" and len(s.containment_steps) == 1
