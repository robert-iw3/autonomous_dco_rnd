"""
Lab agentic-swarm -- Phase 5: live acquisition & detonation swarm integration.

Wires the Det Chamber into the swarm:
  * a `file` entity the host_expert can confirm as TP,
  * `AcquisitionRequestSchema` -- the validated request the host_expert's
    acquire_and_detonate tool emits (first-line path safety; the deterministic
    worker re-validates with the full deny-list),
  * a confidence GATE so acquisition only fires on a high-confidence (critic-
    reviewed) TP,
  * the enrichment loop-back: a `nexus.alerts.detonation` result maps to a
    follow-up SOAR action -- contain on malicious, RESTORE on benign (false
    positive), manual review on a custody failure.

Heavy deps (langchain_core) are stubbed before import; pydantic is real.
"""

import sys
import types
from pathlib import Path

import pytest

HUNTER = Path(__file__).resolve().parents[2] / "analytics" / "llm_hunter"
for p in (HUNTER, HUNTER / "tools", HUNTER / "agents"):
    sys.path.insert(0, str(p))


def _stub(name):
    if name not in sys.modules:
        m = types.ModuleType(name)
        m.__path__ = []
        sys.modules[name] = m
    return sys.modules[name]


# langchain_core.messages (state.py) + langchain_core.tools (acquire_detonate.py)
class _BaseMessage:
    id = None
    def __init__(self, content="", **kw): self.content = content

_lc = _stub("langchain_core")
_msg = _stub("langchain_core.messages")
_msg.BaseMessage = _BaseMessage
_msg.HumanMessage = type("HumanMessage", (_BaseMessage,), {})
_msg.RemoveMessage = type("RemoveMessage", (_BaseMessage,), {})
_lc.messages = _msg

_tools_mod = _stub("langchain_core.tools")
class _BaseTool:                      # minimal stand-in for langchain BaseTool
    name = ""
    description = ""
    args_schema = None
_tools_mod.BaseTool = _BaseTool

import state                          # noqa: E402
import acquire_detonate as ad         # noqa: E402
import detonation_enrichment as de    # noqa: E402


# ─── file entity + AcquisitionRequestSchema ──────────────────────────────────
def test_file_entity_type_allowed():
    e = state.EntityTracking(type="file", status="malicious", notes="/tmp/evil.bin")
    assert e.type == "file"


def test_acquisition_request_valid():
    r = state.AcquisitionRequestSchema(
        incident_id="INC-1", host="ep-1", file_path="/home/u/evil.bin",
        os_family="linux", confidence=0.93, reason="host_expert confirmed TP")
    assert r.os_family == "linux"


@pytest.mark.parametrize("bad", [
    {"file_path": "/home/u/*.bin"},          # wildcard
    {"file_path": "/a/../etc/shadow"},        # traversal
    {"os_family": "solaris"},                 # bad os
    {"confidence": 1.5},                      # out of range
])
def test_acquisition_request_rejects_bad_input(bad):
    base = dict(incident_id="INC-1", host="ep", file_path="/home/u/x.bin",
                os_family="linux", confidence=0.9, reason="r")
    base.update(bad)
    with pytest.raises(Exception):
        state.AcquisitionRequestSchema(**base)


# ─── acquire tool gating (auto on critic-reviewed TP + threshold) ────────────
def test_gate_blocks_low_confidence():
    assert ad.should_acquire(0.95) is True
    assert ad.should_acquire(0.50) is False


def test_tool_refuses_below_gate_and_does_not_emit(monkeypatch):
    emitted = []
    monkeypatch.setattr(ad, "_publish", lambda subj, payload: emitted.append((subj, payload)))
    tool = ad.AcquireAndDetonateTool()
    out = tool._run(host="ep", file_path="/home/u/x.bin", os_family="linux",
                    reason="weak", confidence=0.4, incident_id="INC-1")
    assert "refus" in out.lower()
    assert emitted == [], "must not dispatch acquisition below the confidence gate"


def test_tool_emits_request_above_gate(monkeypatch):
    emitted = []
    monkeypatch.setattr(ad, "_publish", lambda subj, payload: emitted.append((subj, payload)))
    tool = ad.AcquireAndDetonateTool()
    out = tool._run(host="ep", file_path="/home/u/x.bin", os_family="linux",
                    reason="confirmed", confidence=0.92, incident_id="INC-1")
    assert emitted and emitted[0][0] == ad.ACQUIRE_SUBJECT == "nexus.acquire.request"
    assert emitted[0][1]["file_path"] == "/home/u/x.bin"
    assert "detonat" in out.lower()


# ─── enrichment loop-back: detonation result -> follow-up action ─────────────
def _result(status="detonated", summary=None, **kw):
    base = {"incident_id": "INC-9", "host": "ep-9", "sha256": "ab" * 32,
            "os_family": "linux", "status": status, "summary": summary}
    base.update(kw)
    return base


def test_malicious_detonation_triggers_containment():
    res = _result(summary={"static": {"yara_matches": ["Win.Trojan"]}})
    action = de.enrichment_decision(res, had_containment=False)
    assert action["action_type"] == "isolate_host"
    state.SoarExecutionSchema(**action)   # must be a valid SOAR action


def test_benign_detonation_after_containment_triggers_restore():
    res = _result(summary={"verdict": "benign"})
    action = de.enrichment_decision(res, had_containment=True)
    assert action["action_type"] == "restore"
    state.SoarExecutionSchema(**action)   # 'restore' must be an allowed action_type


def test_benign_without_containment_takes_no_action():
    res = _result(summary={"verdict": "benign"})
    assert de.enrichment_decision(res, had_containment=False) is None


def test_custody_failure_routes_to_manual_review():
    action = de.enrichment_decision(_result(status="custody_failed", summary=None),
                                    had_containment=False)
    assert action["action_type"] == "manual_review_required"


def test_interpret_summary():
    assert de.interpret_summary({"static": {"yara_matches": ["x"]}}) == "malicious"
    assert de.interpret_summary({"verdict": "benign"}) == "benign"
    assert de.interpret_summary({}) == "unknown"


# ─── wiring (source-level, avoids importing the heavy tool/orchestrator graph) ─
def test_tool_wired_into_host_rbac():
    src = (HUNTER / "tools" / "__init__.py").read_text()
    assert "AcquireAndDetonateTool" in src and "HOST_ANALYST_TOOLS" in src


def test_orchestrator_consumes_detonation_alerts():
    src = (HUNTER / "orchestrator.py").read_text()
    assert "nexus.alerts.detonation" in src and "enrichment" in src.lower()


def test_host_expert_sop_mentions_acquisition():
    src = (HUNTER / "agents" / "host_expert.py").read_text().lower()
    assert "acquire" in src and "detonat" in src
