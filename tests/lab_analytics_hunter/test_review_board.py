"""
Lab 10 -- Adversarial Review Board (llm_hunter).

Proves the critic-replacement contract: a finding is a TRUE POSITIVE only if NO
implicated expert-counterpart can disprove its domain. Two full mock-simulation
workflows run the real `review_board_node` end to end with the LLM seam
(`_run_counterpart`) stubbed:

  A. the swarm BELIEVES it's a TP, but counterparts DISPROVE it      -> overridden
  B. a genuine TP that counterparts CANNOT disprove                  -> confirmed

plus the pure `aggregate_board` decision rule (fail-closed, FP symmetry).

No network / no LLM: langchain_core and agents.llm_providers are stubbed so the
board imports cleanly, exactly like test_hunter_contracts.py stubs langchain_core.
"""
import asyncio
import sys
import types
from pathlib import Path

import pytest

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"


# -- stub langchain_core (.messages + .prompts) -------------------------------
class _BaseMessage:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


_lc = types.ModuleType("langchain_core")
_msg = types.ModuleType("langchain_core.messages")
_msg.BaseMessage = _BaseMessage
_msg.RemoveMessage = type("RemoveMessage", (_BaseMessage,), {})
_msg.HumanMessage = type("HumanMessage", (_BaseMessage,), {})
_prompts = types.ModuleType("langchain_core.prompts")
_prompts.ChatPromptTemplate = type("ChatPromptTemplate", (), {
    "from_messages": staticmethod(lambda m: types.SimpleNamespace(__or__=lambda self, o: o)),
})
_prompts.MessagesPlaceholder = type("MessagesPlaceholder", (), {"__init__": lambda self, **k: None})
_lc.messages, _lc.prompts = _msg, _prompts
sys.modules.setdefault("langchain_core", _lc)
sys.modules.setdefault("langchain_core.messages", _msg)
sys.modules.setdefault("langchain_core.prompts", _prompts)

# -- stub the `agents` package (avoid its heavy __init__) + llm_providers -----
_agents_pkg = types.ModuleType("agents")
_agents_pkg.__path__ = [str(HUNTER / "agents")]
sys.modules["agents"] = _agents_pkg
_llmp = types.ModuleType("agents.llm_providers")
_llmp.build_failover_chain = lambda temperature=0.0: []
_llmp.circuit_is_callable = lambda n: True
_llmp.record_call_success = lambda n: None
_llmp.record_call_failure = lambda n: None
sys.modules["agents.llm_providers"] = _llmp

sys.path.insert(0, str(HUNTER))

import importlib
# Force a clean import (another suite's source-contract stub may replace this in
# sys.modules) and capture the real node ref so it can't be clobbered later.
sys.modules.pop("agents.review_board", None)
rb = importlib.import_module("agents.review_board")
NODE = rb.review_board_node
from state import FP_CONFIDENCE_GATE  # noqa: E402


def R(domain, implicated, disproved, conf, axis="", benign="", just="ok"):
    return rb.RebuttalSchema(domain=domain, implicated=implicated, disproved=disproved,
                             confidence=conf, failed_axis=axis, benign_alternative=benign,
                             justification=just)


# ------------------------ pure decision rule --------------------------------
def test_tp_confirmed_only_when_no_counterpart_disproves():
    sv = {"is_true_positive": True, "confidence": 0.9}
    rebuttals = [R("host", True, False, 0.1), R("net", True, False, 0.2),
                 R("cloud", False, False, 0.0), R("nettap", False, False, 0.0)]
    out = rb.aggregate_board(sv, rebuttals)["verdict"]
    assert out["is_true_positive"] is True
    assert out["recommended_action"] == "contain"
    assert out["confidence"] == pytest.approx(min(0.9, 1 - 0.2))  # tempered by the best rebuttal
    assert "CONFIRMED" in out["justification"]


def test_tp_overridden_when_one_counterpart_disproves():
    sv = {"is_true_positive": True, "confidence": 0.9}
    rebuttals = [R("host", True, True, 0.85, "benign_alternative", "nessus vuln scan"),
                 R("net", True, False, 0.1),
                 R("cloud", False, False, 0.0), R("nettap", False, False, 0.0)]
    out = rb.aggregate_board(sv, rebuttals)["verdict"]
    assert out["is_true_positive"] is False, "a disproved TP must be overridden"
    assert out["recommended_action"] == "monitor", "override never auto-contains"
    assert out["confidence"] < 0.5
    assert "host" in out["justification"] and "nessus" in out["justification"]


def test_tp_fails_closed_when_implicated_domain_unreviewable():
    sv = {"is_true_positive": True, "confidence": 0.9}
    rebuttals = [R("host", True, False, 0.0, just="COUNTERPART_UNREVIEWABLE: no provider"),
                 R("net", True, False, 0.1)]
    out = rb.aggregate_board(sv, rebuttals)["verdict"]
    assert out["is_true_positive"] is False
    assert out["recommended_action"] == "monitor"
    assert out["confidence"] == 0.0


def test_tp_with_no_implicated_domain_fails_closed():
    sv = {"is_true_positive": True, "confidence": 0.9}
    rebuttals = [R(d, False, False, 0.0) for d in ("host", "net", "cloud", "nettap")]
    out = rb.aggregate_board(sv, rebuttals)["verdict"]
    assert out["is_true_positive"] is False and out["recommended_action"] == "monitor"


def test_fp_dismissal_upheld_when_unchallenged():
    sv = {"is_true_positive": False, "confidence": 0.9}
    rebuttals = [R("host", True, False, 0.1), R("net", False, False, 0.0)]
    out = rb.aggregate_board(sv, rebuttals)["verdict"]
    assert out["is_true_positive"] is False
    assert out["recommended_action"] == "dismiss"
    assert out["confidence"] == 0.9


def test_fp_dismissal_disproved_drops_below_gate_never_contains():
    sv = {"is_true_positive": False, "confidence": 0.9}
    rebuttals = [R("host", True, True, 0.8, benign="", just="unexplained lsass access")]
    out = rb.aggregate_board(sv, rebuttals)["verdict"]
    assert out["is_true_positive"] is False
    assert out["recommended_action"] == "monitor", "disproved dismissal must NOT auto-contain"
    assert out["confidence"] < FP_CONFIDENCE_GATE, "must stay below the immunity gate"


# -------------------- full mock-simulation workflows ------------------------
def _patch_counterparts(monkeypatch, scripted: dict):
    async def fake(domain, state, verdict):
        return scripted[domain]
    monkeypatch.setattr(rb, "_run_counterpart", fake)


def test_workflow_A_believed_tp_is_disproved_by_counterparts(monkeypatch):
    """The swarm thinks it found a true positive; the host + net counterparts
    disprove it (benign vuln scanner). The board overrides to monitor."""
    scripted = {
        "host": R("host", True, True, 0.88, "benign_alternative",
                  "credentialed Qualys vuln scan from the scanner subnet"),
        "net": R("net", True, True, 0.8, "no_execution_proof",
                 "all connections were RST/blocked -- no session, no bytes"),
        "cloud": R("cloud", False, False, 0.0),
        "nettap": R("nettap", False, False, 0.0),
    }
    _patch_counterparts(monkeypatch, scripted)
    state = {"verdict": {"is_true_positive": True, "confidence": 0.86,
                         "recommended_action": "contain"}, "messages": []}

    result = asyncio.run(NODE(state))
    v = result["verdict"]
    assert result["next_agent"] == "response_agent"
    assert v["is_true_positive"] is False, "disproved finding must not stay a TP"
    assert v["recommended_action"] == "monitor"
    assert "OVERRIDE" in v["justification"] or "disproved" in v["justification"]


def test_workflow_B_real_tp_survives_complete_review(monkeypatch):
    """A genuine true positive: every implicated counterpart tries and FAILS to
    disprove it, so the board confirms containment."""
    scripted = {
        "host": R("host", True, False, 0.1, just="confirmed lsass dump + scheduled-task persistence; no benign cause"),
        "net": R("net", True, False, 0.15, just="established C2 session, 4MB beaconed egress -- real execution"),
        "cloud": R("cloud", False, False, 0.0),
        "nettap": R("nettap", True, False, 0.2, just="periodic 60s beacon cadence to the same dst -- malicious"),
    }
    _patch_counterparts(monkeypatch, scripted)
    state = {"verdict": {"is_true_positive": True, "confidence": 0.92,
                         "recommended_action": "contain"}, "messages": []}

    result = asyncio.run(NODE(state))
    v = result["verdict"]
    assert v["is_true_positive"] is True, "an undisputed finding must be confirmed"
    assert v["recommended_action"] == "contain"
    assert "CONFIRMED" in v["justification"]
    # board confidence is tempered by the strongest (failed) rebuttal, not inflated
    assert v["confidence"] == pytest.approx(min(0.92, 1 - 0.2))


def test_workflow_confabulated_tp_is_grounding_demoted(monkeypatch):
    """Every counterpart FAILS to disprove (board would CONFIRM), but the
    supervisor's finding cites an IP that appears nowhere in the evidence corpus.
    The wired grounding control must demote the confirmed TP to monitor."""
    scripted = {
        "host": R("host", True, False, 0.1, just="real persistence write"),
        "net": R("net", True, False, 0.1, just="established session"),
        "cloud": R("cloud", False, False, 0.0),
        "nettap": R("nettap", False, False, 0.0),
    }
    _patch_counterparts(monkeypatch, scripted)
    # No messages/entities/alert mention 203.0.113.250 -> it is confabulated.
    state = {
        "alert": {"sensor_id": "host-9", "raw_event": {}},
        "entities_of_interest": {},
        "messages": [],
        "verdict": {"is_true_positive": True, "confidence": 0.95,
                    "recommended_action": "contain",
                    "justification": "confirmed C2 beacon to 203.0.113.250"},
    }
    v = asyncio.run(NODE(state))["verdict"]
    assert v["is_true_positive"] is False, "ungrounded (confabulated) TP must be demoted"
    assert v["recommended_action"] == "monitor"
    assert "GROUNDING OVERRIDE" in v["justification"]
    assert "203.0.113.250" in v["justification"]


def test_workflow_grounded_tp_survives_grounding_check(monkeypatch):
    """The same finding, but the cited IP IS present in the evidence corpus -- the
    board's CONFIRMED true positive must stand."""
    scripted = {
        "host": R("host", True, False, 0.1, just="real persistence write"),
        "net": R("net", True, False, 0.15, just="established C2 session + egress"),
        "cloud": R("cloud", False, False, 0.0),
        "nettap": R("nettap", False, False, 0.0),
    }
    _patch_counterparts(monkeypatch, scripted)
    state = {
        "alert": {"sensor_id": "host-9", "raw_event": {"dst": "203.0.113.7"}},
        "entities_of_interest": {"203.0.113.7": {"type": "ip", "status": "malicious"}},
        "messages": [],
        "verdict": {"is_true_positive": True, "confidence": 0.92,
                    "recommended_action": "contain",
                    "justification": "confirmed C2 beacon to 203.0.113.7"},
    }
    v = asyncio.run(NODE(state))["verdict"]
    assert v["is_true_positive"] is True, "a grounded TP must survive"
    assert v["recommended_action"] == "contain"
    assert "CONFIRMED" in v["justification"]


def test_workflow_single_disprover_vetoes_the_board(monkeypatch):
    """Even if three counterparts uphold it, ONE credible disproof vetoes the TP --
    the board requires unanimous survival, not a majority."""
    scripted = {
        "host": R("host", True, False, 0.1),
        "net": R("net", True, False, 0.1),
        "cloud": R("cloud", True, True, 0.82, "benign_alternative", "Terraform CI service account apply"),
        "nettap": R("nettap", True, False, 0.1),
    }
    _patch_counterparts(monkeypatch, scripted)
    state = {"verdict": {"is_true_positive": True, "confidence": 0.9}, "messages": []}
    v = asyncio.run(NODE(state))["verdict"]
    assert v["is_true_positive"] is False and v["recommended_action"] == "monitor"
    assert "cloud" in v["justification"]
