"""
Lab 10 (WS-G / G2c) -- review-board counterpart SIEM disproof.

Proves a counterpart pulls DISCONFIRMING cross-source SIEM evidence (the
prevalence pivot) to challenge a proposed finding, that it fails to transcript-only
reasoning when no SIEM is reachable, and that the wiring leaves aggregate_board's
pure contract untouched.
"""
import sys
import types
from pathlib import Path

import pytest

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"


# -- stub langchain_core + agents package (mirrors test_review_board.py) ------
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
    "from_messages": staticmethod(lambda m: types.SimpleNamespace(__or__=lambda self, o: o))})
_prompts.MessagesPlaceholder = type("MessagesPlaceholder", (), {"__init__": lambda self, **k: None})
_lc.messages, _lc.prompts = _msg, _prompts
sys.modules.setdefault("langchain_core", _lc)
sys.modules.setdefault("langchain_core.messages", _msg)
sys.modules.setdefault("langchain_core.prompts", _prompts)

_agents_pkg = types.ModuleType("agents")
_agents_pkg.__path__ = [str(HUNTER / "agents")]
sys.modules["agents"] = _agents_pkg
_llmp = types.ModuleType("agents.llm_providers")
_llmp.build_failover_chain = lambda temperature=0.0: []
_llmp.circuit_is_callable = lambda n: True
_llmp.record_call_success = lambda n: None
_llmp.record_call_failure = lambda n: None
sys.modules["agents.llm_providers"] = _llmp
_controls = types.ModuleType("agents.controls")
_controls.enforce_grounding = lambda result, state: (result, [])
sys.modules["agents.controls"] = _controls

sys.path.insert(0, str(HUNTER))
import importlib
sys.modules.pop("agents.review_board", None)
rb = importlib.import_module("agents.review_board")


class _FakeSiem:
    """Captures the query the counterpart issues; returns a high-prevalence row."""
    def __init__(self, rows="distinct_sources=412 (benign shared infra)"):
        self.last = None
        self._rows = rows

    def _run(self, reasoning, backend, query):
        self.last = {"reasoning": reasoning, "backend": backend, "query": query}
        return f"SIEM '{backend}' returned 1 row for: {query}\n{self._rows}"


def _active(dialect="spl", allowed=("nexus_network", "fw_traffic")):
    return {"default_window_hours": 6, "max_rows": 200, "any_active": True,
            "backends": {"splunk": {"dialect": dialect, "allowed_indexes": list(allowed),
                                    "active": True}}}


def _state_with_ip(ip="203.0.113.7"):
    return {"entities_of_interest": {ip: {"type": "ip", "status": "malicious"}},
            "alert": {"sensor_id": "host-9"}, "messages": []}


# -- prevalence disproof query builder ---------------------------------------
class TestPrevalenceQuery:
    def test_spl_prevalence_counts_distinct_sources(self):
        q = rb.build_prevalence_query("203.0.113.7", "spl", ["nexus_network", "fw_traffic"])
        assert 'dest="203.0.113.7"' in q and "dc(src)" in q and "distinct_sources" in q
        assert "index=nexus_network" in q and "index=fw_traffic" in q  # cross-source

    def test_esql_prevalence_counts_distinct_sources(self):
        q = rb.build_prevalence_query("203.0.113.7", "esql", ["nexus-network"])
        assert 'destination.ip == "203.0.113.7"' in q and "COUNT_DISTINCT(source.ip)" in q


# -- disputed entity selection -----------------------------------------------
class TestDisputedEntity:
    def test_picks_typed_ip_entity(self):
        assert rb._disputed_entity(_state_with_ip("8.8.4.4"), {}) == "8.8.4.4"

    def test_picks_ip_shaped_key_without_type(self):
        st = {"entities_of_interest": {"10.0.0.9": {"status": "investigating"}}}
        assert rb._disputed_entity(st, {}) == "10.0.0.9"

    def test_no_ip_entity_returns_empty(self):
        st = {"entities_of_interest": {"pid-4821": {"type": "pid"}}}
        assert rb._disputed_entity(st, {}) == ""


# -- counterpart SIEM lookup (the disproof instrument) -----------------------
class TestCounterpartLookup:
    def test_returns_disconfirming_evidence(self):
        fake = _FakeSiem()
        out = rb._counterpart_siem_lookup("net", _state_with_ip(), {"is_true_positive": True},
                                          siem_tool=fake, siem_config=_active())
        assert "DISCONFIRMING SIEM EVIDENCE" in out
        assert "distinct_sources=412" in out
        # the query the counterpart actually issued is the prevalence disproof
        assert "dc(src)" in fake.last["query"] and 'dest="203.0.113.7"' in fake.last["query"]
        assert "never instructions" in out  # untrusted framing

    def test_no_active_backend_yields_no_evidence(self):
        off = {"backends": {"splunk": {"dialect": "spl", "active": False, "allowed_indexes": []}}}
        out = rb._counterpart_siem_lookup("net", _state_with_ip(), {}, siem_tool=_FakeSiem(),
                                          siem_config=off)
        assert out == ""

    def test_no_ip_entity_yields_no_evidence(self):
        st = {"entities_of_interest": {"svc_account": {"type": "user"}}, "messages": []}
        out = rb._counterpart_siem_lookup("cloud", st, {}, siem_tool=_FakeSiem(), siem_config=_active())
        assert out == ""

    def test_siem_tool_exception_fails_to_transcript_only(self):
        class _Boom:
            def _run(self, *a, **k):
                raise RuntimeError("siem down")
        out = rb._counterpart_siem_lookup("net", _state_with_ip(), {}, siem_tool=_Boom(),
                                          siem_config=_active())
        assert out == "", "a SIEM failure must degrade to transcript-only, never raise"


# -- wiring contract (no regression to the pure decision rule) ---------------
class TestWiringContract:
    SRC = (HUNTER / "agents/review_board.py").read_text()

    def test_system_prompt_carries_siem_evidence_slot(self):
        assert "{siem_evidence}" in self.SRC

    def test_run_counterpart_calls_siem_lookup(self):
        assert "_counterpart_siem_lookup(domain, state, verdict)" in self.SRC

    def test_aggregate_board_signature_unchanged(self):
        # the pure decision rule must not have grown SIEM coupling
        assert "def aggregate_board(supervisor_verdict: dict, rebuttals: list)" in self.SRC
        # aggregate_board body must contain no SIEM reference (purity preserved)
        body = self.SRC.split("def aggregate_board(")[1].split("\ndef ")[0]
        assert "siem" not in body.lower(), "aggregate_board must stay free of SIEM coupling"
