"""
NIST AI 600-1 control WIRING tests (llm_hunter).

The wave-2/4 suites prove the control *logic* in `agents.controls` and the thin
ledger wrappers in isolation. This suite proves the controls are actually
*wired into the live agentic workflow* -- i.e. that running the real graph nodes
produces the control side-effects -- which is the gap unit tests cannot catch:

  NC-10  every investigation appends its verdict to the tamper-evident lineage
  NC-11  every investigation records a per-run inference energy estimate
  NC-9   a confabulated (grounding-violated) verdict is captured as a hard example
  +      the review board surfaces grounding violations into state for NC-9
  +      a ledger I/O failure never blocks the containment decision (fail-soft)

These run the REAL `response_agent` / `review_board_node` end to end with only the
network/LLM seams (qdrant, redis, langchain, llm_providers) stubbed -- exactly the
style of test_review_board.py. They FAIL on a tree where the ledgers are defined
but never called.
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

# -- stub qdrant_client (response.py builds an AsyncQdrantClient at import) ----
_qc = types.ModuleType("qdrant_client")
_qc.AsyncQdrantClient = type("AsyncQdrantClient", (), {"__init__": lambda self, *a, **k: None})
_qcm = types.ModuleType("qdrant_client.models")
_qcm.PointStruct = type("PointStruct", (), {"__init__": lambda self, *a, **k: None})
sys.modules.setdefault("qdrant_client", _qc)
sys.modules.setdefault("qdrant_client.models", _qcm)

# -- stub redis (response.py builds a Redis client at import) ------------------
_redis = types.ModuleType("redis")
_redis_aio = types.ModuleType("redis.asyncio")
_redis_aio.Redis = type("Redis", (), {"from_url": staticmethod(lambda *a, **k: object())})
_redis.asyncio = _redis_aio
sys.modules.setdefault("redis", _redis)
sys.modules.setdefault("redis.asyncio", _redis_aio)

# -- stub the `agents` package (empty __init__) so real submodules import clean -
_agents_pkg = types.ModuleType("agents")
_agents_pkg.__path__ = [str(HUNTER / "agents")]
sys.modules["agents"] = _agents_pkg
_llmp = types.ModuleType("agents.llm_providers")
_llmp.build_failover_chain = lambda temperature=0.0: []   # no providers -> no LLM call
_llmp.get_embedder = lambda: types.SimpleNamespace(encode=lambda s: [0.0])
_llmp.circuit_is_callable = lambda n: True
_llmp.record_call_success = lambda n: None
_llmp.record_call_failure = lambda n: None
sys.modules["agents.llm_providers"] = _llmp

# -- stub tools.sanitizer (DLP scrub is identity for the wiring assertions) ----
_tools_pkg = types.ModuleType("tools")
_tools_pkg.__path__ = [str(HUNTER / "tools")]
sys.modules.setdefault("tools", _tools_pkg)
_san = types.ModuleType("tools.sanitizer")
_san.CognitiveSanitizer = type("CognitiveSanitizer", (), {
    "scrub_outbound_dlp": staticmethod(lambda s: s),
})
sys.modules["tools.sanitizer"] = _san

sys.path.insert(0, str(HUNTER))

import importlib  # noqa: E402

# Real modules under test (force clean import; capture refs).
for _m in ("agents.response", "agents.review_board", "agents.verdict_ledger",
           "agents.energy_accounting", "agents.active_learning"):
    sys.modules.pop(_m, None)
response_mod = importlib.import_module("agents.response")
rb_mod = importlib.import_module("agents.review_board")
verdict_ledger = importlib.import_module("agents.verdict_ledger")
energy_accounting = importlib.import_module("agents.energy_accounting")
active_learning = importlib.import_module("agents.active_learning")

RESPONSE = response_mod.response_agent
REVIEW_BOARD = rb_mod.review_board_node


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def ledgers(tmp_path, monkeypatch):
    """Redirect every per-run ledger to tmp_path via the env vars response.py
    reads at call time, so each test is isolated and nothing touches /var/lib."""
    paths = {
        "verdict": tmp_path / "verdict_lineage.jsonl",
        "energy": tmp_path / "energy.jsonl",
        "failure": tmp_path / "active_learning.jsonl",
    }
    monkeypatch.setenv("NEXUS_VERDICT_LEDGER", str(paths["verdict"]))
    monkeypatch.setenv("NEXUS_ENERGY_LEDGER", str(paths["energy"]))
    monkeypatch.setenv("NEXUS_FAILURE_CORPUS", str(paths["failure"]))
    return paths


def _state(verdict, grounding_violations=None, event_id="evt-1"):
    st = {
        "alert": {"event_id": event_id, "sensor_id": "host-7", "source_type": "sysmon_sensor"},
        "messages": [],
        "entities_of_interest": {},
        "verdict": verdict,
        "analysis_complete": True,
    }
    if grounding_violations is not None:
        st["grounding_violations"] = grounding_violations
    return st


# ---------------------------------------------------------------------------
# NC-10 -- verdict lineage is appended for EVERY run
# ---------------------------------------------------------------------------
def test_response_appends_verdict_to_lineage_ledger(ledgers):
    state = _state({"is_true_positive": True, "confidence": 0.9,
                    "recommended_action": "contain", "justification": "beaconing"})
    asyncio.run(RESPONSE(state))

    entries = verdict_ledger.load_ledger(str(ledgers["verdict"]))
    assert len(entries) == 1, "NC-10: response_agent did not append a verdict-lineage entry"
    assert entries[0]["record"]["event_id"] == "evt-1"
    assert entries[0]["record"]["is_true_positive"] is True
    assert verdict_ledger.verify_ledger(str(ledgers["verdict"]))["valid"] is True


def test_lineage_chains_across_consecutive_runs(ledgers):
    asyncio.run(RESPONSE(_state({"is_true_positive": False, "confidence": 0.2,
                                 "recommended_action": "dismiss", "justification": "benign"},
                                event_id="evt-A")))
    asyncio.run(RESPONSE(_state({"is_true_positive": True, "confidence": 0.8,
                                 "recommended_action": "monitor", "justification": "ok"},
                                event_id="evt-B")))
    entries = verdict_ledger.load_ledger(str(ledgers["verdict"]))
    assert len(entries) == 2
    # second entry binds the first -> tamper-evident chain across separate runs
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert verdict_ledger.verify_ledger(str(ledgers["verdict"]))["valid"] is True


# ---------------------------------------------------------------------------
# NC-11 -- per-run inference energy recorded for EVERY run
# ---------------------------------------------------------------------------
def test_response_records_inference_energy(ledgers):
    asyncio.run(RESPONSE(_state({"is_true_positive": False, "confidence": 0.1,
                                 "recommended_action": "dismiss", "justification": "x"})))
    recs = energy_accounting.load_ledger(str(ledgers["energy"]))
    assert len(recs) == 1, "NC-11: response_agent did not record per-run energy"
    r = recs[0]
    assert r["event_id"] == "evt-1"
    assert "energy_wh" in r and "co2e_g" in r and r["energy_wh"] >= 0.0


# ---------------------------------------------------------------------------
# NC-9 -- grounding violation captured as an active-learning hard example
# ---------------------------------------------------------------------------
def test_grounding_violation_is_captured_as_failure(ledgers):
    state = _state({"is_true_positive": False, "confidence": 0.0,
                    "recommended_action": "monitor", "justification": "demoted"},
                   grounding_violations=["203.0.113.5"])
    asyncio.run(RESPONSE(state))
    corpus = active_learning.load_corpus(str(ledgers["failure"]))
    assert len(corpus) == 1, "NC-9: grounding violation was not captured"
    assert corpus[0]["reason"] == "ungrounded_evidence"
    assert "203.0.113.5" in corpus[0]["artifacts"]


def test_no_failure_captured_for_grounded_verdict(ledgers):
    # No grounding_violations -> NC-9 stays silent, but NC-10/11 still fire.
    asyncio.run(RESPONSE(_state({"is_true_positive": True, "confidence": 0.95,
                                 "recommended_action": "contain", "justification": "clean"})))
    assert active_learning.load_corpus(str(ledgers["failure"])) == []
    assert len(verdict_ledger.load_ledger(str(ledgers["verdict"]))) == 1
    assert len(energy_accounting.load_ledger(str(ledgers["energy"]))) == 1


# ---------------------------------------------------------------------------
# review board surfaces grounding violations into state (the NC-9 feed)
# ---------------------------------------------------------------------------
def test_review_board_surfaces_grounding_violations(monkeypatch):
    # supervisor confirmed a TP citing an IP absent from the evidence corpus.
    verdict = {"is_true_positive": True, "confidence": 0.9,
               "recommended_action": "contain",
               "justification": "exfil to 198.51.100.9"}
    state = {"alert": {"event_id": "e", "raw_event": "nothing here", "sensor_id": "h"},
             "messages": [], "entities_of_interest": {}, "verdict": verdict}

    # implicated but unable to disprove -> the board CONFIRMS the TP, so the
    # grounding check actually runs (a non-implicated board fails closed earlier).
    async def _upheld(domain, st, v):
        return rb_mod.RebuttalSchema(domain=domain, implicated=True, disproved=False,
                                     confidence=0.0, failed_axis="", benign_alternative="",
                                     justification="could not disprove")
    monkeypatch.setattr(rb_mod, "_run_counterpart", _upheld)

    result = asyncio.run(REVIEW_BOARD(state))
    assert result["grounding_violations"] == ["198.51.100.9"]
    # and the verdict was demoted (fail-closed), proving the same signal both
    # blocks containment and feeds NC-9.
    assert result["verdict"]["is_true_positive"] is False


def test_review_board_clears_violations_for_grounded_verdict(monkeypatch):
    verdict = {"is_true_positive": True, "confidence": 0.9,
               "recommended_action": "contain", "justification": "exfil to 198.51.100.9"}
    state = {"alert": {"event_id": "e", "raw_event": "saw 198.51.100.9 beaconing", "sensor_id": "h"},
             "messages": [], "entities_of_interest": {}, "verdict": verdict}

    # implicated but unable to disprove -> the board CONFIRMS the TP, so the
    # grounding check actually runs (a non-implicated board fails closed earlier).
    async def _upheld(domain, st, v):
        return rb_mod.RebuttalSchema(domain=domain, implicated=True, disproved=False,
                                     confidence=0.0, failed_axis="", benign_alternative="",
                                     justification="could not disprove")
    monkeypatch.setattr(rb_mod, "_run_counterpart", _upheld)

    result = asyncio.run(REVIEW_BOARD(state))
    assert result["grounding_violations"] == []
    assert result["verdict"]["is_true_positive"] is True


# ---------------------------------------------------------------------------
# fail-soft: a ledger I/O error must NOT break the containment decision
# ---------------------------------------------------------------------------
def test_ledger_failure_does_not_block_response(ledgers, monkeypatch):
    def _boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(verdict_ledger, "append_verdict", _boom)

    state = _state({"is_true_positive": True, "confidence": 0.9,
                    "recommended_action": "contain", "justification": "beaconing"})
    out = asyncio.run(RESPONSE(state))  # must not raise
    assert out["action_payload"]["action_type"] == "isolate_host"
    # the other ledgers still recorded despite the verdict-ledger failure
    assert len(energy_accounting.load_ledger(str(ledgers["energy"]))) == 1
