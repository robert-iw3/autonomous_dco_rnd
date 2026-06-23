"""
Response-agent → playbook initiation (llm_hunter).

Runs the REAL `response_agent` end to end (network/LLM seams stubbed) and proves
it turns the swarm's typed entities into the on-host playbook plan in the SOAR
payload: os_family, the ordered response_actions, and the typed IOC params the
playbooks consume. Also proves the HitL circuit breaker clears autonomous
playbooks on a TIER-1 asset, and that cloud targets initiate no host playbook.

Same stub style as test_nist_controls_wiring.py.
"""
import asyncio
import sys
import types
from pathlib import Path

import pytest

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"


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

_qc = types.ModuleType("qdrant_client")
_qc.AsyncQdrantClient = type("AsyncQdrantClient", (), {"__init__": lambda self, *a, **k: None})
_qcm = types.ModuleType("qdrant_client.models")
_qcm.PointStruct = type("PointStruct", (), {"__init__": lambda self, *a, **k: None})
sys.modules.setdefault("qdrant_client", _qc)
sys.modules.setdefault("qdrant_client.models", _qcm)

_redis = types.ModuleType("redis")
_redis_aio = types.ModuleType("redis.asyncio")
_redis_aio.Redis = type("Redis", (), {"from_url": staticmethod(lambda *a, **k: object())})
_redis.asyncio = _redis_aio
sys.modules.setdefault("redis", _redis)
sys.modules.setdefault("redis.asyncio", _redis_aio)

_agents_pkg = types.ModuleType("agents")
_agents_pkg.__path__ = [str(HUNTER / "agents")]
sys.modules["agents"] = _agents_pkg
_llmp = types.ModuleType("agents.llm_providers")
_llmp.build_failover_chain = lambda temperature=0.0: []
_llmp.get_embedder = lambda: types.SimpleNamespace(encode=lambda s: [0.0])
_llmp.circuit_is_callable = lambda n: True
_llmp.record_call_success = lambda n: None
_llmp.record_call_failure = lambda n: None
sys.modules["agents.llm_providers"] = _llmp

# tools/sanitizer.py is stdlib-only — load the REAL module (do NOT stub it, or we
# replace the sanitizer that sibling tests in this section, e.g. test_siem_query,
# depend on). Expose the `tools` package by path; the real submodule then imports.
sys.modules.setdefault("tools", types.ModuleType("tools"))
sys.modules["tools"].__path__ = [str(HUNTER / "tools")]

sys.path.insert(0, str(HUNTER))

import importlib  # noqa: E402
for _m in ("agents.response", "agents.playbook_planner"):
    sys.modules.pop(_m, None)
response_mod = importlib.import_module("agents.response")
RESPONSE = response_mod.response_agent


def _ent(etype, status="malicious", notes=""):
    return {"type": etype, "status": status, "notes": notes}


def _tp_state(source_type="sysmon_sensor", sensor_id="ws-finance-042", entities=None):
    return {
        "alert": {"event_id": "evt-pb", "sensor_id": sensor_id, "source_type": source_type,
                  "timestamp": 1_700_000_000.0},
        "messages": [],
        "entities_of_interest": entities or {},
        "verdict": {"is_true_positive": True, "confidence": 0.95,
                    "recommended_action": "contain", "justification": "confirmed C2 + payload"},
        "analysis_complete": True,
    }


def _entities4():
    return {
        "10.0.0.9": _ent("ip"),
        "evil.test": _ent("domain"),
        "4242": _ent("pid"),
        "deadbeef" + "0" * 56: _ent("hash"),
    }


def test_first_pass_is_contain_and_collect_only():
    # evidence-first: the first response wave contains + captures RAM; eradication
    # is held for the memory-enriched re-entry.
    out = asyncio.run(RESPONSE(_tp_state(entities=_entities4())))
    p = out["action_payload"]
    assert p["action_type"] == "isolate_host"            # primary unchanged
    assert p["os_family"] == "windows"                   # sysmon → windows
    assert p["response_actions"] == ["isolate_host", "collect_forensics"]
    # typed IOCs are still carried so wave 2 (and the cloud/audit path) have them
    assert p["c2_ips"] == ["10.0.0.9"]
    assert p["c2_domains"] == ["evil.test"]
    assert p["pids"] == ["4242"]
    assert p["hashes"] == ["deadbeef" + "0" * 56]


def test_memory_enriched_reentry_runs_eradication():
    # worker_memory returned an enrichment confirming a memory threat → wave 2
    state = _tp_state(entities=_entities4())
    state["memory_enrichment"] = {"source": "memory_forensics", "memory_threat": True}
    p = asyncio.run(RESPONSE(state))["action_payload"]
    assert p["response_actions"] == ["block_ip", "eradicate_process", "eradicate_persistence"]


def test_memory_cleared_runs_no_eradication():
    state = _tp_state(entities=_entities4())
    state["memory_enrichment"] = {"source": "memory_forensics", "memory_threat": False}
    p = asyncio.run(RESPONSE(state))["action_payload"]
    assert p["response_actions"] == []      # memory analysis cleared it → eradicate nothing


def test_linux_minimal_contain():
    state = _tp_state(source_type="linux_sentinel", sensor_id="ws-finance-042", entities={})
    p = asyncio.run(RESPONSE(state))["action_payload"]
    assert p["os_family"] == "linux"
    # no typed IOCs → still isolate + capture evidence
    assert p["response_actions"] == ["isolate_host", "collect_forensics"]


def test_tier1_asset_demote_clears_autonomous_playbooks():
    # dc-prod-01 is a TIER-1 critical asset (AssetValue=1.0) → HitL circuit breaker
    state = _tp_state(sensor_id="dc-prod-01", entities={"4242": _ent("pid")})
    p = asyncio.run(RESPONSE(state))["action_payload"]
    assert p["action_type"] == "manual_review_required"
    assert p["response_actions"] == []          # never auto-act on crown jewels
    # IOCs are still recorded for the operator / audit
    assert p["pids"] == ["4242"]


def test_cloud_target_initiates_no_host_playbook():
    state = _tp_state(source_type="aws_cloudtrail", sensor_id="ws-finance-042",
                      entities={"10.0.0.9": _ent("ip")})
    p = asyncio.run(RESPONSE(state))["action_payload"]
    assert p["os_family"] is None
    assert p["response_actions"] == []
    assert p["c2_ips"] == ["10.0.0.9"]          # still surfaced for the cloud path


def test_payload_validates_against_soar_schema():
    # the enriched payload must satisfy the strict dispatch contract
    from state import SoarExecutionSchema
    state = _tp_state(entities={"4242": _ent("pid"), "10.0.0.9": _ent("ip")})
    p = asyncio.run(RESPONSE(state))["action_payload"]
    s = SoarExecutionSchema(
        incident_id=p["incident_id"], action_type=p["action_type"],
        target_sensor=p["target_sensor"], targets=p["targets"],
        confidence=p["confidence"], reason=p["reason"],
        os_family=p["os_family"], response_actions=p["response_actions"],
        c2_ips=p["c2_ips"], c2_domains=p["c2_domains"], pids=p["pids"],
        hashes=p["hashes"], file_paths=p["file_paths"], users=p["users"],
    )
    assert s.response_actions == p["response_actions"]
