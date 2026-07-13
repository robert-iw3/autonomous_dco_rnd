"""
Entity-driven containment protocol builder, the kill-chain coverage gate, and the
per-entity "beyond a shadow of doubt" assurance gate.

The builder turns the swarm's confirmed-TP entities into tailored, executable,
reversible per-target steps, or escalates the entity. Any target with no executable
action must surface as an escalation (kill chain not closed) rather than be
silently dropped.
"""
import importlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
AGENTS = ROOT / "analytics" / "llm_hunter" / "agents"
_pkg = types.ModuleType("agents")
_pkg.__path__ = [str(AGENTS)]
sys.modules.setdefault("agents", _pkg)

cp = importlib.import_module("agents.containment_protocol")

WIN = {"event_id": "e1", "sensor_id": "dc-prod-01", "source_type": "sysmon_sensor"}
AWS = {"event_id": "e2", "sensor_id": "i-0abc", "source_type": "aws_guardduty"}
TP = {"is_true_positive": True, "recommended_action": "contain", "confidence": 0.9}
WEAK = {"is_true_positive": True, "recommended_action": "contain", "confidence": 0.4}


def _acts(p, target=None):
    return [(s["action"], s["target"]) for s in p["steps"]
            if target is None or s["target"] == target]


class TestPrimaryHost:
    def test_endpoint_contain_and_collect_auto(self):
        p = cp.build_containment_protocol(WIN, TP, {})
        a = _acts(p)
        assert ("isolate_host", "dc-prod-01") in a and ("collect_forensics", "dc-prod-01") in a
        assert all(s["gate"] == "auto" for s in p["steps"])           # high confidence
        assert not any(s["action"].startswith("eradicate") for s in p["steps"])  # no memory yet

    def test_low_confidence_gates_disruptive_but_still_collects(self):
        # weak certainty -> the disruptive isolate needs an operator, but the
        # non-destructive evidence capture still runs autonomously.
        p = cp.build_containment_protocol(WIN, WEAK, {})
        iso = next(s for s in p["steps"] if s["action"] == "isolate_host")
        coll = next(s for s in p["steps"] if s["action"] == "collect_forensics")
        assert iso["gate"] == "operator_approval"
        assert coll["gate"] == "auto"

    def test_step_ordering_isolate_collect_then_eradicate(self):
        ent = {"666": {"type": "pid", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent, {"memory_threat": True})
        order = [a for a, _ in _acts(p, "dc-prod-01")]
        assert order.index("isolate_host") < order.index("collect_forensics") < order.index("eradicate_process")


class TestEradicationGate:
    def test_memory_confirmed_unlocks_eradication(self):
        ent = {"666": {"type": "pid", "status": "malicious"},
               "/tmp/x": {"type": "file", "status": "malicious", "notes": "/tmp/x"}}
        p = cp.build_containment_protocol(WIN, TP, ent, {"memory_threat": True})
        acts = {s["action"] for s in p["steps"]}
        assert {"eradicate_process", "eradicate_persistence"} <= acts
        ep = next(s for s in p["steps"] if s["action"] == "eradicate_process")
        assert ep["wave"] == 2 and ep["gate"] == "auto" and "666" in ep["params"]["pids"]

    def test_no_memory_no_eradication(self):
        ent = {"666": {"type": "pid", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent)  # no enrichment
        assert not any(s["action"].startswith("eradicate") for s in p["steps"])


class TestNetworkAndIdentity:
    def test_external_c2_ip_blocked(self):
        ent = {"203.0.113.9": {"type": "ip", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent)
        blk = [s for s in p["steps"] if s["action"] == "block_ip"]
        assert blk and blk[0]["target"] == "203.0.113.9" and blk[0]["target_class"] == "network"

    def test_malicious_domain_is_sinkholed(self):
        ent = {"evil.com": {"type": "domain", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent)
        sk = [s for s in p["steps"] if s["action"] == "dns_sinkhole"]
        assert sk and sk[0]["target"] == "evil.com" and sk[0]["target_class"] == "network"
        assert not any("evil.com" in e for e in p["escalations"])

    def test_compromised_user_is_disabled(self):
        ent = {"alice": {"type": "user", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent)
        da = [s for s in p["steps"] if s["action"] == "disable_user"]
        assert da and da[0]["target"] == "alice" and da[0]["target_class"] == "identity"
        assert da[0]["environment"] == "local"        # windows source -> on-prem AD


class TestCloud:
    def test_cloud_instance_isolated_via_provider(self):
        ent = {"10.0.0.7": {"type": "ip", "status": "malicious"}}
        p = cp.build_containment_protocol(AWS, TP, ent)
        iso = [s for s in p["steps"] if s["action"] == "isolate_host"]
        assert any(s["executor"] == "aws_containment_v1" for s in iso)
        assert any(s["target"] == "10.0.0.7" and s["target_class"] == "cloud_instance" for s in p["steps"])

    def test_cloud_instance_evidence_first_then_isolate_and_revoke_role(self):
        p = cp.build_containment_protocol(AWS, TP, {})
        order = [a for a, _ in _acts(p, "i-0abc")]
        assert {"snapshot_volume", "isolate_host", "revoke_instance_role"} <= set(order)
        assert order.index("snapshot_volume") < order.index("isolate_host")
        assert all(s["executor"] == "aws_containment_v1" for s in p["steps"] if s["target"] == "i-0abc")


class TestContainer:
    def test_container_quarantined_kill_held_for_confirmation(self):
        ent = {"pod-evil": {"type": "container", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent)
        steps = {s["action"]: s for s in p["steps"] if s["target"] == "pod-evil"}
        assert steps["quarantine_container"]["target_class"] == "container"
        assert steps["quarantine_container"]["gate"] == "auto"      # corroborated
        assert steps["kill_pod"]["gate"] == "operator_approval"     # confirmed floor, no memory yet

    def test_container_kill_unlocked_when_memory_confirms(self):
        ent = {"pod-evil": {"type": "container", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent, {"memory_threat": True})
        kp = next(s for s in p["steps"] if s["action"] == "kill_pod")
        assert kp["gate"] == "auto" and kp["wave"] == 2


class TestCoverage:
    def test_multi_class_kill_chain_closed(self):
        ent = {"203.0.113.9": {"type": "ip", "status": "malicious"},   # network block_ip
               "evil.com": {"type": "domain", "status": "malicious"},  # network dns_sinkhole
               "alice": {"type": "user", "status": "malicious"},       # identity disable_user
               "10.0.0.5": {"type": "ip", "status": "malicious"}}      # endpoint isolate
        p = cp.build_containment_protocol(WIN, TP, ent)
        cov = p["coverage"]
        assert cov["tp_entities"] == 4 and cov["uncovered"] == []
        assert p["escalations"] == [] and p["kill_chain_closed"] is True
        acts = {s["action"] for s in p["steps"]}
        assert {"block_ip", "dns_sinkhole", "disable_user", "isolate_host"} <= acts

    def test_lateral_peer_unified_and_operator_gated(self):
        # an internal peer the host reached (still under investigation) is contained
        # in the same protocol, but isolation needs an operator (not yet confirmed).
        ent = {"10.0.0.50": {"type": "ip", "status": "investigating"}}
        p = cp.build_containment_protocol(WIN, TP, ent)
        assert "10.0.0.50" in p["lateral_targets"]
        iso = next(s for s in p["steps"] if s["target"] == "10.0.0.50" and s["action"] == "isolate_host")
        assert iso["lateral"] is True and iso["gate"] == "operator_approval"

    def test_lateral_overflow_escalates(self):
        ent = {f"10.0.0.{i}": {"type": "ip", "status": "investigating"} for i in range(1, 9)}
        p = cp.build_containment_protocol(WIN, TP, ent)
        assert any("fan-out exceeds cap" in e for e in p["escalations"])
        assert p["kill_chain_closed"] is False

    def test_uncovered_target_escalates_not_dropped(self):
        # vmware has no containment provider, so its targets cannot be auto-contained.
        vmware = {"event_id": "e3", "sensor_id": "vm-1", "source_type": "vmware_syslog"}
        ent = {"10.0.0.9": {"type": "ip", "status": "malicious"}}
        p = cp.build_containment_protocol(vmware, TP, ent)
        assert p["escalations"] and p["kill_chain_closed"] is False


class TestRollback:
    def test_rollback_reverses_reversible_steps(self):
        ent = {"203.0.113.9": {"type": "ip", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent)
        rb = cp.build_rollback_protocol(p)
        acts = {s["action"] for s in rb["steps"]}
        assert "unblock_ip" in acts          # reverses the network block_ip
        assert "restore" in acts             # reverses the host isolate_host
        assert all(s["gate"] == "auto" for s in rb["steps"])   # de-escalation is safe
        assert rb["reverses"] == len(rb["steps"])

    def test_rollback_skips_irreversible(self):
        # collect_forensics has no reversible_by, so it produces no rollback step
        ent = {"666": {"type": "pid", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent, {"memory_threat": True})
        rb = cp.build_rollback_protocol(p)
        assert "collect_forensics" not in {s["action"] for s in rb["steps"]}
        assert "eradicate_process" not in {s["action"] for s in rb["steps"]}


class TestGovernance:
    def test_steps_carry_idempotency_keys(self):
        ent = {"203.0.113.9": {"type": "ip", "status": "malicious"}}
        p = cp.build_containment_protocol(WIN, TP, ent)
        blk = next(s for s in p["steps"] if s["action"] == "block_ip")
        assert blk["idempotency_key"] == "e1:203.0.113.9:block_ip"
        # every step is keyed
        assert all(s["idempotency_key"] for s in p["steps"])
