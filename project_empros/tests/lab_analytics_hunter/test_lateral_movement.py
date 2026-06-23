"""
Lateral-movement detection + bounded IR fan-out (llm_hunter).

Proves the host_expert turns a confirmed compromise into a bounded campaign: only
internal peers, only once memory confirms the threat, deduped, origin/infra
excluded, hard-capped (overflow escalates to an operator), with synthetic alerts
that carry the parent incident for campaign correlation. Pure (stdlib only).
"""
import sys
from pathlib import Path

HUNTER = Path(__file__).parent.parent.parent / "analytics/llm_hunter"
sys.path.insert(0, str(HUNTER / "agents"))

import lateral_movement as lm  # noqa: E402


def _ent(etype, status="malicious"):
    return {"type": etype, "status": status, "notes": ""}


class TestIsInternalIp:
    def test_rfc1918_internal(self):
        for ip in ("10.0.0.9", "172.16.5.4", "192.168.1.20"):
            assert lm.is_internal_ip(ip) is True

    def test_public_loopback_garbage_not_internal(self):
        for ip in ("8.8.8.8", "203.0.113.9", "127.0.0.1", "169.254.1.1", "not-an-ip", ""):
            assert lm.is_internal_ip(ip) is False


class TestConnectedPeers:
    def test_only_internal_malicious_ip_entities(self):
        entities = {
            "10.0.0.21": _ent("ip"),                       # internal peer ✓
            "192.168.1.50": _ent("ip", status="investigating"),  # internal peer ✓
            "8.8.8.8": _ent("ip"),                         # external C2 ✗
            "10.0.0.99": _ent("ip", status="cleared"),     # not malicious ✗
            "4242": _ent("pid"),                           # not an ip ✗
            "10.0.0.5": _ent("ip"),                        # == origin ✗
        }
        peers = lm.connected_internal_peers(entities, origin_host="10.0.0.5")
        assert peers == ["10.0.0.21", "192.168.1.50"]

    def test_exclude_infra(self):
        entities = {"10.0.0.21": _ent("ip"), "10.0.0.1": _ent("ip")}
        peers = lm.connected_internal_peers(entities, origin_host="h", exclude={"10.0.0.1"})
        assert peers == ["10.0.0.21"]


class TestFanoutBounds:
    def test_cap_and_overflow_escalates(self):
        peers = [f"10.0.0.{i}" for i in range(1, 9)]   # 8 peers
        plan = lm.plan_fanout(peers, max_hosts=5)
        assert plan["fanout"] == peers[:5]
        assert plan["overflow"] == peers[5:]
        assert plan["escalate"] is True

    def test_within_cap_no_escalation(self):
        plan = lm.plan_fanout(["10.0.0.1", "10.0.0.2"], max_hosts=5)
        assert plan["escalate"] is False and plan["overflow"] == []


class TestFanoutAlerts:
    def test_alerts_carry_parent_incident_and_shape(self):
        alerts = lm.build_fanout_alerts(["10.0.0.21"], "INC-7", "linux_sentinel", timestamp=123.0)
        a = alerts[0]
        assert a["sensor_id"] == "10.0.0.21"
        assert a["source_type"] == "linux_sentinel"
        assert a["vector_name"] == "lateral_movement"
        assert a["raw_event"]["parent_incident"] == "INC-7"
        assert a["event_id"] == "INC-7-lm-10.0.0.21"


class TestPlanLateralResponse:
    def _entities(self):
        return {"10.0.0.21": _ent("ip"), "10.0.0.22": _ent("ip"), "8.8.8.8": _ent("ip")}

    def test_no_fanout_without_memory_confirmation(self):
        out = lm.plan_lateral_response(self._entities(), "10.0.0.5", "INC-1", "linux_sentinel",
                                       memory_threat=False)
        assert out["peers"] == [] and out["alerts"] == []

    def test_fanout_after_memory_confirms(self):
        out = lm.plan_lateral_response(self._entities(), "10.0.0.5", "INC-1", "linux_sentinel",
                                       memory_threat=True)
        assert out["peers"] == ["10.0.0.21", "10.0.0.22"]     # external 8.8.8.8 excluded
        assert len(out["alerts"]) == 2
        assert out["escalate"] is False
