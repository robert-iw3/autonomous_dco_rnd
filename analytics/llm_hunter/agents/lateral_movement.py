"""
Lateral-movement detection + IR fan-out planning.

A single host's enriched investigation is the *seed* of a campaign: given the
typed entities + the memory-forensics enrichment, the host_expert identifies the
**internal** hosts the compromised host talked to and plans a **bounded** fan-out —
open the same contain → collect → memory-analyze → eradicate IR workflow on each
peer, tagged with the parent incident for campaign correlation.

Pure / stdlib-only so the fan-out decision is unit-tested deterministically; the
host_expert / orchestrator does the IO (publishing the synthetic alerts). Bounds
(internal-only, de-dup, drop origin, hard cap) keep the fan-out from becoming a
mass action — the same blast-radius discipline as the rest of the response path.
"""
from __future__ import annotations

import ipaddress

# Hard cap on hosts a single investigation may fan out to (blast-radius control;
# mirrors MAX_SOAR_TARGETS). A campaign larger than this escalates to an operator.
MAX_FANOUT_HOSTS = 5


# Explicit RFC1918 / unique-local nets. We do NOT use ipaddress.is_private: on
# modern Python it also matches reserved/TEST-NET ranges (e.g. 203.0.113.0/24),
# which are not internal peers.
_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def is_internal_ip(value: str) -> bool:
    """True for an RFC1918 / unique-local address (a candidate internal peer).
    Public addresses are C2/egress, not lateral-movement peers; loopback,
    link-local and multicast are never peers."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    return any(ip in net for net in _INTERNAL_NETS)


def connected_internal_peers(entities: dict, origin_host: str = "",
                             exclude: set = None) -> list:
    """Internal IPs the compromised host connected to, drawn from the malicious /
    investigating `ip` entities the swarm pivoted on. Excludes the origin host and
    any explicit excludes (e.g. GLOBAL_DO_NOT_PIVOT infra). Order-preserving, deduped."""
    exclude = set(exclude or set())
    exclude.add(str(origin_host))
    peers = []
    for eid, edata in (entities or {}).items():
        edata = edata or {}
        if str(edata.get("type", "")).lower() != "ip":
            continue
        if str(edata.get("status", "")).lower() not in ("malicious", "investigating"):
            continue
        sid = str(eid)
        if sid in exclude or not is_internal_ip(sid):
            continue
        peers.append(sid)
    return list(dict.fromkeys(peers))


def plan_fanout(peers: list, max_hosts: int = MAX_FANOUT_HOSTS) -> dict:
    """Bound the fan-out: the hosts to open IR on now, plus any overflow that must
    be escalated to an operator rather than auto-actioned."""
    peers = list(dict.fromkeys(peers or []))
    cap = max(0, int(max_hosts))
    return {"fanout": peers[:cap], "overflow": peers[cap:],
            "escalate": len(peers) > cap}


def build_fanout_alerts(peers: list, parent_incident: str, source_type: str,
                        timestamp: float = 0.0) -> list:
    """Synthetic, UnifiedAlertSchema-shaped alerts that re-enter the pipeline to
    open an IR workflow per peer. Each carries `parent_incident` so the campaign
    correlator can stitch the hosts into one Campaign_Report."""
    alerts = []
    for host in dict.fromkeys(peers or []):
        alerts.append({
            "event_id": f"{parent_incident}-lm-{host}",
            "timestamp": float(timestamp or 0.0),
            "sensor_id": str(host),
            "source_type": source_type,
            "vector_name": "lateral_movement",
            "anomaly_score": 1.0,
            "raw_event": {"parent_incident": str(parent_incident),
                          "reason": "lateral-movement peer of a confirmed compromise"},
        })
    return alerts


def plan_lateral_response(entities: dict, origin_host: str, parent_incident: str,
                          source_type: str, *, memory_threat: bool,
                          exclude: set = None, timestamp: float = 0.0) -> dict:
    """Full host_expert fan-out decision. Only fans out once the memory ground
    truth confirms the compromise (`memory_threat`) — never on suspicion alone —
    and only to bounded internal peers. Returns the peers, the synthetic alerts to
    publish, and whether overflow must be escalated to an operator."""
    if not memory_threat:
        return {"peers": [], "alerts": [], "escalate": False, "overflow": []}
    peers = connected_internal_peers(entities, origin_host, exclude)
    plan = plan_fanout(peers)
    return {
        "peers": plan["fanout"],
        "alerts": build_fanout_alerts(plan["fanout"], parent_incident, source_type, timestamp),
        "overflow": plan["overflow"],
        "escalate": plan["escalate"],
    }
