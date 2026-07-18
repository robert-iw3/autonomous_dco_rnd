"""
coverage_analyzer + environment_profile — the sensorless-value artifacts.

Beyond per-incident triage, standalone analysis reads an estate's SIEM data and
answers two environment-level questions:

  * Coverage/gap report — which Nexus data classes the SIEM's fields already
    satisfy, which are partial, and which are blind spots, with a prioritized
    sensor-deployment recommendation to close each gap. Table-driven and pure,
    so it is unit-tested deterministically.
  * Environment profile — a fast read of the estate from the returned rows:
    asset inventory (hosts, identities, cloud resources), egress surface,
    per-source volumes, and the observed time span. It gives the operator a
    quick understanding of the environment and seeds the swarm with grounding
    it would otherwise only learn from Nexus telemetry.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from siem_analysis.entity_extractor import _looks_like_ip, normalize_row

try:
    from agents.lateral_movement import is_internal_ip
except Exception:  # pragma: no cover — standalone import outside the agents pkg
    import ipaddress

    def is_internal_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

# Each Nexus data class is satisfied when the SIEM carries at least one full
# field GROUP for it (groups are alternatives: CIM, ECS, or flat shapes), and
# partial when some — but not all — fields of every group are present.
DATA_CLASS_GROUPS: Dict[str, List[frozenset]] = {
    "process_lineage": [frozenset({"process", "parent_process"}),
                        frozenset({"process.name", "process.parent.name"}),
                        frozenset({"process.command_line", "process.parent.command_line"})],
    "network_egress": [frozenset({"dest_ip"}), frozenset({"destination.ip"}),
                       frozenset({"dest", "dest_port"})],
    "dns_visibility": [frozenset({"dns_query"}), frozenset({"dns.question.name"})],
    "identity": [frozenset({"user"}), frozenset({"user.name"}), frozenset({"user.id"})],
    "cloud_api": [frozenset({"event_action", "cloud_instance"}),
                  frozenset({"event.action", "cloud.instance.id"}),
                  frozenset({"event_action", "src_ip"})],
    "file_integrity": [frozenset({"file_name"}), frozenset({"file.path"}),
                       frozenset({"file.name"})],
    "registry_visibility": [frozenset({"registry_path"}), frozenset({"registry.path"})],
    # network-tap territory: L7/session shape no log-forwarding SIEM source carries
    "l7_payload": [frozenset({"ssl_ja3", "http_uri"}),
                   frozenset({"tls.client.ja3", "url.original"}),
                   frozenset({"network.bytes", "tls.client.ja3"})],
}

# gap -> which sensor closes it (the deployment recommendation vocabulary)
GAP_SENSOR = {
    "process_lineage": "endpoint sensor (sysmon_sensor / linux_sentinel) — no process lineage",
    "network_egress": "network tap or endpoint sensor — no egress visibility",
    "dns_visibility": "network tap (DNS) — no DNS query visibility",
    "identity": "identity log source (Entra/AD/IAM) — no identity events",
    "cloud_api": "cloud audit source (CloudTrail/Activity/Audit) — no cloud API visibility",
    "file_integrity": "endpoint sensor — no file event visibility",
    "registry_visibility": "endpoint sensor (sysmon_sensor) — no registry visibility",
    "l7_payload": "network-tap sensor — no L7/JA3/session-shape visibility (SIEM logs cannot supply this)",
}

# Blind spots that most limit an investigation come first in the recommendation.
_GAP_PRIORITY = ("l7_payload", "process_lineage", "dns_visibility", "network_egress",
                 "identity", "cloud_api", "file_integrity", "registry_visibility")


def classify_fields(fields: Iterable[str]) -> Dict[str, str]:
    """Each Nexus data class -> satisfied | partial | gap for a SIEM field set."""
    have = {str(f) for f in fields or ()}
    out = {}
    for cls, groups in DATA_CLASS_GROUPS.items():
        if any(g <= have for g in groups):
            out[cls] = "satisfied"
        elif any(g & have for g in groups):
            out[cls] = "partial"
        else:
            out[cls] = "gap"
    return out


def coverage_report(siem_name: str, fields: Iterable[str]) -> Dict[str, Any]:
    """Coverage/gap report + prioritized sensor-deployment recommendation."""
    status = classify_fields(fields)
    gaps = sorted(c for c, s in status.items() if s == "gap")
    partial = sorted(c for c, s in status.items() if s == "partial")
    recommendations = [GAP_SENSOR[c] for c in _GAP_PRIORITY if c in gaps]
    return {
        "siem": siem_name,
        "satisfied": sorted(c for c, s in status.items() if s == "satisfied"),
        "partial": partial,
        "gaps": gaps,
        "sensor_recommendations": recommendations,
        "summary": (f"{siem_name}: {len(status) - len(gaps) - len(partial)}/{len(status)} "
                    f"Nexus data classes satisfied, {len(partial)} partial, "
                    f"{len(gaps)} blind spot(s)"),
    }


def environment_profile(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Asset/identity/egress read of the environment from returned rows."""
    hosts, users, processes, domains, instances = set(), set(), set(), set(), set()
    internal_ips, external_ips = set(), set()
    action_counts: Dict[str, int] = {}
    source_counts: Dict[str, int] = {}
    times = []
    for raw in rows or []:
        r = normalize_row(raw)
        if r.get("host"):
            hosts.add(r["host"])
        if r.get("user"):
            users.add(r["user"])
        if r.get("process"):
            processes.add(r["process"])
        if r.get("dns_query"):
            domains.add(r["dns_query"])
        if r.get("cloud_instance"):
            instances.add(r["cloud_instance"])
        for ip_role in ("src_ip", "dest_ip"):
            ip = r.get(ip_role, "")
            if not _looks_like_ip(ip):
                continue
            (internal_ips if is_internal_ip(ip) else external_ips).add(ip)
        if r.get("event_action"):
            action_counts[r["event_action"]] = action_counts.get(r["event_action"], 0) + 1
        src = str((raw or {}).get("index") or (raw or {}).get("sourcetype")
                  or (raw or {}).get("event.dataset") or "")
        if src:
            source_counts[src] = source_counts.get(src, 0) + 1
        if r.get("_time"):
            times.append(r["_time"])
    return {
        "hosts": sorted(hosts),
        "identities": sorted(users),
        "processes": sorted(processes),
        "domains": sorted(domains),
        "cloud_resources": sorted(instances),
        "egress_surface": {"internal_ips": sorted(internal_ips),
                           "external_ips": sorted(external_ips)},
        "action_volumes": dict(sorted(action_counts.items())),
        "source_volumes": dict(sorted(source_counts.items())),
        "window": {"first": min(times) if times else "", "last": max(times) if times else "",
                   "events": len(rows or [])},
    }
