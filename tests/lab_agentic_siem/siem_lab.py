"""
Agentic SIEM analysis - refinement sandbox.

Multiple mock SIEMs hold predefined datasets that mix benign activity with an embedded
attack chain. A detection runs (read-only) against a SIEM, results come back, and the
analysis engine walks the swarm-style phases (triage -> entity extraction -> correlation /
attack graph -> verdict -> response) to produce a definitive incident report + a
contain/eradicate course of action (reusing the real tailored-containment protocol) +
a data-collection gap report. Deterministic so the logic can be refined fast before it is
promoted into the live stack.

Benign events are present and used for context (the timeline) but must never be flagged or
contained; every reported entity must trace to a real SIEM row (grounding).
"""
from __future__ import annotations

import importlib
import importlib.util
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
AGENTS = ROOT / "analytics" / "llm_hunter" / "agents"
HUNTER = ROOT / "analytics" / "llm_hunter"

# Reuse the real tailored-containment protocol (WS-I) via a lightweight agents pkg.
_pkg = types.ModuleType("agents")
_pkg.__path__ = [str(AGENTS)]
sys.modules.setdefault("agents", _pkg)
_cp = importlib.import_module("agents.containment_protocol")
build_containment_protocol = _cp.build_containment_protocol

# Reuse the real prompt-injection neutralizer (SIEM rows are untrusted evidence).
_spec = importlib.util.spec_from_file_location("sanitizer", str(HUNTER / "tools" / "sanitizer.py"))
_san = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_san)
wrap_untrusted = _san.CognitiveSanitizer.wrap_untrusted

# product (from the detection logsource) -> a source_type the containment resolver knows,
# so a SIEM finding maps to the right target class/environment.
_PRODUCT_SOURCE = {"linux": "linux_sentinel", "windows": "sysmon_sensor", "aws": "aws_guardduty"}

# Queries that would mutate the SIEM or run code -- rejected (mirrors siem_query.validate_readonly).
_MUTATING = re.compile(r"\b(delete|collect|outputlookup|sendemail|eval\s+\w+\s*=\s*exec|into\s+|os\.|run|drop|update|insert)\b", re.I)


def validate_readonly(query: str) -> bool:
    return not _MUTATING.search(query or "")


# ---------------------------------------------------------------------------
# Mock SIEM: a queryable store of events. `run` validates read-only, records the
# query, and returns the rows a structured matcher selects (benign rows stay put).
# ---------------------------------------------------------------------------
class MockSiem:
    def __init__(self, name, dialect, product, events, fields):
        self.name = name
        self.dialect = dialect
        self.product = product
        self.events = events
        self.fields = set(fields)          # the fields/columns this SIEM actually carries
        self.queries: list[str] = []

    def run(self, raw_query: str, matcher) -> list[dict]:
        if not validate_readonly(raw_query):
            raise PermissionError(f"refused non-read-only query: {raw_query!r}")
        self.queries.append(raw_query)
        return [e for e in self.events if matcher(e)]

    def host_context(self, host: str) -> list[dict]:
        # broad read-only context pull for the timeline (benign + malicious for the host)
        return self.run(f"search host={host} | sort _time", lambda e: e.get("host") == host)


def _ev(t, **kw):
    kw["_time"] = t
    return kw


# ---- SIEM 1: Splunk (CIM) - Linux web-server compromise -----------------------
_SPLUNK = MockSiem(
    "splunk-prod", "spl", "linux",
    fields=["_time", "host", "user", "process", "parent_process", "dest_ip", "dns_query", "action", "index"],
    events=[
        _ev("10:00", host="web-01", user="root", process="cron", parent_process="systemd", action="exec", index="nexus_endpoint"),
        _ev("10:01", host="web-01", user="www-data", process="nginx", parent_process="systemd", action="exec", index="nexus_endpoint"),
        _ev("10:30", host="db-02", user="svc_app", process="sshd", parent_process="systemd", action="login", index="nexus_endpoint"),
        # attack chain (T1190 -> T1505.003 -> T1059 -> C2 -> T1021)
        _ev("11:05", host="web-01", user="www-data", process="bash", parent_process="nginx", action="exec", index="nexus_endpoint", _malicious=True, mitre="T1505.003"),
        _ev("11:05", host="web-01", user="www-data", process="whoami", parent_process="bash", action="exec", index="nexus_endpoint", _malicious=True, mitre="T1059"),
        _ev("11:06", host="web-01", user="www-data", process="curl", parent_process="bash", dest_ip="203.0.113.66", dns_query="evil-c2.example", action="connect", index="nexus_endpoint", _malicious=True, mitre="T1071"),
        _ev("11:08", host="web-01", user="www-data", process="ssh", parent_process="bash", dest_ip="10.0.0.12", action="connect", index="nexus_endpoint", _malicious=True, mitre="T1021"),
    ],
)

# ---- SIEM 2: Elastic (ECS) - AWS identity / cloud abuse -----------------------
_ELASTIC = MockSiem(
    "elastic-cloud", "esql", "aws",
    fields=["_time", "host", "user", "src_ip", "cloud_instance", "event_action", "index"],
    events=[
        _ev("09:00", user="alice", src_ip="10.0.0.20", event_action="ConsoleLogin", index="nexus_cloud"),
        _ev("09:15", user="svc_ci", src_ip="10.0.0.21", event_action="AssumeRole", index="nexus_cloud"),
        # attack: anomalous IAM + ssh key push to a VM (T1098, T1078)
        _ev("12:00", user="svc_deploy", src_ip="203.0.113.99", event_action="CreateAccessKey", index="nexus_cloud", _malicious=True, mitre="T1098"),
        _ev("12:01", user="svc_deploy", src_ip="203.0.113.99", cloud_instance="i-0bad1", event_action="ModifyInstanceAttribute", index="nexus_cloud", _malicious=True, mitre="T1078.004"),
    ],
)

# ---- SIEM 3: Sentinel (KQL) - Windows encoded-PowerShell via mshta ------------
_SENTINEL = MockSiem(
    "sentinel-corp", "kql", "windows",
    fields=["_time", "host", "user", "process", "parent_process", "dest_ip", "action", "index"],
    events=[
        _ev("08:00", host="ws-finance-07", user="jdoe", process="outlook.exe", parent_process="explorer.exe", action="exec", index="nexus_endpoint"),
        _ev("13:20", host="ws-finance-07", user="jdoe", process="powershell.exe", parent_process="mshta.exe", action="exec", index="nexus_endpoint", _malicious=True, mitre="T1059.001"),
        _ev("13:21", host="ws-finance-07", user="jdoe", process="powershell.exe", parent_process="mshta.exe", dest_ip="203.0.113.50", action="connect", index="nexus_endpoint", _malicious=True, mitre="T1071"),
    ],
)

SIEMS = {"splunk-prod": _SPLUNK, "elastic-cloud": _ELASTIC, "sentinel-corp": _SENTINEL}


# ---------------------------------------------------------------------------
# Analysis engine - the swarm-style phases, deterministic for the sandbox.
# ---------------------------------------------------------------------------
def _entity_type(field: str) -> str:
    # NB: `host` is the incident epicenter (the alert sensor_id), contained as the
    # primary host -- not a standalone entity here.
    return {"dest_ip": "ip", "src_ip": "ip", "user": "user",
            "dns_query": "domain", "cloud_instance": "instance"}.get(field, "")


def extract_entities(rows: list[dict]) -> dict:
    """Typed entities from malicious rows only (grounding: every entity is from a row)."""
    ents: dict = {}
    for r in rows:
        if not r.get("_malicious"):
            continue
        for f in ("dest_ip", "src_ip", "user", "dns_query", "cloud_instance"):
            v = r.get(f)
            if not v:
                continue
            etype = _entity_type(f)
            ents.setdefault(str(v), {"type": etype, "status": "malicious",
                                     "notes": f"{r.get('mitre','')} via {r.get('process','')}".strip()})
    return ents


def build_attack_graph(rows: list[dict]) -> dict:
    nodes, edges, tactics = set(), [], set()
    for r in rows:
        if not r.get("_malicious"):
            continue
        host, proc, parent = r.get("host"), r.get("process"), r.get("parent_process")
        if r.get("mitre"):
            tactics.add(r["mitre"])
        for n in (host, proc, parent, r.get("dest_ip"), r.get("dns_query"), r.get("user"),
                  r.get("cloud_instance"), r.get("src_ip"), r.get("event_action")):
            if n:
                nodes.add(str(n))
        if parent and proc:
            edges.append({"src": str(parent), "dst": str(proc), "rel": "spawned", "mitre": r.get("mitre", "")})
        if proc and r.get("dest_ip"):
            edges.append({"src": str(proc), "dst": str(r["dest_ip"]), "rel": "connect", "mitre": r.get("mitre", "")})
        if proc and r.get("dns_query"):
            edges.append({"src": str(proc), "dst": str(r["dns_query"]), "rel": "resolve", "mitre": r.get("mitre", "")})
        # identity / cloud-API events (no process tree): user -> action / resource / src
        user, act = r.get("user"), r.get("event_action")
        if user and act:
            edges.append({"src": str(user), "dst": str(act), "rel": "performed", "mitre": r.get("mitre", "")})
        if user and r.get("cloud_instance"):
            edges.append({"src": str(user), "dst": str(r["cloud_instance"]), "rel": "modified", "mitre": r.get("mitre", "")})
        if user and r.get("src_ip"):
            edges.append({"src": str(r["src_ip"]), "dst": str(user), "rel": "auth_from", "mitre": r.get("mitre", "")})
    return {"nodes": sorted(nodes), "edges": edges, "mitre": sorted(tactics)}


def adjudicate(hit_rows: list[dict]) -> dict:
    """Verdict ladder: a confirmed-malicious signature in the hits is a TP."""
    mal = [r for r in hit_rows if r.get("_malicious")]
    if mal:
        return {"is_true_positive": True, "recommended_action": "contain",
                "confidence": 0.9, "justification": "Confirmed attack-chain signature in SIEM results."}
    return {"is_true_positive": False, "recommended_action": "monitor",
            "confidence": 0.7, "justification": "Only benign activity matched; no attack signature."}


def analyze(siem: MockSiem, detection: dict) -> dict:
    """Full standalone SIEM analysis -> definitive incident report + course of action."""
    hits = siem.run(detection["raw_query"], detection["matcher"])
    _evidence = wrap_untrusted(str(hits))                  # rows are untrusted evidence
    entities = extract_entities(hits)
    graph = build_attack_graph(hits)
    verdict = adjudicate(hits)

    # timeline uses benign context too (proves benign data informs analysis, isn't flagged)
    affected_hosts = sorted({r["host"] for r in hits if r.get("_malicious") and r.get("host")})
    if affected_hosts:
        timeline = sorted((e for h in affected_hosts for e in siem.host_context(h)), key=lambda e: e["_time"])
    else:
        timeline = sorted(hits, key=lambda e: e["_time"])   # cloud/identity incident (no host)

    primary = affected_hosts[0] if affected_hosts else ""
    alert = {"event_id": f"siem-{detection['id']}", "sensor_id": primary,
             "source_type": _PRODUCT_SOURCE.get(detection["product"], "")}
    protocol = build_containment_protocol(alert, verdict, entities)
    affected_assets = sorted({s["target"] for s in protocol["steps"]})

    return {
        "incident_id": alert["event_id"],
        "siem": siem.name,
        "detection": detection["name"],
        "verdict": verdict,
        "summary": (f"{detection['name']} on {siem.name}: "
                    f"{'CONFIRMED true positive' if verdict['is_true_positive'] else 'benign / no attack signature'}; "
                    f"{len(entities)} malicious entities, {len(timeline)} events in context."),
        "timeline": timeline,
        "attack_graph": graph,
        "blast_radius": sorted(entities),
        "mitre": graph["mitre"],
        "affected_hosts": affected_hosts,
        "affected_assets": affected_assets,
        "containment": protocol,
        "evidence_wrapped": _evidence.startswith("<untrusted_payload>"),
        "queries_run": list(siem.queries),
    }


def coverage_report(siem: MockSiem) -> dict:
    """Map the SIEM's available fields onto the data classes Nexus expects; flag gaps and
    recommend sensors to close them (sensorless value: prove collection gaps)."""
    have = siem.fields
    need = {
        "process_lineage": {"process", "parent_process"},
        "network_egress": {"dest_ip"},
        "dns_visibility": {"dns_query"},
        "identity": {"user"},
        "l7_payload": {"tls_ja3", "http_uri", "byte_ratio"},   # network-tap territory
    }
    gaps, satisfied = [], []
    for cls, fields in need.items():
        (satisfied if fields & have else gaps).append(cls)
    rec = []
    if "l7_payload" in gaps or "dns_visibility" in gaps:
        rec.append("deploy network-tap sensor (no L7/DNS visibility in this SIEM)")
    if "process_lineage" in gaps:
        rec.append("deploy endpoint sensor (no process lineage)")
    return {"siem": siem.name, "satisfied": sorted(satisfied), "gaps": sorted(gaps),
            "sensor_recommendations": rec}
