"""
Standalone analysis entry — SIEM detection/query in, incident report + gated
containment course of action out. No Nexus telemetry alert involved.

Flow (plan §2): pivot (read-only + bounds + untrusted-wrap) -> entity
extraction -> seed synthesis -> adjudication -> report + the WS-I
ContainmentProtocol, with every query and verdict appended to the
tamper-evident verdict ledger.

Adjudication is a seam: `investigate=` accepts the real swarm entry (the seed
is UnifiedAlertSchema-shaped precisely so the existing graph can run it); the
default is a deterministic ladder whose confidence stays below the
corroboration threshold — so containment steps synthesized from a heuristic
verdict gate to operator approval instead of auto-executing. Fail-open: an
unavailable SIEM yields a "could not analyze" report, never a hang or a crash.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from siem_analysis.pivot import STATUS_OK, run_siem_pivot, unwrap_rows
from siem_analysis.entity_extractor import (extract_entities, hosts_in, mark_malicious,
                                            normalize_row)
from siem_analysis.seed import seed_anomaly_score, synthesize_seed
from siem_analysis.coverage import coverage_report, environment_profile

# A deterministic (non-swarm) verdict may never corroborate itself into
# autonomous containment; the swarm's own threshold is 0.80 (containment_protocol).
HEURISTIC_CONFIDENCE_CAP = 0.79


def build_attack_graph(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Grounded graph over the returned rows: every node is a literal row value,
    every edge a relationship the row itself asserts (spawn/connect/resolve/
    performed/modified/auth_from), tagged with the row's MITRE technique."""
    nodes, edges, techniques = set(), [], set()

    def _edge(src, dst, rel, mitre):
        edges.append({"src": src, "dst": dst, "rel": rel, "mitre": mitre})

    for raw in rows or []:
        r = normalize_row(raw)
        mitre = r.get("mitre", "")
        if mitre:
            techniques.add(mitre)
        for v in (r.get("host"), r.get("process"), r.get("parent_process"),
                  r.get("dest_ip"), r.get("src_ip"), r.get("dns_query"),
                  r.get("user"), r.get("cloud_instance"), r.get("event_action")):
            if v:
                nodes.add(v)
        if r.get("parent_process") and r.get("process"):
            _edge(r["parent_process"], r["process"], "spawned", mitre)
        if r.get("process") and r.get("dest_ip"):
            _edge(r["process"], r["dest_ip"], "connect", mitre)
        if r.get("process") and r.get("dns_query"):
            _edge(r["process"], r["dns_query"], "resolve", mitre)
        if r.get("user") and r.get("event_action"):
            _edge(r["user"], r["event_action"], "performed", mitre)
        if r.get("user") and r.get("cloud_instance"):
            _edge(r["user"], r["cloud_instance"], "modified", mitre)
        if r.get("src_ip") and r.get("user"):
            _edge(r["src_ip"], r["user"], "auth_from", mitre)
    return {"nodes": sorted(nodes), "edges": edges, "mitre": sorted(techniques)}


def default_adjudicator(request, seed: Dict[str, Any], entities: Dict[str, dict],
                        rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic verdict ladder for runs without the swarm.

    A detection hit with rows is a suspected true positive at the rows' own
    severity, hard-capped below the corroboration threshold: heuristic findings
    produce a full report and a containment plan, but the plan's steps gate to
    an operator. No rows -> benign/monitor.
    """
    if not rows:
        return {"is_true_positive": False, "confidence": 0.7,
                "recommended_action": "monitor",
                "justification": "Detection returned no matching rows in the window."}
    confidence = min(seed_anomaly_score(rows), HEURISTIC_CONFIDENCE_CAP)
    return {"is_true_positive": True, "confidence": confidence,
            "recommended_action": "contain",
            "justification": (f"Detection '{request.detection_name or request.detection_id or 'ad-hoc'}' "
                              f"matched {len(rows)} row(s); standalone heuristic verdict — "
                              f"swarm/operator corroboration required for autonomous action.")}


def _timeline(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(rows or [], key=lambda r: normalize_row(r).get("_time", ""))


def _audit(record: dict, ledger_path: Optional[str], append) -> None:
    if append is None:
        from agents.verdict_ledger import append_verdict as append  # noqa: PLW0127
    if ledger_path:
        append(record, ledger_path)
    else:
        append(record)


def run_standalone_analysis(request, siem_config: Optional[dict] = None,
                            transport=None, *,
                            investigate: Optional[Callable] = None,
                            caps: Optional[dict] = None,
                            ledger_path: Optional[str] = None,
                            ledger_append: Optional[Callable] = None,
                            now: float = 0.0) -> Dict[str, Any]:
    """One standalone SIEM analysis end to end. Returns the incident report dict.

    `investigate(request, seed, entities, rows) -> verdict` is the analysis
    seam (the swarm entry in production, the deterministic ladder by default).
    `caps`/`ledger_*` are injectable for offline proof.
    """
    from agents.containment_protocol import build_containment_protocol

    now = now or time.time()
    pivot = run_siem_pivot(request, siem_config=siem_config, transport=transport)
    _audit({"kind": "siem_standalone_query", "request_id": request.request_id,
            "backend": request.backend, "dialect": pivot.get("dialect", request.dialect),
            "bounded_query": pivot.get("bounded_query", ""), "status": pivot["status"],
            "entry_point": request.entry_point, "requested_by": request.requested_by,
            "ts": now}, ledger_path, ledger_append)

    report: Dict[str, Any] = {
        "incident_id": f"siem-{request.request_id}",
        "backend": request.backend,
        "detection": request.detection_name or request.detection_id or "ad-hoc query",
        "entry_point": request.entry_point,
        "pivot_status": pivot["status"],
        "queries_run": [pivot.get("bounded_query", "")] if pivot.get("bounded_query") else [],
    }

    if pivot["status"] != STATUS_OK:
        # fail-open: an honest "could not analyze", never a hang
        report.update({
            "analyzed": False,
            "summary": f"Analysis not performed: {pivot['status']} ({pivot['reason']})",
            "verdict": None, "timeline": [], "attack_graph": {"nodes": [], "edges": [], "mitre": []},
            "blast_radius": [], "mitre": [], "affected_hosts": [],
            "containment": {"incident_id": report["incident_id"], "steps": [],
                            "coverage": {}, "escalations": [pivot["reason"]],
                            "kill_chain_closed": False},
        })
        return report

    rows = unwrap_rows(pivot["rows"])
    entities = extract_entities(rows)
    seed = synthesize_seed(request, rows, pivot["bounded_query"], now=now)

    heuristic = investigate is None
    adjudicate = investigate or default_adjudicator
    verdict = adjudicate(request, seed, entities, rows)

    graph = build_attack_graph(rows)
    if verdict.get("is_true_positive"):
        entities = mark_malicious(
            entities, note=f"confirmed by {request.detection_name or 'standalone analysis'}")
        protocol = build_containment_protocol(
            {"event_id": seed["event_id"], "sensor_id": seed["sensor_id"],
             "source_type": seed["source_type"]},
            verdict, entities, caps=caps, now=now)
        if heuristic:
            # No swarm, no review board: a heuristic verdict may plan containment
            # but never auto-execute it — every step waits for an operator.
            for step in protocol["steps"]:
                step["gate"] = "operator_approval"
    else:
        protocol = {"incident_id": seed["event_id"], "generated_at": now, "steps": [],
                    "environment": "", "target_class": "", "coverage": {},
                    "escalations": [], "lateral_targets": [], "kill_chain_closed": False}

    hosts = hosts_in(rows)
    report.update({
        "analyzed": True,
        "heuristic_verdict": heuristic,
        "seed": seed,
        "verdict": verdict,
        "summary": (f"{report['detection']} on {request.backend}: "
                    f"{'suspected TRUE POSITIVE' if verdict.get('is_true_positive') else 'no attack signature'} "
                    f"({len(rows)} row(s), {len(entities)} entities, "
                    f"{len(protocol['steps'])} containment step(s), "
                    f"gates: {sorted({s['gate'] for s in protocol['steps']}) or 'none'})"),
        "timeline": _timeline(rows),
        "attack_graph": graph,
        "blast_radius": sorted(eid for eid, ed in entities.items()
                               if ed.get("status") == "malicious"),
        "mitre": graph["mitre"],
        "affected_hosts": hosts,
        "affected_assets": sorted({s["target"] for s in protocol["steps"]}),
        "containment": protocol,
        "evidence_wrapped": all(str(v).startswith("<untrusted_payload>")
                                for r in pivot["rows"] for v in r.values()),
    })

    if request.include_coverage_report:
        fields = {f for r in rows for f in r}
        report["coverage_report"] = coverage_report(request.backend, fields)
        report["environment_profile"] = environment_profile(rows)

    _audit({"kind": "siem_standalone_verdict", "request_id": request.request_id,
            "incident_id": report["incident_id"], "verdict": verdict,
            "blast_radius": report["blast_radius"],
            "containment_steps": len(protocol["steps"]),
            "kill_chain_closed": protocol["kill_chain_closed"], "ts": now},
           ledger_path, ledger_append)
    return report
