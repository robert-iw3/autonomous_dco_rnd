"""
Tailored containment protocol builder.

Turns the swarm's confirmed-TP entities into a per-target, per-entity containment
protocol that closes the kill chain across target classes (endpoint, cloud
instance, network, identity, ...). Pure / stdlib-only (reads the capability matrix
toml) so it is unit-tested deterministically; the response agent does the IO.

For each malicious entity: classify into (target_class, environment), pick the
tailored actions that are executable for that pair from the capability contract,
gated per-entity by certainty. Any entity with no executable action is surfaced in
escalations (the kill chain is then not marked closed), never silently dropped.
"""
from __future__ import annotations

import re

from agents.playbook_planner import extract_iocs
from agents.target_class import source_environment, classify_entity
from agents.lateral_movement import connected_internal_peers, plan_fanout
from agents.containment_capability import (load_capabilities, capability, actions_for,
                                           is_executable, meets_floor)

# Verdict confidence at or above which the swarm's own judgment corroborates an
# entity (lets reversible wave-1 containment run autonomously); mirrors the FP gate.
CORROBORATION_CONFIDENCE = 0.80
_TI_TOKENS = ("threat intel", "threat-intel", "ti hit", "known-bad", "known bad",
              "abuse", "blocklist", "ioc match")
_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Deterministic intra-protocol ordering: contain spread, capture volatile evidence
# (host stays up), block egress, then eradicate (held for wave 2 / certainty).
_ACTION_ORDER = {
    "snapshot_volume": 0, "isolate_host": 1, "collect_forensics": 2, "cordon_node": 1,
    "block_ip": 3, "dns_sinkhole": 3, "block_url": 3, "revoke_instance_role": 2,
    "disable_user": 4, "revoke_sessions": 4, "revoke_oauth": 4, "credential_reset": 4,
    "quarantine_container": 4, "kill_pod": 5,
    "eradicate_process": 6, "eradicate_persistence": 7,
    "restore": 9, "release_host": 9, "unblock_ip": 9, "uncordon_node": 9,
}


def desired_actions(target_class: str, entity_type: str) -> list:
    """What a target class wants contained, independent of what is wired; the
    capability contract then decides which are executable."""
    if target_class == "cloud_instance":
        return ["isolate_host"]
    if target_class == "network":
        return ["dns_sinkhole"] if entity_type in ("domain", "url") else ["block_ip"]
    if target_class == "identity":
        return ["disable_user", "revoke_sessions"]
    if target_class == "container":
        return ["quarantine_container", "kill_pod"]
    if target_class == "datastore":
        return ["revoke_bucket_policy"]
    if target_class == "saas":
        return ["revoke_sessions"]
    return []


def _host_class(source_env: str):
    if source_env in ("windows", "linux"):
        return "endpoint", source_env
    if source_env in ("aws", "azure", "gcp"):
        return "cloud_instance", source_env
    return None, source_env


def entity_certainty(entity_data: dict, memory_confirmed: bool, confidence: float):
    """(level, score). confirmed = memory/detonation ground truth; corroborated =
    the swarm's high-confidence verdict or a TI hit; else malicious-status only."""
    if memory_confirmed:
        return "confirmed", max(0.9, confidence)
    notes = str((entity_data or {}).get("notes", "")).lower()
    if confidence >= CORROBORATION_CONFIDENCE or any(t in notes for t in _TI_TOKENS):
        return "corroborated", max(confidence, 0.8)
    return "malicious", (confidence or 0.5)


def _step(target, tc, env, action, entry, level, score, stage, params):
    gate = "auto" if meets_floor(level, entry["certainty_floor"]) else "operator_approval"
    return {
        "target": target, "target_class": tc, "environment": env, "action": action,
        "executor": entry["executor"], "params": params or {},
        "kill_chain_stage": stage, "wave": entry["wave"], "certainty": round(score, 3),
        "certainty_level": level, "reversible_by": entry.get("reversible_by", ""),
        "gate": gate, "lateral": False, "idempotency_key": "",
    }


def _host_steps(host, tc, env, caps, iocs, memory_confirmed, confidence):
    """Contain and collect the host epicenter; eradicate only once memory-confirmed."""
    level, score = entity_certainty({}, memory_confirmed, confidence)
    out = []
    for action in actions_for(caps, tc, env):
        if action in ("isolate_host", "collect_forensics", "snapshot_volume",
                      "revoke_instance_role"):
            params = {}
        elif action == "eradicate_process":
            if not (memory_confirmed and iocs.get("pids")):
                continue
            params = {"pids": iocs["pids"], "processes": iocs.get("processes", []),
                      "hashes": iocs.get("hashes", [])}
        elif action == "eradicate_persistence":
            if not (memory_confirmed and (iocs.get("file_paths") or iocs.get("hashes"))):
                continue
            params = {"file_paths": iocs.get("file_paths", []), "hashes": iocs.get("hashes", [])}
        else:
            continue   # block_ip / restore / release are network or rollback actions
        out.append(_step(host, tc, env, action, capability(caps, tc, env, action),
                         level, score, "", params))
    return out


def build_containment_protocol(alert: dict, verdict: dict, entities: dict,
                               enrichment: dict = None, *, caps=None, now: float = 0.0,
                               include_lateral: bool = True) -> dict:
    caps = caps if caps is not None else load_capabilities()
    alert = alert or {}
    source_env = source_environment(alert.get("source_type", ""))
    incident_id = str(alert.get("event_id", ""))
    sensor = str(alert.get("sensor_id", ""))
    confidence = float((verdict or {}).get("confidence", 0.0) or 0.0)
    memory_confirmed = bool((enrichment or {}).get("memory_threat"))
    entities = entities or {}
    malicious = {eid: ed for eid, ed in entities.items() if (ed or {}).get("status") == "malicious"}
    iocs = extract_iocs(entities)

    steps, escalations, covered, tactics = [], [], set(), set()

    # Primary host epicenter (the alerting sensor).
    prim_class, prim_env = _host_class(source_env)
    prim_steps = (_host_steps(sensor, prim_class, prim_env, caps, iocs, memory_confirmed, confidence)
                  if sensor and prim_class else [])
    steps += prim_steps
    primary_contained = bool(prim_steps)
    if sensor and not prim_class:
        escalations.append(f"primary host {sensor}: source '{alert.get('source_type','')}' "
                           f"has no host containment class")

    for eid, ed in malicious.items():
        etype = str((ed or {}).get("type", "")).strip().lower()
        tc, env = classify_entity(eid, ed, source_env)
        m = _MITRE.search(str((ed or {}).get("notes", "")))
        stage = m.group(0) if m else ""
        if stage:
            tactics.add(stage)
        level, score = entity_certainty(ed, memory_confirmed, confidence)

        # Host-local artifacts ride along as eradication params on the host and are
        # contained by the host's isolation (plus eradication once confirmed).
        if etype in ("pid", "hash", "file", "process"):
            if primary_contained:
                covered.add(eid)
            else:
                escalations.append(f"{etype} {eid}: host artifact but no host containment")
            continue

        if tc in ("endpoint", "cloud_instance"):
            if eid == sensor:
                covered.add(eid)
                continue
            s = _host_steps(eid, tc, env, caps, iocs, memory_confirmed, confidence)
            if s:
                steps += s
                covered.add(eid)
            else:
                escalations.append(f"{tc}/{env} {eid}: no executable host action")
            continue

        wants = desired_actions(tc, etype)
        made = False
        for action in wants:
            if is_executable(caps, tc, env, action):
                params = {"target": eid} if tc == "network" else {}
                steps.append(_step(eid, tc, env, action, capability(caps, tc, env, action),
                                   level, score, stage, params))
                made = True
        if made:
            covered.add(eid)
        else:
            escalations.append(f"{tc}/{env} {eid} ({etype}): no executable action "
                               f"for {wants or 'unknown class'}")

    # Lateral unification: contain the internal peers the compromised host reached
    # (suspected spread) in the SAME protocol. Suspected peers are operator-gated;
    # an overflow beyond the fan-out cap is escalated, never silently auto-actioned.
    lateral_targets = []
    if include_lateral and prim_class:
        peers = connected_internal_peers(entities, origin_host=sensor, exclude=set(covered))
        fan = plan_fanout(peers)
        for peer in fan["fanout"]:
            for s in _host_steps(peer, prim_class, prim_env, caps, {}, False, confidence):
                s["lateral"] = True
                if s["action"] != "collect_forensics":   # only evidence capture stays autonomous
                    s["gate"] = "operator_approval"
                steps.append(s)
            lateral_targets.append(peer)
        if fan["escalate"]:
            escalations.append(f"lateral fan-out exceeds cap: {len(fan['overflow'])} more "
                               f"peers need an operator")

    for s in steps:                       # per (incident, target, action) replay guard
        s["idempotency_key"] = f"{incident_id}:{s['target']}:{s['action']}"
    steps.sort(key=lambda s: (s["wave"], _ACTION_ORDER.get(s["action"], 50), s["target"]))
    coverage = {"tp_entities": len(malicious), "covered": len(covered),
                "uncovered": sorted(set(malicious) - covered), "tactics": sorted(tactics)}
    kill_chain_closed = (not escalations) and len(covered) == len(malicious)
    return {"incident_id": incident_id, "generated_at": now, "steps": steps,
            "environment": prim_env or source_env, "target_class": prim_class or "",
            "coverage": coverage, "escalations": escalations,
            "lateral_targets": lateral_targets, "kill_chain_closed": kill_chain_closed}


def build_rollback_protocol(protocol: dict, *, now: float = 0.0) -> dict:
    """Reverse an executed protocol when the verdict flips to false positive.
    For every step that declared a reversible_by action, emit that rollback on the
    same target and executor. Rollbacks are de-escalations, so they run autonomously."""
    steps = []
    for s in (protocol or {}).get("steps", []):
        rev = s.get("reversible_by")
        if not rev:
            continue
        steps.append({
            "target": s["target"], "target_class": s["target_class"],
            "environment": s.get("environment", ""), "action": rev,
            "executor": s["executor"], "params": {}, "kill_chain_stage": "",
            "wave": 2, "certainty": s.get("certainty", 0.0),
            "certainty_level": s.get("certainty_level", "malicious"),
            "reversible_by": "", "gate": "auto", "lateral": s.get("lateral", False),
            "idempotency_key": f"{(protocol or {}).get('incident_id','')}:{s['target']}:{rev}",
        })
    steps.sort(key=lambda x: (_ACTION_ORDER.get(x["action"], 50), x["target"]))
    return {"incident_id": (protocol or {}).get("incident_id", ""), "generated_at": now,
            "steps": steps, "reverses": len(steps)}
