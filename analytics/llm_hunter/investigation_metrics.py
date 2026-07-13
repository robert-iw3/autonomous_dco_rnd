"""InvestigationMetrics record (WS-A M-27, plan §3.4).

Pure/stdlib builder: the swarm state at the end of trigger_swarm → one record for
the measurement plane (NATS nexus.metrics.investigation → parquet ledger). The
`outcome` block is filled later by 11_join_outcomes (operator action + SOAR +
24h reinfection). Emission is fire-and-forget and never blocks the hot path.
"""
from __future__ import annotations

import time

_EFFICIENCY_KEYS = ("turns", "llm_calls", "provider_fallbacks",
                    "tool_errors", "tokens_est", "wall_ms")
_RESOLVED = {"malicious", "cleared"}


def _entity_rollup(entities: dict) -> dict:
    ents = (entities or {}).values()
    statuses = [str((e or {}).get("status", "")).lower() for e in ents]
    return {
        "seeded": len(statuses),
        "malicious": sum(s == "malicious" for s in statuses),
        "cleared": sum(s == "cleared" for s in statuses),
        "resolved": sum(s in _RESOLVED for s in statuses),
    }


def build_record(alert: dict, state: dict, *, efficiency: dict = None,
                 model_versions: dict = None, ts: float = None) -> dict:
    """Build the per-investigation metrics record from the alert + final state."""
    alert, state = alert or {}, state or {}
    v = state.get("verdict") or {}
    critic = state.get("critic") or {}
    eff = {k: 0 for k in _EFFICIENCY_KEYS}
    eff.update({k: (efficiency or {}).get(k, 0) for k in _EFFICIENCY_KEYS})
    roll = _entity_rollup(state.get("entities_of_interest"))
    roll["temporal_seeded"] = int(state.get("temporal_seeded", 0) or 0)
    immunity = state.get("immunity") or {}
    return {
        "event_id": str(alert.get("event_id", "")),
        "ts": ts if ts is not None else time.time(),
        "source_type": alert.get("source_type", ""),
        "vector_name": alert.get("vector_name", ""),
        "anomaly_score": float(alert.get("anomaly_score", 0.0) or 0.0),
        "model_versions": dict(model_versions or {}),
        "verdict": {
            "is_tp": bool(v.get("is_true_positive", False)),
            "confidence": float(v.get("confidence", 0.0) or 0.0),
            "action": v.get("recommended_action", ""),
        },
        "analysis_complete": bool(state.get("analysis_complete", False)),
        "gate_overrides_used": int(state.get("gate_overrides", 0) or 0),
        "critic": {
            "invoked": bool(critic.get("invoked", False)),
            "overrode": bool(critic.get("overrode", False)),
            "direction": critic.get("direction", ""),
        },
        "immunity": {
            "hit": bool(state.get("immunity_hit", immunity.get("hit", False))),
            "point_id": str(state.get("immunity_point_id", immunity.get("point_id", "")) or ""),
        },
        "entities": roll,
        "efficiency": eff,
        "outcome": {},   # joined later by 11_join_outcomes
    }
