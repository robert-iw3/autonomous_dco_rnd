"""
Seed synthesis — a SIEM detection hit becomes an investigation seed.

The standalone path introduces no new analysis brain: it shapes the SIEM hit
into the same UnifiedAlertSchema the orchestrator already investigates, so the
existing swarm graph (supervisor -> experts -> review board -> response) can
run unchanged. The seed's source_type is the canonical class for the
detection's product (windows -> sysmon_sensor, aws -> aws_cloudtrail, ...) so
routing and containment-environment resolution reuse the existing maps; the
SIEM provenance (backend, dialect, bounded query) rides in raw_event.

`synthesize_seed` is pure and returns a plain dict; `validate_seed` round-trips
it through the strict UnifiedAlertSchema (imported lazily so pure callers do
not need the langchain-backed state module).
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from siem_analysis.entity_extractor import hosts_in

SEED_VECTOR_NAME = "siem_pivot"

# Result fields that may carry a detection-scored severity/risk (0-100 or 0-1).
_SCORE_FIELDS = ("event.risk_score", "risk_score", "score", "event.severity", "severity")

_SEVERITY_WORDS = {"informational": 0.3, "low": 0.45, "medium": 0.65,
                   "high": 0.85, "critical": 0.95}


def seed_anomaly_score(rows: List[Dict[str, Any]], default: float = 0.75) -> float:
    """Anomaly score for the seed from the rows' own severity/risk fields.

    The maximum scored value wins (an analyst triages to the worst signal);
    numeric scores above 1 are treated as 0-100 scaled. Rows with no scoring
    fields fall back to the default — a detection hit is prima facie worth a
    real investigation, but not a confirmed critical.
    """
    best = None
    for row in rows or []:
        for field in _SCORE_FIELDS:
            val = (row or {}).get(field)
            if val is None:
                continue
            sval = str(val).strip().lower()
            if sval in _SEVERITY_WORDS:
                score = _SEVERITY_WORDS[sval]
            else:
                try:
                    score = float(sval)
                except ValueError:
                    continue
                if score > 1.0:
                    score = score / 100.0
            score = min(max(score, 0.0), 1.0)
            best = score if best is None else max(best, score)
    return default if best is None else best


def synthesize_seed(request, rows: List[Dict[str, Any]],
                    bounded_query: str = "", now: float = 0.0) -> Dict[str, Any]:
    """UnifiedAlertSchema-shaped seed dict from a SIEM hit (plain rows)."""
    hosts = hosts_in(rows)
    return {
        "event_id": f"siem-{request.request_id}",
        "timestamp": now or time.time(),
        "sensor_id": hosts[0] if hosts else request.backend,
        "source_type": request.source_type(),
        "vector_name": SEED_VECTOR_NAME,
        "anomaly_score": seed_anomaly_score(rows),
        "raw_event": {
            "siem": {
                "backend": request.backend,
                "dialect": request.dialect,
                "bounded_query": bounded_query,
                "detection_id": request.detection_id,
                "detection_name": request.detection_name,
                "entry_point": request.entry_point,
            },
            "row_count": len(rows or []),
            "hosts": hosts,
            "sample_rows": (rows or [])[:10],
        },
    }


def validate_seed(seed: Dict[str, Any]):
    """Round-trip the seed through the strict schema; returns the model.
    Lazily imports the state module (pydantic + langchain-backed)."""
    from state import UnifiedAlertSchema
    return UnifiedAlertSchema(**seed)
