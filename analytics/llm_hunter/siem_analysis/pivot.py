"""
Standalone siem_pivot runner — SiemQueryTool's read path outside an investigation.

The same guards, in the same order, as the expert tool (tools/siem_query):
read-only validation, index allowlist, forced time+row bounds, dialect adapter
with an injectable transport, untrusted-wrapped results, fail-open on an
unreachable SIEM. The difference is the caller: an operator/API/detection entry
point running a SiemAnalysisRequest, and a structured PivotResult (parsed rows)
instead of a tool string, so the analysis pipeline can consume the evidence.

Never mutates a SIEM; never raises on SIEM failure — an unavailable backend
yields status SIEM_UNAVAILABLE and the analysis reports "could not analyze"
instead of hanging.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from tools.siem_query import (_ADAPTERS, _FUTURE_DIALECTS, Transport, enforce_bounds,
                              sanitize_rows, validate_indexes, validate_readonly)
from tools.sanitizer import CognitiveSanitizer
from tools.nexus_config import get_siem_config

logger = logging.getLogger("nexus-siem-standalone")

STATUS_OK = "ok"
STATUS_REJECTED = "SIEM_QUERY_REJECTED"
STATUS_UNAVAILABLE = "SIEM_UNAVAILABLE"
STATUS_NOT_IMPLEMENTED = "SIEM_BACKEND_NOT_IMPLEMENTED"


def _result(status: str, reason: str = "", **kw) -> Dict[str, Any]:
    return {"status": status, "reason": reason, "rows": [], "bounded_query": "",
            "backend": kw.pop("backend", ""), "dialect": kw.pop("dialect", ""), **kw}


def run_siem_pivot(request, siem_config: Optional[dict] = None,
                   transport: Optional[Transport] = None) -> Dict[str, Any]:
    """Execute one read-only, bounded pivot for a SiemAnalysisRequest.

    Returns a PivotResult dict:
        status         ok | SIEM_QUERY_REJECTED | SIEM_UNAVAILABLE | SIEM_BACKEND_NOT_IMPLEMENTED
        reason         human-readable detail for non-ok statuses
        rows           sanitized result rows (every cell untrusted-wrapped)
        bounded_query  the query actually dispatched (bounds enforced)
        backend/dialect  echo of the target
    """
    siem = siem_config if siem_config is not None else get_siem_config()
    backend_cfg = (siem.get("backends") or {}).get(request.backend)
    if not backend_cfg or not backend_cfg.get("active"):
        return _result(STATUS_UNAVAILABLE,
                       f"backend '{request.backend}' is not reachable/configured",
                       backend=request.backend, dialect=request.dialect)

    dialect = backend_cfg.get("dialect", request.dialect)
    if dialect in _FUTURE_DIALECTS:
        return _result(STATUS_NOT_IMPLEMENTED,
                       f"the '{dialect}' adapter is boilerplate (future backend)",
                       backend=request.backend, dialect=dialect)

    query = request.query.strip()
    if not query:
        return _result(STATUS_REJECTED,
                       f"detection_id '{request.detection_id}' did not resolve to a query "
                       f"(saved-detection resolution requires the backend's detection store)",
                       backend=request.backend, dialect=dialect)

    ok, reason = validate_readonly(query, dialect)
    if not ok:
        return _result(STATUS_REJECTED, reason, backend=request.backend, dialect=dialect)

    allowed = backend_cfg.get("allowed_indexes", [])
    if request.scope_indexes:
        # a request may narrow the allowlist, never widen it
        allowed = [i for i in allowed if i in request.scope_indexes] or ["__scope_mismatch__"]
    ok, reason = validate_indexes(query, dialect, allowed)
    if not ok:
        return _result(STATUS_REJECTED, reason, backend=request.backend, dialect=dialect)

    max_rows = min(request.max_rows, int(siem.get("max_rows", 200)))
    bounded = enforce_bounds(query, dialect, request.window_hours, max_rows)

    adapter_cls = _ADAPTERS.get(dialect)
    if adapter_cls is None:
        return _result(STATUS_REJECTED, f"no adapter for dialect '{dialect}'",
                       backend=request.backend, dialect=dialect)

    try:
        raw_rows = adapter_cls(backend_cfg, transport=transport).search(bounded)
    except Exception as e:  # noqa: BLE001 — fail-open, never hang the analysis
        logger.warning("standalone SIEM pivot failed (%s): %s", request.backend, e)
        return _result(STATUS_UNAVAILABLE,
                       f"query to '{request.backend}' failed ({type(e).__name__})",
                       backend=request.backend, dialect=dialect, bounded_query=bounded)

    rows = sanitize_rows(raw_rows, max_rows)
    return {"status": STATUS_OK, "reason": "", "rows": rows, "bounded_query": bounded,
            "backend": request.backend, "dialect": dialect, "row_count": len(rows)}


def unwrap_cell(value: str) -> str:
    """Strip the untrusted-payload envelope from one sanitized cell so pure
    analysis code (entity extraction, profiling) can read the value while the
    LLM-facing evidence keeps the wrap."""
    s = str(value)
    start = s.find(">")
    end = s.rfind("</untrusted_payload")
    if s.startswith("<untrusted_payload") and start >= 0 and end > start:
        return s[start + 1:end].strip()
    return s


def unwrap_rows(rows) -> list:
    """Plain-value copies of sanitized rows for pure (non-LLM) analysis."""
    return [{k: unwrap_cell(v) for k, v in (r or {}).items()} for r in rows or []]
