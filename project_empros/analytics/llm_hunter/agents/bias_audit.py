"""
Bias / homogenization audit job (NC-1; NIST MS-2.11-002 + GV-1.3-005).

Periodically scrolls the swarm's persisted verdict/immunity memory and runs the
pure analytics from `agents.controls`:
  * `fairness_report`        -- disaggregated containment/TP rates per subgroup
                                (source_type / asset class) vs the fleet baseline;
                                flags allocative disparity in autonomous containment.
  * `memory_homogenization`  -- distribution health of the immunity memory; flags
                                over-concentration on a single signature (the
                                model-collapse / feedback-loop risk).

This converts those two analytics from "implemented" to a *running control*: a
scheduler (cron / RSI cadence) calls `collect_and_audit`, which writes a dated
report and raises an alert when either axis is flagged. The Qdrant scroll is the
only impure part and is isolated + injectable so the decision logic stays
deterministically unit-tested.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from agents.controls import fairness_report, memory_homogenization

logger = logging.getLogger("nexus-bias-audit")

MEMORY_COLLECTION = "nexus_swarm_memory"
DEFAULT_REPORT_DIR = os.getenv("NEXUS_BIAS_AUDIT_DIR", "/var/lib/nexus/bias_audit")


def _signature(rec: dict) -> str:
    """Stable cluster signature for the homogenization distribution."""
    return f"{rec.get('source_type', '')}|{rec.get('vector_name', '')}"


def run_bias_audit(records: List[Dict[str, Any]], dimension: str = "source_type",
                   min_support: int = 5, max_disparity: float = 0.2) -> dict:
    """Pure: turn a list of verdict-memory records into a fairness + homogenization
    audit. Each record carries `source_type`, `is_true_positive`, an `action`
    (or `contained`), and `vector_name`."""
    fair = fairness_report(records, dimension=dimension,
                           min_support=min_support, max_disparity=max_disparity)
    homo = memory_homogenization([_signature(r) for r in records])
    flagged_reasons = []
    if fair["flagged"]:
        flagged_reasons.append(f"containment disparity in {fair['flagged']}")
    if homo["homogenized"]:
        flagged_reasons.append(
            f"immunity-memory over-concentration (top_share={homo['top_share']})")
    return {
        "generated_at": time.time(),
        "n_records": len(records),
        "dimension": dimension,
        "fairness": fair,
        "homogenization": homo,
        "flagged": bool(flagged_reasons),
        "flagged_reasons": flagged_reasons,
    }


def write_report(audit: dict, report_dir: str = DEFAULT_REPORT_DIR) -> str:
    """Write the audit JSON to a dated file; return its path."""
    d = Path(report_dir)
    d.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime(audit.get("generated_at", time.time())))
    path = d / f"bias_audit_{ts}.json"
    path.write_text(json.dumps(audit, indent=2))
    if audit["flagged"]:
        logger.warning("BIAS AUDIT FLAGGED: %s -> %s", "; ".join(audit["flagged_reasons"]), path)
    else:
        logger.info("Bias audit clean (%d records) -> %s", audit["n_records"], path)
    return str(path)


def _scroll_qdrant(client, collection: str, limit: int) -> List[Dict[str, Any]]:
    """Pull verdict-memory payloads from Qdrant (production collector). Isolated so
    the rest of the job is infra-free + unit-tested."""
    records, offset = [], None
    while len(records) < limit:
        points, offset = client.scroll(
            collection_name=collection, with_payload=True,
            limit=min(256, limit - len(records)), offset=offset)
        for p in points:
            pl = getattr(p, "payload", None) or {}
            records.append({
                "source_type": pl.get("source_type", ""),
                "vector_name": pl.get("vector_name", ""),
                "is_true_positive": bool(pl.get("is_true_positive", False)),
                "action": pl.get("action", ""),
            })
        if offset is None or not points:
            break
    return records


def collect_and_audit(client=None, collection: str = MEMORY_COLLECTION, limit: int = 50000,
                      report_dir: str = DEFAULT_REPORT_DIR,
                      collector: Optional[Callable] = None) -> dict:
    """Scheduler entry point: collect verdict memory, audit, write report. `client`
    or a `collector(client, collection, limit) -> records` may be injected (tests)."""
    if collector is None:
        collector = _scroll_qdrant
    records = collector(client, collection, limit)
    audit = run_bias_audit(records)
    audit["report_path"] = write_report(audit, report_dir)
    return audit
