"""
Inference-endpoint abuse / model-extraction monitor (NC-7; NIST MS-2.10-001,
OWASP LLM10, ATLAS AML.T0024/AML.T0040).

The sovereign vLLM endpoints are network-isolated but not rate/anomaly-checked.
This job turns per-caller access records into a running control: a scheduler
(cron / RSI cadence) calls `collect_and_monitor`, which applies the pure analytics
from `agents.controls` (`endpoint_abuse_report`) and writes a dated report,
raising an alert when a caller trips a quota, a volume spike over its own
baseline, or a systematic near-duplicate probing pattern (extraction / membership
inference). The access-log collector is the only impure part and is isolated +
injectable so the decision logic stays deterministically unit-tested.

Access records are shaped `{caller, query, ts?}`. In production they come from the
vLLM gateway access log or the proxy in front of the sovereign endpoints; the
baseline is the prior window's per-caller mean, persisted alongside the report.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from agents.controls import endpoint_abuse_report

logger = logging.getLogger("nexus-endpoint-abuse")

DEFAULT_REPORT_DIR = os.getenv("NEXUS_ENDPOINT_ABUSE_DIR", "/var/lib/nexus/endpoint_abuse")
DEFAULT_QUOTA = int(os.getenv("NEXUS_ENDPOINT_QUOTA", "5000"))
DEFAULT_VOLUME_FACTOR = float(os.getenv("NEXUS_ENDPOINT_VOLUME_FACTOR", "3.0"))
DEFAULT_VOLUME_FLOOR = int(os.getenv("NEXUS_ENDPOINT_VOLUME_FLOOR", "500"))
DEFAULT_SIM_THRESHOLD = float(os.getenv("NEXUS_ENDPOINT_SIM_THRESHOLD", "0.85"))
DEFAULT_MIN_QUERIES = int(os.getenv("NEXUS_ENDPOINT_MIN_QUERIES", "25"))


def run_endpoint_abuse_audit(records: List[Dict[str, Any]], baseline=None,
                             quota: int = DEFAULT_QUOTA,
                             volume_factor: float = DEFAULT_VOLUME_FACTOR,
                             volume_floor: int = DEFAULT_VOLUME_FLOOR,
                             sim_threshold: float = DEFAULT_SIM_THRESHOLD,
                             min_queries: int = DEFAULT_MIN_QUERIES) -> dict:
    """Pure: per-caller access records -> abuse report with per-caller baselines."""
    report = endpoint_abuse_report(
        records, quota=quota, baseline=baseline or {},
        volume_factor=volume_factor, volume_floor=volume_floor,
        sim_threshold=sim_threshold, min_queries=min_queries)
    reasons = [f"{c['caller']}: {'+'.join(c['reasons'])}" for c in report["flagged"]]
    return {
        "generated_at": time.time(),
        "n_records": len(records or []),
        "report": report,
        "flagged": bool(report["flagged"]),
        "flagged_reasons": reasons,
        # next window's baseline: this window's per-caller counts
        "next_baseline": _counts(records),
    }


def _counts(records) -> dict:
    counts: dict = {}
    for r in records or []:
        c = str((r or {}).get("caller", ""))
        counts[c] = counts.get(c, 0) + 1
    return {c: float(n) for c, n in counts.items()}


def write_report(audit: dict, report_dir: str = DEFAULT_REPORT_DIR) -> str:
    """Write the audit JSON to a dated file; return its path."""
    d = Path(report_dir)
    d.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime(audit.get("generated_at", time.time())))
    path = d / f"endpoint_abuse_{ts}.json"
    path.write_text(json.dumps(audit, indent=2))
    if audit["flagged"]:
        logger.warning("ENDPOINT ABUSE FLAGGED: %s -> %s",
                       "; ".join(audit["flagged_reasons"]), path)
    else:
        logger.info("Endpoint-abuse audit clean (%d records) -> %s",
                    audit["n_records"], path)
    return str(path)


def _read_access_log(client, path_or_source, limit: int) -> List[Dict[str, Any]]:
    """Load access records (production collector). Isolated so the rest of the job
    is infra-free + unit-tested. Reads a JSONL access log of {caller, query, ts}."""
    records: List[Dict[str, Any]] = []
    p = Path(path_or_source)
    if not p.exists():
        return records
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or len(records) >= limit:
            break
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        records.append({"caller": d.get("caller", ""), "query": d.get("query", ""),
                        "ts": d.get("ts")})
    return records


def _load_baseline(report_dir: str) -> dict:
    """Most recent report's next_baseline, if any (per-caller prior-window means)."""
    d = Path(report_dir)
    if not d.exists():
        return {}
    reports = sorted(d.glob("endpoint_abuse_*.json"))
    if not reports:
        return {}
    try:
        return json.loads(reports[-1].read_text()).get("next_baseline", {}) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def collect_and_monitor(client=None, source: str = "", limit: int = 500000,
                        report_dir: str = DEFAULT_REPORT_DIR,
                        collector: Optional[Callable] = None,
                        baseline: Optional[dict] = None, **audit_kwargs) -> dict:
    """Scheduler entry point: collect access records, run the abuse audit, write the
    report. `collector(client, source, limit) -> records` and `baseline` may be
    injected (tests); otherwise the baseline is read from the last report. Extra
    kwargs (quota, volume_factor/floor, sim_threshold, min_queries) tune sensitivity
    and are forwarded to the audit."""
    if collector is None:
        collector = _read_access_log
    records = collector(client, source, limit)
    if baseline is None:
        baseline = _load_baseline(report_dir)
    audit = run_endpoint_abuse_audit(records, baseline=baseline, **audit_kwargs)
    audit["report_path"] = write_report(audit, report_dir)
    return audit
