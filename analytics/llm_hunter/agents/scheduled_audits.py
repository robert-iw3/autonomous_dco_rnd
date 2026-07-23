"""
Scheduled governance-audit runner (POA&M-1).

Single entry point a systemd timer (or cron) invokes on a cadence to run every
periodic AI-governance control as a *running* job, not just implemented logic:

  * NC-1  bias / homogenization audit         (agents/bias_audit.collect_and_audit)
  * NC-2  calibration + over-reliance report  (agents/calibration_ledger.over_reliance)
  * NC-7  inference-endpoint abuse monitor    (agents/endpoint_abuse_monitor.collect_and_monitor)
  * WS-H  GRC continuous re-assessment        (docs/governance/grc_assess) — re-derives
          proven control posture from the latest JUnit, appends the posture ledger, and
          flags on regression / any open finding, so posture is monitored continuously
          (not only on commit).

Each job is fail-soft and isolated: one job raising never blocks the others, and
the runner returns a per-job status so the timer's journal shows what ran. The
data collectors are the only impure parts and are injectable, so the
orchestration logic stays deterministically unit-tested.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Callable, Dict, Any, List

logger = logging.getLogger("nexus-scheduled-audits")


def _safe(name: str, fn: Callable[[], Any]) -> dict:
    """Run one job, capturing success/failure without propagating."""
    try:
        result = fn()
        flagged = bool(result.get("flagged")) if isinstance(result, dict) else False
        return {"job": name, "ok": True, "flagged": flagged}
    except Exception as e:  # a broken job must not sink the others
        logger.error("audit job %s failed: %s", name, e)
        return {"job": name, "ok": False, "error": f"{type(e).__name__}: {e}"}


def run_all(jobs: Dict[str, Callable[[], Any]]) -> dict:
    """Run every provided {name: callable} job fail-soft; summarize outcomes."""
    results: List[dict] = [_safe(name, fn) for name, fn in (jobs or {}).items()]
    return {
        "generated_at": time.time(),
        "n_jobs": len(results),
        "n_failed": sum(1 for r in results if not r["ok"]),
        "n_flagged": sum(1 for r in results if r.get("flagged")),
        "results": results,
    }


def default_jobs() -> Dict[str, Callable[[], Any]]:
    """The production job set, wired to each control's collect/entry point. Imports
    are local so this module (and its tests) load without the collectors' deps."""
    from agents import bias_audit, endpoint_abuse_monitor
    from agents import calibration_ledger

    def _reliance():
        recs = calibration_ledger.load_ledger()
        return calibration_ledger.over_reliance(recs)

    def _grc_reassessment():
        # WS-H: re-derive proven posture from the latest reports, append the ledger,
        # and flag on regression or any open finding. Imported locally (governance
        # engine lives under docs/governance) so this module loads without it.
        import sys
        gov = Path(__file__).resolve().parents[3] / "docs/governance"
        sys.path.insert(0, str(gov))
        import grc_lib, grc_assess
        junit = grc_lib.load_junit()
        a = grc_assess.assess(junit)
        p = grc_assess.posture(a)
        grc_assess.append_ledger(a, p, grc_assess._timestamp(grc_lib.DEFAULT_REPORTS))
        ok, _reasons = grc_assess.gate(a, p, grc_assess.load_baseline())
        return {"flagged": (not ok) or any(x["finding"] for x in a)}

    return {
        "bias_audit": bias_audit.collect_and_audit,
        "over_reliance": _reliance,
        "endpoint_abuse": endpoint_abuse_monitor.collect_and_monitor,
        "grc_assessment": _grc_reassessment,
    }


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Scheduled AI-governance audits (POA&M-1)")
    ap.add_argument("--status-file", default="/var/lib/nexus/governance/last_run.json")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    summary = run_all(default_jobs())
    out = Path(args.status_file)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2))
    logger.info("governance audits complete: %d jobs, %d failed, %d flagged -> %s",
                summary["n_jobs"], summary["n_failed"], summary["n_flagged"], out)
    # Non-zero exit only on a job *error* (not a flag): a flag is an expected
    # finding the report captures; an error means the control did not run.
    return 1 if summary["n_failed"] else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
