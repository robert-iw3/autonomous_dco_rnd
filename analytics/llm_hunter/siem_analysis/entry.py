"""
Operator / API / detection-driven entry points for standalone SIEM analysis.

Two thin IO shells around `run_standalone_analysis`:

  * CLI — an operator runs one analysis from the command line and gets the
    incident report as JSON on stdout.
  * NATS consumer — subscribes `nexus.siem.analyze` (published by the operator
    API gateway or a detection hit) and publishes the finished report on
    `nexus.siem.analysis.report`. RBAC rides on the NATS accounts: the swarm
    account is the only subscriber of the request subject, and the SIEM side
    stays read-only by construction (the pivot's guards).

Every request is audited to the tamper-evident verdict ledger by the runner
itself, whichever entry it came through.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from siem_analysis.request import SiemAnalysisRequest
from siem_analysis.standalone import run_standalone_analysis

logger = logging.getLogger("nexus-siem-entry")

SUBJECT_ANALYZE = "nexus.siem.analyze"
SUBJECT_REPORT = "nexus.siem.analysis.report"


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Standalone agentic SIEM analysis")
    ap.add_argument("--backend", required=True)
    ap.add_argument("--dialect", required=True, choices=["spl", "esql", "kql"])
    ap.add_argument("--query", default="")
    ap.add_argument("--detection-id", default="")
    ap.add_argument("--detection-name", default="")
    ap.add_argument("--product", default="")
    ap.add_argument("--window-hours", type=int, default=24)
    ap.add_argument("--max-rows", type=int, default=200)
    ap.add_argument("--coverage", action="store_true",
                    help="include the coverage/gap report + environment profile")
    ap.add_argument("--requested-by", default=os.getenv("USER", "operator"))
    args = ap.parse_args(argv)

    request = SiemAnalysisRequest(
        backend=args.backend, dialect=args.dialect, query=args.query,
        detection_id=args.detection_id, detection_name=args.detection_name,
        product=args.product, window_hours=args.window_hours, max_rows=args.max_rows,
        include_coverage_report=args.coverage, entry_point="operator",
        requested_by=args.requested_by)
    report = run_standalone_analysis(request)
    json.dump(report, sys.stdout, indent=2, default=str)
    print()
    return 0 if report.get("analyzed") else 1


async def consume(nc) -> None:
    """Serve nexus.siem.analyze requests on an existing NATS connection."""

    async def _on_request(msg):
        try:
            request = SiemAnalysisRequest(**json.loads(msg.data.decode()))
        except Exception as e:  # noqa: BLE001 — a malformed request is reported, not fatal
            logger.error("rejected malformed siem.analyze request: %s", e)
            await nc.publish(SUBJECT_REPORT, json.dumps(
                {"analyzed": False, "error": f"malformed request: {e}"}).encode())
            return
        loop = asyncio.get_running_loop()
        report = await loop.run_in_executor(None, run_standalone_analysis, request)
        await nc.publish(SUBJECT_REPORT, json.dumps(report, default=str).encode())
        logger.info("siem.analyze %s -> analyzed=%s", request.request_id,
                    report.get("analyzed"))

    await nc.subscribe(SUBJECT_ANALYZE, cb=_on_request)
    logger.info("subscribed %s", SUBJECT_ANALYZE)


async def serve() -> None:  # pragma: no cover — thin production shell
    import nats
    connect_kwargs: dict = {"servers": [os.getenv("NATS_URL", "nats://nats:4222")]}
    user, password = os.getenv("NATS_USER", ""), os.getenv("NATS_PASSWORD", "")
    if user and password:
        connect_kwargs.update(user=user, password=password)
    nc = await nats.connect(**connect_kwargs)
    await consume(nc)
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    if "--serve" in sys.argv:
        asyncio.run(serve())
    else:
        sys.exit(cli())
