"""
Det Chamber intake service.

Bridges an acquired artifact (in the quarantine bucket) to a detonation and emits
the result for the swarm. The pure orchestration -- handle_intake() -- takes its
I/O as injected callables so it is fully unit-testable; main() wires the real
NATS + S3/MinIO clients (imported lazily so the test path needs neither).

Flow (one message on nexus.detonation.intake):
  parse manifest -> fetch artifact -> VERIFY CHAIN OF CUSTODY -> route by os_family
  -> run engine (single file) -> publish result on nexus.alerts.detonation.

If custody verification fails the service NEVER detonates; it emits a
`custody_failed` result (acked + surfaced, never silently dropped) instead.
"""

import json
import logging
import os
from typing import Callable

from manifest import CustodyError, manifest_from_dict, verify_custody

logger = logging.getLogger("detchamber-intake")

SUBJECT_INTAKE = "nexus.detonation.intake"
SUBJECT_ALERTS = "nexus.alerts.detonation"
RESULT_SCHEMA = "detonation_result_v1"

# -- Prometheus metrics --
_METRICS = {}


def serve_metrics(port: int = 9464):  # pragma: no cover - wired in production main()
    """Expose detonation/custody metrics on /metrics for the platform Prometheus."""
    from prometheus_client import start_http_server, Counter
    _METRICS["detonations"] = Counter(
        "detchamber_detonations_total", "Detonation results by status", ["status"])
    start_http_server(port)
    logger.info("intake metrics on :%d", port)


def _inc(status: str):
    m = _METRICS.get("detonations")
    if m is not None:
        m.labels(status=status).inc()

# os_family -> analyzer label. The Linux analyzer becomes real in Phase 3; the
# routing contract is fixed here so the rest of the pipeline can rely on it.
_ANALYZER_BY_OS = {"windows": "windows_engine", "linux": "linux_sandbox"}


def select_analyzer(os_family: str) -> str:
    try:
        return _ANALYZER_BY_OS[str(os_family).lower()]
    except KeyError:
        raise ValueError(f"no analyzer for os_family={os_family!r}")


def _result_envelope(manifest, *, status, analyzer, summary):
    return {
        "schema": RESULT_SCHEMA,
        "incident_id": manifest.incident_id,
        "host": manifest.host,
        "filename": manifest.filename,
        "sha256": manifest.sha256,
        "os_family": manifest.os_family,
        "analyzer": analyzer,
        "status": status,                 # "detonated" | "custody_failed"
        "summary": summary,               # engine summary.json (or None)
    }


def handle_intake(request: dict, *,
                  fetch_artifact: Callable[[str], bytes],
                  run_engine: Callable,
                  publish: Callable[[str, dict], None]) -> dict:
    """Process one intake request. Returns the result envelope that was published."""
    manifest = manifest_from_dict(request["manifest"])
    analyzer = select_analyzer(manifest.os_family)
    data = fetch_artifact(request["artifact_ref"])

    # -- CHAIN OF CUSTODY: detonate only byte-identical, manifested artifacts --
    try:
        verify_custody(data, manifest)
    except CustodyError as e:
        logger.error("Custody verification FAILED for incident %s: %s -- refusing to detonate",
                     manifest.incident_id, e)
        event = _result_envelope(manifest, status="custody_failed",
                                 analyzer=analyzer, summary={"error": str(e)})
        publish(SUBJECT_ALERTS, event)
        _inc("custody_failed")
        return event

    summary = run_engine(data, manifest, analyzer)
    event = _result_envelope(manifest, status="detonated", analyzer=analyzer, summary=summary)
    publish(SUBJECT_ALERTS, event)
    _inc("detonated")
    logger.info("Detonation complete for incident %s (%s) via %s",
                manifest.incident_id, manifest.filename, analyzer)
    return event


# -- Production wiring (lazy clients; not needed by the test path) -------------
def _real_main():  # pragma: no cover - exercised in the live dockerized topology
    import asyncio
    import boto3
    import nats

    nats_url = os.getenv("NATS_URL", "nats://nats:4222")
    # Authenticate as detchamber_node -- the broker is default-deny.
    nats_user = os.getenv("NATS_USER", "detchamber_node")
    nats_pass = os.getenv("NATS_PASS", "")
    serve_metrics(int(os.getenv("DETCHAMBER_METRICS_PORT", "9464")))
    s3 = boto3.client("s3", endpoint_url=os.getenv("QUARANTINE_S3_ENDPOINT"))

    def fetch_artifact(ref: str) -> bytes:
        # ref: s3://bucket/key
        _, _, rest = ref.partition("://")
        bucket, _, key = rest.partition("/")
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    def run_engine(data, manifest, analyzer):
        from engine_runner import detonate_single  # Phase 3 single-file engine wrapper
        return detonate_single(data, manifest, analyzer)

    async def _run():
        auth = {"user": nats_user, "password": nats_pass} if nats_user and nats_pass else {}
        nc = await nats.connect(nats_url, **auth)

        async def _cb(msg):
            try:
                req = json.loads(msg.data.decode())
                await asyncio.to_thread(
                    handle_intake, req,
                    fetch_artifact=fetch_artifact, run_engine=run_engine,
                    publish=lambda subj, ev: asyncio.run(nc.publish(subj, json.dumps(ev).encode())),
                )
                await msg.ack()
            except Exception as e:
                logger.error("intake handler error: %s", e)

        await nc.subscribe(SUBJECT_INTAKE, cb=_cb)
        logger.info("intake service online on %s", SUBJECT_INTAKE)
        while True:
            await asyncio.sleep(3600)

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    _real_main()
