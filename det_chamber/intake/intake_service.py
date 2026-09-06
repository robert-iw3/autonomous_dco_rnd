"""
Det Chamber intake service.

Bridges an acquired artifact (in the quarantine bucket) to a detonation and emits
the result for the swarm. The pure orchestration -- handle_intake() -- takes its
I/O as injected callables so it is fully unit-testable; main() wires the real
NATS + S3/MinIO clients (imported lazily so the test path needs neither).

Flow (one message on nexus.detonation.intake):
  parse manifest -> fetch artifact -> VERIFY CHAIN OF CUSTODY -> route by os_family
  -> run engine (single file) -> publish result on nexus.alerts.detonation.

Two producers publish that subject: core_ingress (PRIMARY -- manifest in NATS
headers, packaged artifact in the body) and the acquire_worker SSH fallback
(`{artifact_ref, manifest}` JSON). A message matching neither shape is logged as
an error and counted, never dropped quietly.

If custody verification fails the service NEVER detonates; it emits a
`custody_failed` result (acked + surfaced, never silently dropped) instead.
"""

import io
import json
import logging
import os
import zipfile
from datetime import datetime, timezone
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


# NATS header -> manifest field, as core_ingress relays them
# (services/core_ingress/src/main.rs handle_artifact_upload).
_HDR_TO_FIELD = {
    "x-incident-id": "incident_id",
    "x-sensor-id": "host",
    "x-src-path": "src_path",
    "x-artifact-filename": "filename",
    "x-artifact-sha256": "sha256",
    "x-artifact-size": "size",
    "x-os-family": "os_family",
    "x-acquired-at": "acquired_at",
}


def is_relayed_artifact(headers) -> bool:
    """True when the message carries the ingress relay shape (manifest in headers)."""
    return any(str(k).lower() in _HDR_TO_FIELD for k in (headers or {}))


def manifest_from_headers(headers, *, received_at: str) -> dict:
    """Rebuild the manifest core_ingress relays as NATS headers."""
    d = {_HDR_TO_FIELD[str(k).lower()]: v for k, v in (headers or {}).items()
         if str(k).lower() in _HDR_TO_FIELD}
    if not d.get("acquired_at"):
        # The ingress does not forward an acquisition timestamp yet; record the
        # intake receipt time so the provenance field is never silently blank.
        d["acquired_at"] = received_at
        logger.warning("no X-Acquired-At on the relayed artifact -- stamping intake "
                       "receipt time %s", received_at)
    return d


def unpackage(blob: bytes, name: str) -> bytes:
    """Original bytes out of the packaged (zipped) artifact the ingress relays.
    Mirrors acquire_core.unpackage -- the intake image ships without agents/."""
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        return z.read(name)


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
            body = bytes(msg.data or b"")
            try:
                if is_relayed_artifact(msg.headers):
                    # PRIMARY path: manifest in headers, packaged artifact in the body.
                    received = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    manifest = manifest_from_headers(msg.headers, received_at=received)
                    req = {"artifact_ref": None, "manifest": manifest}
                    name = manifest.get("filename", "")

                    def fetch(_ref, _blob=body, _name=name):
                        return unpackage(_blob, _name)
                else:
                    req = json.loads(body.decode())
                    fetch = fetch_artifact
                manifest_from_dict(req["manifest"])   # reject a bad manifest loudly, here
            except Exception as e:
                logger.error("UNPARSEABLE intake message DROPPED -- %d body bytes, "
                             "headers=%s: %s", len(body), sorted(msg.headers or {}), e)
                _inc("unparseable")
                return
            try:
                await asyncio.to_thread(
                    handle_intake, req,
                    fetch_artifact=fetch, run_engine=run_engine,
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
