"""
Acquire worker -- consumes nexus.acquire.request, drives the on-endpoint agent,
uploads the artifact to the quarantine bucket, and emits nexus.detonation.intake.

The pure orchestration (handle_acquire_request) takes its I/O injected so it is
unit-testable; production wiring (NATS + the ssh_playbook_v1 SSH/WinRM executor +
S3/MinIO upload) is lazy. This is the deterministic worker that does the actual
endpoint reach -- the LLM only ever emitted the validated AcquisitionRequest.
"""

import json
import logging
import os
from typing import Callable, Tuple

from acquire_core import validate_request_path, AcquisitionError

logger = logging.getLogger("detchamber-acquire-worker")

SUBJECT_ACQUIRE = "nexus.acquire.request"
SUBJECT_INTAKE = "nexus.detonation.intake"


def enqueue_acquisition_task(request: dict, *,
                             enqueue: Callable[[str, dict], None]) -> dict:
    """PRIMARY path (outbound-only endpoints): vet the request and enqueue an
    acquisition task keyed by host. The on-host acquisition agent polls ingress
    (GET /api/v1/tasks), acquires the file locally, and transmits it OUTBOUND over
    HTTPS to ingress (POST /api/v1/artifact) -- the platform never reaches into the
    endpoint. Ingress verifies custody + HMAC, stores the artifact, and emits
    nexus.detonation.intake. Returns the enqueued task.
    """
    validate_request_path(request["file_path"], os_family=request["os_family"])
    task = {
        "incident_id": request["incident_id"],
        "host": request["host"],
        "file_path": request["file_path"],
        "os_family": request["os_family"],
        "reason": request.get("reason", ""),
    }
    enqueue(request["host"], task)   # task store keyed by host; agent polls it
    logger.info("Enqueued acquisition task for %s (incident %s)",
                request["host"], request["incident_id"])
    return task


def handle_acquire_request(request: dict, *,
                           run_playbook: Callable[[dict], Tuple[dict, bytes]],
                           upload: Callable[[str, str, bytes], str],
                           publish: Callable[[str, dict], None]) -> dict:
    """FALLBACK path (managed hosts with EDR live-response / SSH-WinRM reach-in):
    vet -> dispatch agent -> upload -> emit intake. Returns the intake message.
    Prefer enqueue_acquisition_task for endpoints the platform cannot reach inbound."""
    # Defense in depth: vet the path on the worker BEFORE touching the endpoint.
    # (The on-endpoint agent re-validates too.) A denied path never dispatches.
    validate_request_path(request["file_path"], os_family=request["os_family"])

    manifest, artifact = run_playbook(request)        # agent runs on the endpoint
    ref = upload(manifest["incident_id"], manifest["filename"], artifact)
    intake_msg = {"artifact_ref": ref, "manifest": manifest}
    publish(SUBJECT_INTAKE, intake_msg)
    logger.info("Acquired %s from %s (incident %s) -> %s",
                manifest["filename"], manifest["host"], manifest["incident_id"], ref)
    return intake_msg


def _real_main():  # pragma: no cover - exercised in the live topology
    import asyncio
    import boto3
    import nats
    import requests

    nats_url = os.getenv("NATS_URL", "nats://nats:4222")
    # Authenticate as detchamber_node -- the broker is default-deny.
    nats_user = os.getenv("NATS_USER", "detchamber_node")
    nats_pass = os.getenv("NATS_PASS", "")
    bucket = os.getenv("QUARANTINE_BUCKET", "nexus-quarantine")
    s3 = boto3.client("s3", endpoint_url=os.getenv("QUARANTINE_S3_ENDPOINT"))
    executor_url = os.getenv("PLAYBOOK_EXECUTOR_URL", "http://n8n:5678/webhook/fallback-containment")

    def run_playbook(req: dict) -> Tuple[dict, bytes]:
        # Dispatch 05_acquire_artifact over the ssh_playbook_v1 executor; the agent
        # uploads the artifact itself and returns the manifest it wrote.
        r = requests.post(executor_url, json={**req, "action": "acquire_artifact"}, timeout=600)
        r.raise_for_status()
        payload = r.json()
        artifact = s3.get_object(Bucket=bucket, Key=payload["artifact_key"])["Body"].read()
        return payload["manifest"], artifact

    def upload(incident_id: str, filename: str, artifact: bytes) -> str:
        key = f"{incident_id}/{filename}.zip"
        s3.put_object(Bucket=bucket, Key=key, Body=artifact)
        return f"s3://{bucket}/{key}"

    async def _run():
        auth = {"user": nats_user, "password": nats_pass} if nats_user and nats_pass else {}
        nc = await nats.connect(nats_url, **auth)

        async def _cb(msg):
            try:
                req = json.loads(msg.data.decode())
                await asyncio.to_thread(
                    handle_acquire_request, req,
                    run_playbook=run_playbook, upload=upload,
                    publish=lambda subj, ev: asyncio.run(nc.publish(subj, json.dumps(ev).encode())))
                await msg.ack()
            except AcquisitionError as e:
                logger.error("refused acquisition: %s", e)
                await msg.ack()   # terminal -- never redeliver an unsafe request
            except Exception as e:
                logger.error("acquire handler error: %s", e)

        await nc.subscribe(SUBJECT_ACQUIRE, cb=_cb)
        logger.info("acquire worker online on %s", SUBJECT_ACQUIRE)
        while True:
            await asyncio.sleep(3600)

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    _real_main()
