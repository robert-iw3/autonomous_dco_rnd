"""
Acquisition agent -- a separate lightweight on-host agent (Phase 8).

Endpoints can't be reached inbound, so this agent works OUTBOUND only, mirroring
how the sensors already ship telemetry:

  1. POLL  GET  {TASKS_ENDPOINT}    -- ask ingress for pending acquisition tasks
  2. VERIFY                         -- check Nexus's HMAC signature on the task; the
                                       ingress only ROUTES, the host owns the secret
  3. ACQUIRE                        -- run acquire_core locally (validate path, read
                                       bytes, zip, sha256, manifest -- NEVER execute)
  4. TRANSMIT POST {ARTIFACT_ENDPOINT} -- send the zipped artifact to core_ingress
                                       over HTTPS with JWT + HMAC + the manifest
                                       headers; ingress verifies custody, stores it
                                       in the quarantine bucket, emits the intake.
"""

import hashlib
import hmac
import json
import os
import time
from typing import Tuple

import acquire_core

TASKS_ENDPOINT = "/api/v1/tasks"
ARTIFACT_ENDPOINT = "/api/v1/artifact"
HDR_ARTIFACT_HMAC = "X-Artifact-HMAC"


class TaskSignatureError(Exception):
    """Raised when a polled task does not carry a valid Nexus signature."""


def _sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _canonical_task(task: dict) -> bytes:
    # Byte-identical to the signer (operations/agent/response_executor._canonical,
    # mirrored in worker_soar's agent_task::canonical): compact, key-sorted JSON
    # with `signature` removed.
    body = {k: task[k] for k in sorted(task) if k != "signature"}
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


def verify_task(task: dict, secret: bytes) -> None:
    """Raise TaskSignatureError unless the task carries Nexus's HMAC signature.

    The ingress only ROUTES tasks; the signature is verified HERE, on the host that
    owns the secret (NEXUS_TASK_SECRET, the key worker_soar signs with). Fails closed
    when no secret is configured -- an unverified task is never acted on.
    """
    if not secret:
        raise TaskSignatureError("NEXUS_TASK_SECRET unset -- cannot verify task signature")
    provided = task.get("signature", "")
    if not provided or not hmac.compare_digest(provided, _sign(secret, _canonical_task(task))):
        raise TaskSignatureError("task signature invalid -- refusing to acquire")


def acquire_and_build_upload(task: dict, *, hmac_secret: bytes) -> Tuple[dict, bytes]:
    """Acquire the task's file and build the authenticated HTTPS upload.

    Returns (headers, body): the zipped artifact plus the chain-of-custody manifest
    headers and an HMAC over the body that ingress verifies with the shared secret.
    Raises AcquisitionError (from acquire_core) on an unsafe path / oversize file.
    """
    manifest, artifact = acquire_core.acquire(
        task["file_path"], incident_id=task["incident_id"],
        host=task["host"], os_family=task["os_family"])
    headers = {
        "X-Incident-Id": manifest["incident_id"],
        "X-Sensor-Id": task["host"],
        "X-Os-Family": manifest["os_family"],
        "X-Artifact-Filename": manifest["filename"],
        "X-Artifact-SHA256": manifest["sha256"],
        "X-Artifact-Size": str(manifest["size"]),
        "X-Src-Path": manifest["src_path"],
        # Provenance the intake manifest requires; intake stamps its own receipt
        # time when this is absent (the ingress relay list must forward it).
        "X-Acquired-At": manifest["acquired_at"],
        HDR_ARTIFACT_HMAC: _sign(hmac_secret, artifact),
    }
    return headers, artifact


# ── Production poll/transmit loop (lazy; not needed by the test path) ─────────
def _real_main():  # pragma: no cover - exercised on a live endpoint
    import requests

    ingress = os.getenv("INGRESS_URL", "https://nexus-edge:8080")
    token = os.getenv("INGRESS_JWT", "")
    sensor_id = os.getenv("NEXUS_SENSOR_ID", os.uname().nodename)
    secret = os.getenv("INTEGRITY_HMAC_SECRET", "").encode()
    task_secret = os.getenv("NEXUS_TASK_SECRET", "").encode()
    poll_interval = int(os.getenv("ACQUIRE_POLL_INTERVAL", "15"))
    sess = requests.Session()

    while True:
        try:
            r = sess.get(f"{ingress}{TASKS_ENDPOINT}", params={"sensor_id": sensor_id},
                         headers={"Authorization": f"Bearer {token}"}, timeout=30)
            r.raise_for_status()
            for task in r.json().get("tasks", []):
                try:
                    # Nexus signs the task; the ingress only routes it. Verify before
                    # the task is acted on -- an unsigned task never reads a file.
                    verify_task(task, task_secret)
                    headers, body = acquire_and_build_upload(task, hmac_secret=secret)
                    headers["Authorization"] = f"Bearer {token}"
                    sess.post(f"{ingress}{ARTIFACT_ENDPOINT}", data=body, headers=headers, timeout=600)
                except (TaskSignatureError, acquire_core.AcquisitionError) as e:
                    # Report the refusal; never retry an unsigned task or unsafe path.
                    sess.post(f"{ingress}{TASKS_ENDPOINT}/nack",
                              json={"task": task, "error": str(e)},
                              headers={"Authorization": f"Bearer {token}"}, timeout=30)
        except Exception:
            pass
        time.sleep(poll_interval)


if __name__ == "__main__":  # pragma: no cover
    _real_main()
