"""
Acquisition agent -- a separate lightweight on-host agent (Phase 8).

Endpoints can't be reached inbound, so this agent works OUTBOUND only, mirroring
how the sensors already ship telemetry:

  1. POLL  GET  {TASKS_ENDPOINT}    -- ask ingress for pending acquisition tasks
  2. ACQUIRE                        -- run acquire_core locally (validate path, read
                                       bytes, zip, sha256, manifest -- NEVER execute)
  3. TRANSMIT POST {ARTIFACT_ENDPOINT} -- send the zipped artifact to core_ingress
                                       over HTTPS with JWT + HMAC + the manifest
                                       headers; ingress verifies custody, stores it
                                       in the quarantine bucket, emits the intake.
"""

import hashlib
import hmac
import os
import time
from typing import Tuple

import acquire_core

TASKS_ENDPOINT = "/api/v1/tasks"
ARTIFACT_ENDPOINT = "/api/v1/artifact"
HDR_ARTIFACT_HMAC = "X-Artifact-HMAC"


def _sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


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
    poll_interval = int(os.getenv("ACQUIRE_POLL_INTERVAL", "15"))
    sess = requests.Session()

    while True:
        try:
            r = sess.get(f"{ingress}{TASKS_ENDPOINT}", params={"sensor_id": sensor_id},
                         headers={"Authorization": f"Bearer {token}"}, timeout=30)
            r.raise_for_status()
            for task in r.json().get("tasks", []):
                try:
                    headers, body = acquire_and_build_upload(task, hmac_secret=secret)
                    headers["Authorization"] = f"Bearer {token}"
                    sess.post(f"{ingress}{ARTIFACT_ENDPOINT}", data=body, headers=headers, timeout=600)
                except acquire_core.AcquisitionError as e:
                    # Report the refusal; never retry an unsafe path.
                    sess.post(f"{ingress}{TASKS_ENDPOINT}/nack",
                              json={"task": task, "error": str(e)},
                              headers={"Authorization": f"Bearer {token}"}, timeout=30)
        except Exception:
            pass
        time.sleep(poll_interval)


if __name__ == "__main__":  # pragma: no cover
    _real_main()
