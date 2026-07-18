"""
model_steward - IO shell around the pure promotion core in steward.py.

Runs on the serving plane with read-only registry credentials. Subscribes to
`nexus.models.promote`, and for each message: pulls the version prefix from
the registry bucket, hands it to `handle_promotion` (verify -> pin -> restart
unit -> probe -> rollback on failure), and publishes the resulting
`nexus.models.promoted` / `nexus.models.rejected` answer.

Environment:
    NATS_URL / NATS_USER / NATS_PASSWORD   steward_node NATS account
    MODEL_REGISTRY_ENDPOINT                MinIO/S3 endpoint
    MODEL_REGISTRY_BUCKET                  registry bucket (nexus-model-registry)
    MODEL_REGISTRY_ACCESS_KEY / _SECRET_KEY  read-only credentials
    MODEL_STORE_DIR                        local versioned model store
    MODEL_UNITS                            JSON {model_id: {unit, health}} map
    STEWARD_PROBE_RETRIES / _INTERVAL_S    readiness probe budget (12 x 10s)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
import urllib.request
from pathlib import Path

import steward as st

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] [steward] %(message)s")
logger = logging.getLogger("nexus-model-steward")

REGISTRY_BUCKET = os.getenv("MODEL_REGISTRY_BUCKET", "nexus-model-registry")
STORE_DIR = os.getenv("MODEL_STORE_DIR", "/opt/sentinel-nexus/models/registry")
PROBE_RETRIES = int(os.getenv("STEWARD_PROBE_RETRIES", "12"))
PROBE_INTERVAL_S = float(os.getenv("STEWARD_PROBE_INTERVAL_S", "10"))

# Which systemd unit serves each model, and where its readiness probe answers.
DEFAULT_MODEL_UNITS = {
    "model_b": {"unit": "vllm-network.service", "health": "http://localhost:8001/health"},
    "model_c": {"unit": "vllm-inference.service", "health": "http://localhost:8000/health"},
    "model_d": {"unit": "vllm-critic.service", "health": "http://localhost:8002/health"},
}


def model_units() -> dict:
    raw = os.getenv("MODEL_UNITS", "")
    if not raw:
        return DEFAULT_MODEL_UNITS
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.error("MODEL_UNITS is not valid JSON; using defaults")
        return DEFAULT_MODEL_UNITS


def _s3_client():
    import boto3
    return boto3.client(
        "s3",
        endpoint_url=os.getenv("MODEL_REGISTRY_ENDPOINT", "http://minio-service:9000"),
        aws_access_key_id=os.getenv("MODEL_REGISTRY_ACCESS_KEY", ""),
        aws_secret_access_key=os.getenv("MODEL_REGISTRY_SECRET_KEY", ""),
    )


def fetch_version(model_id: str, version: str, dest_dir, s3=None,
                  bucket: str = REGISTRY_BUCKET) -> int:
    """Pull every object under the version prefix into dest_dir."""
    s3 = s3 or _s3_client()
    prefix = f"{model_id}/{version}/"
    dest_dir = Path(dest_dir)
    pulled = 0
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            rel = obj["Key"][len(prefix):]
            if not rel:
                continue
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            s3.download_file(bucket, obj["Key"], str(target))
            pulled += 1
    if pulled == 0:
        raise FileNotFoundError(f"registry prefix {prefix} is empty")
    return pulled


def registry_reachable() -> bool:
    try:
        _s3_client().head_bucket(Bucket=REGISTRY_BUCKET)
        return True
    except Exception:
        return False


def _probe(url: str) -> bool:
    for _ in range(PROBE_RETRIES):
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(PROBE_INTERVAL_S)
    return False


def activate(model_id: str, current_path) -> bool:
    """Restart the model's serving unit and wait for its readiness probe.
    A model without a configured unit verifies + pins only (its consumer
    resolves the store's `current` path on next start)."""
    entry = model_units().get(model_id)
    if entry is None:
        logger.info("%s: no serving unit configured; pin-only promotion", model_id)
        return True
    unit = entry["unit"]
    logger.info("%s: restarting %s (current -> %s)", model_id, unit, current_path)
    rc = subprocess.run(["systemctl", "restart", unit]).returncode
    if rc != 0:
        logger.error("%s: systemctl restart %s failed (rc=%d)", model_id, unit, rc)
        return False
    ok = _probe(entry["health"])
    logger.info("%s: readiness probe %s", model_id, "passed" if ok else "FAILED")
    return ok


async def run() -> None:
    import nats

    store = st.LocalStore(STORE_DIR)
    logger.info("boot: %s", json.dumps(st.boot_status(store, registry_reachable())))

    connect_kwargs: dict = {"servers": [os.getenv("NATS_URL", "nats://nats:4222")]}
    user, password = os.getenv("NATS_USER", ""), os.getenv("NATS_PASSWORD", "")
    if user and password:
        connect_kwargs.update(user=user, password=password)
    nc = await nats.connect(**connect_kwargs)
    logger.info("subscribed %s", st.SUBJECT_PROMOTE)

    async def on_promote(msg):
        try:
            payload = json.loads(msg.data.decode())
        except json.JSONDecodeError:
            logger.error("unparseable promote message dropped")
            return
        bucket = payload.get("bucket") or REGISTRY_BUCKET
        loop = asyncio.get_running_loop()
        ack = await loop.run_in_executor(
            None,
            lambda: st.handle_promotion(
                payload, store,
                fetch=lambda m, v, d: fetch_version(m, v, d, bucket=bucket),
                activate=activate,
            ),
        )
        await nc.publish(ack["subject"], json.dumps(ack["body"]).encode())
        logger.info("answered %s for %s/%s: %s", ack["subject"],
                    ack["body"]["model_id"], ack["body"]["version"],
                    ack["body"]["reason"])

    await nc.subscribe(st.SUBJECT_PROMOTE, cb=on_promote)
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(run())
