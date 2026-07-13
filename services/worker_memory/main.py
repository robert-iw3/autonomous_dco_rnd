"""worker_memory — orchestration shell (thin IO around the pure cores).

Flow (all evidence is gateway-verified; no side channel):
  • core_ingress /api/v1/evidence verifies (JWT + HMAC + SHA-256 custody), streams
    the RAM image into the WORM archive, and publishes a verified handle on
    `nexus.memory.intake`;
  • this worker pulls the verified object, re-checks the custody hash, runs the
    EXISTING analyzer (Analyze-Memory{.ps1,-Linux.sh} --adjudicate) in an ephemeral
    container, writes findings/status to the WORM record, and publishes
    `nexus.memory.enrichment` so the swarm makes the verdict;
  • on conclusion an OPERATOR purges the (GOVERNANCE-locked) image via
    `handle_operator_cleanup` — the COMPLIANCE record persists.

Pure logic is in memory_analysis / evidence_intake; this file is IO only.
Air-gapped: toolkit + symbols staged offline.
"""
from __future__ import annotations

import glob
import json
import logging
import os
import subprocess
import tempfile

import memory_analysis as ma
import evidence_intake as ei

logger = logging.getLogger("nexus-worker-memory")

ARCHIVE_BUCKET = os.getenv("NEXUS_MEMORY_ARCHIVE_BUCKET", "nexus-ir-memory-archive")
KMS_KEY_ID = os.getenv("NEXUS_MEMORY_KMS_KEY_ID", "")
RETAIN_DAYS = int(os.getenv("NEXUS_MEMORY_RETAIN_DAYS", "365"))
CONTAINER_RUNTIME = os.getenv("NEXUS_CONTAINER_RUNTIME", "podman")
FETCH_SYMBOLS = os.getenv("NEXUS_MEM_FETCH_SYMBOLS", "").lower() in ("1", "true", "yes")


def run_memory_analyzer(os_family: str, image_local_path: str, host_folder: str):
    """Run the EXISTING analyzer in an ephemeral, network-less container; return
    (findings, status) read back from its shared-schema output."""
    analysis_image = ma.select_analysis_image(os_family)
    analyzer = ma.build_analyzer_command(
        os_family, "/image/" + os.path.basename(image_local_path), "/reports",
        fetch_symbols=FETCH_SYMBOLS)
    cmd = [CONTAINER_RUNTIME, "run", "--rm", "--network=none",
           "-v", f"{image_local_path}:/image/{os.path.basename(image_local_path)}:ro",
           "-v", f"{host_folder}:/reports", "-w", "/opt/ir-toolkit/playbooks",
           analysis_image, *analyzer]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except Exception as e:  # noqa: BLE001 — read whatever the analyzer wrote
        logger.warning("memory analyzer container error: %s", e)
    return _read_findings(host_folder), _read_status(host_folder)


def _read_findings(host_folder: str) -> list:
    matches = sorted(glob.glob(os.path.join(host_folder, "Memory_Findings_*.json")))
    if not matches:
        return []
    try:
        with open(matches[-1], encoding="utf-8-sig", errors="replace") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else data.get("findings", [])
    except (OSError, json.JSONDecodeError):
        return []


def _read_status(host_folder: str) -> dict:
    try:
        with open(os.path.join(host_folder, "_status.json"), encoding="utf-8-sig",
                  errors="replace") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _archive_record(s3, incident_id: str, host: str, findings: list, status: dict) -> None:
    """Write the adjudicated findings + status to the WORM record (COMPLIANCE).
    The image is already in WORM — the gateway streamed it on verified upload."""
    for kind, body in (("findings", json.dumps(findings).encode()),
                       ("status", json.dumps(status).encode())):
        s3.put_object(Body=body, **ma.s3_object_lock_params(
            ARCHIVE_BUCKET, ma.archive_key(incident_id, host, kind),
            RETAIN_DAYS, KMS_KEY_ID, kind=kind))


async def handle_intake(handle: dict, *, s3, publish) -> dict:
    """Process one verified intake handle → published enrichment. `s3` (get_object/
    put_object) and `publish(subject, bytes)` are injected for testability."""
    desc = ei.parse_handle(handle)
    incident_id, host, os_family = desc["incident_id"], desc["host"], desc["os_family"]

    body = _pull_object(s3, desc["s3_key"])
    ok, reason = ei.verify_pulled_object(body, handle)
    if not ok:
        logger.error("evidence custody check failed for %s (%s) — refusing analysis",
                     incident_id, reason)
        raise ei_custody_error(reason)

    local = _write_temp(body, desc["s3_key"])
    host_folder = tempfile.mkdtemp(prefix=f"nexus-mem-{incident_id}-")
    try:
        findings, status = run_memory_analyzer(os_family, local, host_folder)
        try:
            _archive_record(s3, incident_id, host, findings, status)
        except Exception as e:  # noqa: BLE001 — archival must not block the verdict
            logger.error("WORM record write failed (non-fatal to enrichment): %s", e)
        enrichment = ma.to_enrichment(incident_id, host, os_family, findings, status)
        await publish(ei.ENRICHMENT_SUBJECT, json.dumps(enrichment).encode())
        logger.info("memory enrichment published for %s (memory_threat=%s)",
                    incident_id, enrichment["memory_threat"])
        return enrichment
    finally:
        _cleanup(local)
        _cleanup_dir(host_folder)


async def handle_operator_cleanup(event: dict, *, s3, audit) -> dict:
    """Operator-gated purge of the GOVERNANCE-locked RAM image once the
    investigation is concluded. Records a tamper-evident audit line. The COMPLIANCE
    findings/status/custody record is never touched. Never autonomous."""
    incident_id = str(event.get("incident_id", ""))
    host = str(event.get("host", ""))
    operator = str(event.get("operator", ""))
    if not operator:
        raise PermissionError("operator identity required to purge a memory image")
    if not ma.cleanup_eligible(event.get("investigation_status", "")):
        raise PermissionError("investigation not concluded — image purge refused")
    key = ma.archive_key(incident_id, host, "image")
    s3.delete_object(**ma.operator_delete_image_params(ARCHIVE_BUCKET, key))
    record = ma.deletion_audit_record(incident_id, host, key, operator)
    await audit(json.dumps(record).encode())
    logger.warning("operator %s purged memory image %s (incident %s)", operator, key, incident_id)
    return record


def ei_custody_error(reason: str) -> Exception:
    return ValueError(f"evidence custody: {reason}")


def _pull_object(s3, key: str) -> bytes:
    return s3.get_object(Bucket=ARCHIVE_BUCKET, Key=key)["Body"].read()


def _write_temp(body: bytes, key: str) -> str:
    suffix = "." + ma.image_format(key) if ma.image_format(key) else ".raw"
    fd, path = tempfile.mkstemp(prefix="nexus-mem-", suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(body)
    return path


def _cleanup(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _cleanup_dir(path: str) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)


async def _run() -> None:
    """IO loop: subscribe to the verified intake + operator-cleanup subjects and
    dispatch to the handlers. Heavy clients imported lazily (kept off the test path)."""
    import nats
    import boto3

    nc = await nats.connect(os.getenv("NATS_URL", "nats://nats:4222"))
    js = nc.jetstream()
    s3 = boto3.client("s3", endpoint_url=os.getenv("S3_ENDPOINT_URL") or None)

    async def _publish(subject, body):
        await js.publish(subject, body)

    async def _audit(body):
        await js.publish("nexus.memory.cleanup.audit", body)

    async def _on_intake(msg):
        await handle_intake(json.loads(msg.data), s3=s3, publish=_publish)
        await msg.ack()

    async def _on_cleanup(msg):
        await handle_operator_cleanup(json.loads(msg.data), s3=s3, audit=_audit)
        await msg.ack()

    await js.subscribe(ei.INTAKE_SUBJECT, durable="worker_memory_intake", cb=_on_intake)
    await js.subscribe("nexus.memory.cleanup", durable="worker_memory_cleanup", cb=_on_cleanup)
    logger.info("worker_memory online: %s + nexus.memory.cleanup", ei.INTAKE_SUBJECT)
    import asyncio as _a
    await _a.Event().wait()


if __name__ == "__main__":
    import asyncio
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_run())
