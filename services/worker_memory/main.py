"""
worker_memory — the DFIR platform's adjudicated findings, on the swarm's bus.

This stack does not collect or store memory evidence. The platform does: it receives the
capture through its own one-way ingest, seals it, holds it in its enclave, and adjudicates
it with the toolkit both projects share. What reaches this worker is a **projection** — a
sealed, flat, allow-listed extract of the findings and their run context, and nothing else.
The RAM image never leaves the platform's enclave, so nothing here has to be trusted with it.

Flow:
  • the platform publishes a sealed projection to its DMZ edge (or an operator drops one
    on removable media — the seal is what makes both legitimate);
  • this worker pulls it, verifies the seal, and validates it against the contract in
    `dfir_platform` — seal first, so an unsealed bundle is never parsed for meaning;
  • it maps the bundle into the toolkit's own finding schema and runs it through the SAME
    enrichment core (`memory_analysis`) that produced enrichment when this stack ran the
    analyzer itself, so `nexus.memory.enrichment` keeps the shape the swarm already reads;
  • the swarm reasons over that flagged evidence and decides whether containment is
    warranted, initiating the established eradication playbooks.

A bundle that fails validation goes to the DLQ with its reason. It is never partially
accepted, and it is never silently dropped.

Retention, legal hold and purge of the underlying image are the platform's, along with the
audit record of each. Removing that duty from this stack is the point of the arrangement,
not an omission from it.

Configuration:
  NEXUS_PROJECTION_DIR / NEXUS_PROJECTION_URL   where projections come from (transport.py)
  NEXUS_PROJECTION_HMAC_KEY                     the shared seal key; required
  NEXUS_PROJECTION_ALLOW_UNSEALED               lab-only opt-out, default off
  NEXUS_PROJECTION_INTERVAL                     seconds between polls (default 30)
  NEXUS_PROJECTION_STATE                        ledger of bundle ids already published
"""
from __future__ import annotations

import json
import logging
import os

import memory_analysis as ma

import dfir_platform.contract as contract
import dfir_platform.transport as transport

logger = logging.getLogger("nexus-worker-memory")

ENRICHMENT_SUBJECT = "nexus.memory.enrichment"
# A refused projection is a fault worth seeing, not a log line to lose. The subject sits
# under the same DLQ tree the cognitive and archive faults use.
DLQ_SUBJECT = "nexus.dlq.memory_projection"

HMAC_KEY = os.getenv("NEXUS_PROJECTION_HMAC_KEY", "")
ALLOW_UNSEALED = os.getenv("NEXUS_PROJECTION_ALLOW_UNSEALED", "").lower() in ("1", "true", "yes")
POLL_INTERVAL = int(os.getenv("NEXUS_PROJECTION_INTERVAL", "30"))
STATE_PATH = os.getenv("NEXUS_PROJECTION_STATE", "/var/lib/nexus/projection_seen")


class SeenLedger:
    """Bundle ids already published, so re-delivery is idempotent.

    A projection's id is the hash of its payload, so the platform republishing a run — a
    retried dispatch, a re-mounted drop — yields the same id and produces no second
    enrichment. Persisted, because a restart is exactly when re-delivery happens.
    """

    def __init__(self, path: str):
        self.path = path
        self.ids = set()
        try:
            with open(path, encoding="utf-8") as fh:
                self.ids = {line.strip() for line in fh if line.strip()}
        except OSError:
            pass

    def __contains__(self, bundle_ref: str) -> bool:
        return bundle_ref in self.ids

    def add(self, bundle_ref: str) -> None:
        self.ids.add(bundle_ref)
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(bundle_ref + "\n")
        except OSError as e:  # noqa: BLE001 — a ledger we cannot persist still works in-process
            logger.warning("projection ledger not persisted (%s): %s", self.path, e)


async def handle_projection(raw: bytes, *, publish, dlq=None, seen=None,
                            hmac_key: str = None, allow_unsealed: bool = None) -> dict | None:
    """Process one projection → published enrichment.

    Returns the enrichment, or None when the bundle was already published. Raises
    `contract.ProjectionError` when the bundle is refused, after routing it to the DLQ —
    the caller decides whether to acknowledge the source, and a refused bundle should not
    be acknowledged away without a record of why.
    """
    key = HMAC_KEY if hmac_key is None else hmac_key
    unsealed_ok = ALLOW_UNSEALED if allow_unsealed is None else allow_unsealed
    try:
        bundle = contract.decode(raw)
        bundle_ref = contract.accept(bundle, key, allow_unsealed=unsealed_ok)
    except contract.ProjectionError as e:
        logger.error("projection refused: %s", e)
        if dlq is not None:
            await dlq(DLQ_SUBJECT, json.dumps({
                "source": "dfir_platform_projection",
                "reason": str(e),
                "bytes": len(raw or b""),
            }).encode())
        raise

    if seen is not None and bundle_ref in seen:
        logger.info("projection %s already published — skipping", bundle_ref[:12])
        return None

    desc = contract.descriptor(bundle)
    findings = contract.to_toolkit_findings(bundle)
    status = contract.to_status(bundle)

    enrichment = ma.to_enrichment(desc["incident_id"], desc["host"], desc["os_family"],
                                  findings, status)
    # Provenance the swarm's grounding controls key on: which platform run this came from,
    # and whether that run's custody seal verified on the platform side. A finding whose
    # chain of custody did not verify is still reportable, but it is not the same claim.
    enrichment["projection_id"] = bundle_ref
    enrichment["platform_run_id"] = desc["run_id"]
    enrichment["run_kind"] = desc["run_kind"]
    enrichment["custody_verified"] = desc["custody_verified"]

    await publish(ENRICHMENT_SUBJECT, json.dumps(enrichment).encode())
    if seen is not None:
        seen.add(bundle_ref)
    logger.info("memory enrichment published for %s from platform run %s (memory_threat=%s)",
                desc["incident_id"], desc["run_id"], enrichment["memory_threat"])
    return enrichment


async def drain(source, *, publish, dlq=None, seen=None,
                hmac_key: str = None, allow_unsealed: bool = None) -> int:
    """Consume everything the source currently holds. Returns the number published.

    A bundle is acknowledged only after its enrichment is on the bus, so a crash between
    the two leaves it held rather than lost. A refused bundle is acknowledged too — it has
    been recorded in the DLQ, and leaving it in place would refuse it again on every poll.
    """
    published = 0
    for ref, raw in source.poll():
        try:
            if await handle_projection(raw, publish=publish, dlq=dlq, seen=seen,
                                       hmac_key=hmac_key,
                                       allow_unsealed=allow_unsealed) is not None:
                published += 1
        except contract.ProjectionError:
            source.ack(ref)
            continue
        except Exception as e:  # noqa: BLE001 — a publish failure must not consume the bundle
            logger.error("projection %s not published (%s) — leaving it held", ref, e)
            continue
        source.ack(ref)
    return published


async def _run() -> None:
    """IO loop: poll the configured projection source, publish enrichment. Heavy clients
    imported lazily (kept off the test path)."""
    import asyncio

    import nats

    source = transport.from_env()
    seen = SeenLedger(STATE_PATH)

    nc = await nats.connect(os.getenv("NATS_URL", "nats://nats:4222"))
    js = nc.jetstream()

    async def _publish(subject, body):
        await js.publish(subject, body)

    logger.info("worker_memory online: %s every %ss → %s",
                type(source).__name__, POLL_INTERVAL, ENRICHMENT_SUBJECT)
    while True:
        try:
            await drain(source, publish=_publish, dlq=_publish, seen=seen)
        except transport.TransportError as e:
            logger.warning("projection source unavailable: %s", e)
        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    import asyncio
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_run())
