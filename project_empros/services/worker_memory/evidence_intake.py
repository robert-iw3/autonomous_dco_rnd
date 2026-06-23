"""Verified intake of IR evidence from the Zero-Trust gateway.

Memory/IR evidence is its own data class. The on-host agent streams it to
core_ingress `/api/v1/evidence` (JWT + HMAC-SHA256 over the body + SHA-256
chain-of-custody); the gateway verifies, streams it into the WORM S3 archive, and
publishes a small verified handle on `nexus.memory.intake`. worker_memory pulls the
verified object and re-checks the custody hash before the analyzer runs — no
unverified side channel into analysis.
"""
from __future__ import annotations

import hashlib
import hmac

INTAKE_SUBJECT = "nexus.memory.intake"          # gateway → worker_memory (verified handle)
ENRICHMENT_SUBJECT = "nexus.memory.enrichment"  # worker_memory → swarm

EVIDENCE_KINDS = {"memory_image", "findings", "status", "custody"}
REQUIRED_HANDLE = ("incident_id", "host", "os_family", "kind", "sha256", "s3_key")


def verify_sha256(body: bytes, expected_hex: str) -> bool:
    """Chain-of-custody: bytes must hash to the sealed manifest sha256."""
    if not expected_hex:
        return False
    return hmac.compare_digest(hashlib.sha256(body).hexdigest(), str(expected_hex).lower())


def verify_hmac(secret, body: bytes, provided_hex: str) -> bool:
    """HMAC-SHA256 over the body — the primitive the gateway enforces on upload
    (parity with core_ingress verify_artifact_hmac); kept here for spec + tests."""
    if not secret or not provided_hex:
        return False
    key = secret.encode() if isinstance(secret, str) else secret
    mac = hmac.new(key, body, hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(mac, str(provided_hex).lower())
    except (TypeError, ValueError):
        return False


def missing_handle_fields(handle: dict) -> list:
    h = {str(k).lower() for k in (handle or {})}
    return [r for r in REQUIRED_HANDLE if r not in h]


def parse_handle(handle: dict) -> dict:
    """Normalize a verified intake handle (case-insensitive) to the descriptor
    worker_memory acts on."""
    def g(name):
        for k, v in (handle or {}).items():
            if str(k).lower() == name:
                return v
        return None
    return {f: (str(g(f)) if g(f) is not None else "") for f in REQUIRED_HANDLE}


def verify_pulled_object(body: bytes, handle: dict) -> tuple[bool, str]:
    """Re-check a WORM object pulled for analysis against its verified handle:
    known kind + custody sha256. Returns (ok, reason)."""
    miss = missing_handle_fields(handle)
    if miss:
        return False, f"handle missing: {','.join(miss)}"
    kind = parse_handle(handle)["kind"]
    if kind not in EVIDENCE_KINDS:
        return False, f"unknown evidence kind {kind!r}"
    if not verify_sha256(body, parse_handle(handle)["sha256"]):
        return False, "sha256 custody mismatch"
    return True, ""
