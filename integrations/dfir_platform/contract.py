"""
The projection contract — what the DFIR platform publishes and what this stack accepts.

The platform is the system of record for memory evidence: it collects, seals, stores and
adjudicates. This stack does none of that. It consumes a **projection** — a sealed, flat,
allow-listed extract of adjudicated findings and their run context — and turns it into swarm
enrichment. Evidence itself never crosses.

Direction is the whole design. The platform's enclave holds the images and initiates
everything; nothing dials into it. A projection is written outward to the platform's DMZ
edge and pulled from there by `transport.py`. This module never opens a socket — it decides
whether bytes that arrived are a legitimate projection, and what they mean.

Three properties are enforced here, because this is the only place they can be:

  **Sealed.** HMAC-SHA256 over the canonical payload, keyed by a secret shared out of band.
  An unsealed bundle is refused; the platform's own receiver refuses plaintext evidence for
  the same reason, and a consumer that quietly accepts unsealed input makes the seal
  decorative.

  **Flat.** Every value in the payload is a scalar or a list of scalars — there is no nested
  object anywhere. The payload is derived from a compromised host's RAM, so the question is
  not "did the platform send something reasonable" but "is there any shape in which it could
  carry something else". A structure with no containers has no smuggling channel, and that is
  cheaper to guarantee than to audit.

  **Allow-listed.** Fields are named exhaustively below, mirroring the platform's own model
  field names so that drift shows up as an unknown key rather than as a silent omission.
  `platform_drift.py` pins those names against a real checkout.

Pure stdlib, no third-party imports, and no dependency on the platform's tree at runtime.
"""
from __future__ import annotations

import hashlib
import hmac
import json

CONTRACT = "dfir-platform.projection"
VERSION = "1.0"

# The single shared verdict ladder. Owned by the toolkit's reporting/finding_schema.py and
# mirrored by the platform's cases/models.py; this is the third mirror and the drift tracker
# is what keeps all three in lockstep. An off-ladder verdict is refused rather than treated
# as non-TP: a verdict this consumer does not understand is not evidence of innocence.
VERDICTS = ("False Positive", "Likely False Positive", "Indeterminate",
            "Likely True Positive", "True Positive")

# Run context. Names mirror cases.CollectionRun / cases.Host so the platform side is a
# projection of its own model rather than a translation of it.
RUN_FIELDS = frozenset({
    "run_id", "incident_id", "investigation", "hostname", "machine_id", "platform",
    "run_kind", "overall_status", "tp_count", "compromised", "custody_verified",
    "collected_at", "toolkit_version",
})
RUN_REQUIRED = ("run_id", "incident_id", "hostname", "platform", "overall_status")

# Adjudicated findings. Deliberately narrower than cases.Finding: `raw` (the verbatim
# finding) and `subject_path` are excluded because both can carry bytes lifted out of the
# image, which is the one thing a projection must never move.
FINDING_FIELDS = frozenset({
    "finding_type", "target", "verdict", "confidence", "mitre", "tier", "source",
})
FINDING_REQUIRED = ("finding_type", "target", "verdict")

ENVELOPE_REQUIRED = ("contract", "version", "produced_at", "payload")

# A target is a PID, a path or an address. The platform caps its own at 512 characters;
# this is the ceiling past which a field has stopped being an identifier and started being
# a payload.
MAX_STR = 2048
MAX_FINDINGS = 10000


class ProjectionError(ValueError):
    """A bundle that is not a valid projection. Never raised for a bundle that is merely
    empty — a run with no findings is a legitimate, meaningful result."""


# ── canonical form, seal, identity ───────────────────────────────────────────
def canonical(payload) -> bytes:
    """The exact bytes the seal covers. Sorted keys and no whitespace, so producer and
    consumer agree on the encoding without agreeing on a serializer."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def seal_value(payload, key) -> str:
    """HMAC-SHA256 over the canonical payload. The platform computes this with the same
    key; the key is shared out of band and is not carried in the bundle."""
    k = key.encode() if isinstance(key, str) else key
    return hmac.new(k, canonical(payload), hashlib.sha256).hexdigest()


def bundle_id(bundle) -> str:
    """Stable identity of a projection: the hash of its payload. Two publications of the
    same run produce the same id, which is what makes re-delivery idempotent instead of a
    duplicate enrichment on the bus."""
    return hashlib.sha256(canonical((bundle or {}).get("payload"))).hexdigest()


def verify_seal(bundle, key, *, allow_unsealed: bool = False) -> tuple[bool, str]:
    """Check the bundle's seal. Fails closed: with no key configured, a bundle is refused
    unless the caller has explicitly opted out for a lab run."""
    seal = (bundle or {}).get("seal") or {}
    if not key:
        if allow_unsealed:
            return True, ""
        return False, "no projection HMAC key configured"
    if not isinstance(seal, dict):
        return False, "seal is not an object"
    if seal.get("alg") != "HMAC-SHA256":
        return False, f"unsupported seal alg {seal.get('alg')!r}"
    provided = str(seal.get("value") or "")
    if not provided:
        return False, "bundle carries no seal value"
    if not hmac.compare_digest(seal_value(bundle.get("payload"), key), provided):
        return False, "seal mismatch"
    return True, ""


# ── structural validation ────────────────────────────────────────────────────
def _scalar_ok(value) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _flat_ok(value) -> tuple[bool, str]:
    """A value is acceptable when it is a scalar, or a list of scalars. Anything that can
    contain a key/value structure is refused — that is the no-smuggling invariant."""
    if isinstance(value, str) and len(value) > MAX_STR:
        return False, f"string exceeds {MAX_STR} characters"
    if _scalar_ok(value):
        return True, ""
    if isinstance(value, list):
        for item in value:
            if not _scalar_ok(item):
                return False, "list contains a non-scalar"
            if isinstance(item, str) and len(item) > MAX_STR:
                return False, f"string exceeds {MAX_STR} characters"
        return True, ""
    return False, f"nested {type(value).__name__} is not permitted in a projection"


def _check_object(obj, allowed, required, label) -> str:
    if not isinstance(obj, dict):
        return f"{label} is not an object"
    unknown = sorted(set(obj) - allowed)
    if unknown:
        return f"{label} carries unknown field(s): {', '.join(unknown)}"
    for field in required:
        if obj.get(field) in (None, ""):
            return f"{label} missing required field {field}"
    for field, value in obj.items():
        ok, why = _flat_ok(value)
        if not ok:
            return f"{label}.{field}: {why}"
    return ""


def validate(bundle) -> tuple[bool, str]:
    """Full structural check of a decoded bundle. Returns (ok, reason); the reason is the
    first failure, because a bundle is either conformant or refused — there is no partial
    acceptance of a projection."""
    if not isinstance(bundle, dict):
        return False, "bundle is not an object"
    for field in ENVELOPE_REQUIRED:
        if field not in bundle:
            return False, f"envelope missing {field}"
    if bundle.get("contract") != CONTRACT:
        return False, f"not a {CONTRACT} bundle"
    major = str(bundle.get("version") or "").split(".")[0]
    if major != VERSION.split(".")[0]:
        return False, f"unsupported contract version {bundle.get('version')!r}"

    payload = bundle.get("payload")
    if not isinstance(payload, dict):
        return False, "payload is not an object"
    unknown = sorted(set(payload) - {"run", "findings"})
    if unknown:
        return False, f"payload carries unknown section(s): {', '.join(unknown)}"

    why = _check_object(payload.get("run"), RUN_FIELDS, RUN_REQUIRED, "run")
    if why:
        return False, why

    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        return False, "findings is not a list"
    if len(findings) > MAX_FINDINGS:
        return False, f"findings exceeds {MAX_FINDINGS} entries"
    for i, finding in enumerate(findings):
        why = _check_object(finding, FINDING_FIELDS, FINDING_REQUIRED, f"findings[{i}]")
        if why:
            return False, why
        verdict = finding.get("verdict")
        if verdict not in VERDICTS:
            return False, f"findings[{i}] verdict {verdict!r} is not on the shared ladder"
        mitre = finding.get("mitre")
        if mitre is not None and not isinstance(mitre, (list, str)):
            return False, f"findings[{i}] mitre must be a list or a string"
    return True, ""


def accept(bundle, key, *, allow_unsealed: bool = False) -> str:
    """Seal-then-structure, the order that matters: an unsealed bundle is not parsed for
    meaning. Returns the bundle id; raises ProjectionError on refusal."""
    ok, why = verify_seal(bundle, key, allow_unsealed=allow_unsealed)
    if not ok:
        raise ProjectionError(f"projection seal: {why}")
    ok, why = validate(bundle)
    if not ok:
        raise ProjectionError(f"projection schema: {why}")
    return bundle_id(bundle)


def decode(raw: bytes) -> dict:
    """Decode transport bytes into a bundle object. JSON errors surface as ProjectionError
    so a caller has one exception type to handle for 'this is not a projection'."""
    try:
        return json.loads(raw.decode("utf-8-sig", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProjectionError(f"projection decode: {e}") from e


# ── adaptation to the shape the enrichment core already speaks ───────────────
# worker_memory's pure core (memory_analysis.py) consumes the toolkit's own finding schema
# — Type / Target / Verdict / MITRE — and a _status.json. It gets exactly that here, so
# the swarm-facing enrichment is produced by the same code that produced it when this stack
# ran the analyzer itself, and nothing downstream on the bus changes.
def to_toolkit_findings(bundle) -> list:
    """Projection findings in the toolkit's shared finding schema."""
    out = []
    for finding in (bundle or {}).get("payload", {}).get("findings", []) or []:
        mitre = finding.get("mitre")
        if isinstance(mitre, list):
            mitre = ",".join(str(m) for m in mitre if m)
        out.append({
            "Type": finding.get("finding_type"),
            "Target": finding.get("target"),
            "Verdict": finding.get("verdict"),
            "MITRE": mitre or "",
        })
    return out


def to_status(bundle) -> dict:
    """The run's `_status.json` equivalent: the platform's own adjudicated TP count and
    overall status, not a count recomputed here."""
    run = (bundle or {}).get("payload", {}).get("run", {}) or {}
    return {"status": run.get("overall_status", ""),
            "tp_count": int(run.get("tp_count", 0) or 0)}


def descriptor(bundle) -> dict:
    """Who this projection is about, in the terms the enrichment envelope uses."""
    run = (bundle or {}).get("payload", {}).get("run", {}) or {}
    return {
        "incident_id": str(run.get("incident_id", "")),
        "host": str(run.get("hostname", "")),
        "os_family": str(run.get("platform", "")),
        "run_id": run.get("run_id"),
        "run_kind": str(run.get("run_kind", "")),
        "custody_verified": bool(run.get("custody_verified", False)),
        "compromised": bool(run.get("compromised", False)),
    }
