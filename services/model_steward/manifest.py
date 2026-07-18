"""
Registry manifest contract - the serving plane's verification side.

The steward trusts nothing the promote message says: every version is judged
by its `manifest.json` pulled from the registry bucket, and every artifact
byte is re-hashed against `sha384_manifest` before it can be swapped in.
No verifiable manifest, no complete gate set, no scores - no swap.

The vocabulary here (schema name, model ids, artifact types, quants, required
gates, version format) is the contract shared with the training-plane
publisher (`mlops/scripts/13_publish_model.py`); the registry contract tests
pin the two sides together.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

MANIFEST_SCHEMA = "model_manifest_v1"
MODEL_IDS = {"model_a", "model_b", "model_c", "model_d"}
ARTIFACT_TYPES = {"merged_weights", "lora_adapter", "onnx"}
VALID_QUANT = {"nf4-4bit", "fp16", "bf16", "onnx-int8"}
REQUIRED_GATES = {"tier0", "garak", "pyrit", "regression", "alignment"}
VERSION_RE = re.compile(r"^\d{8}T\d{4,6}-[A-Za-z0-9]{2,40}$")


def validate_manifest(manifest: dict) -> list:
    """Contract errors ([] == acceptable). Mirrors the publisher's validation;
    the serving side re-enforces what the training side claims."""
    m = manifest or {}
    errs = []
    if m.get("schema") != MANIFEST_SCHEMA:
        errs.append(f"schema must be {MANIFEST_SCHEMA}, got {m.get('schema')!r}")
    if m.get("model_id") not in MODEL_IDS:
        errs.append(f"unknown model_id {m.get('model_id')!r}")
    if not VERSION_RE.match(str(m.get("version", ""))):
        errs.append(f"malformed version {m.get('version')!r}")
    if m.get("artifact_type") not in ARTIFACT_TYPES:
        errs.append(f"unknown artifact_type {m.get('artifact_type')!r}")
    if m.get("quant") not in VALID_QUANT:
        errs.append(f"unknown quant {m.get('quant')!r}")
    sha = m.get("sha384_manifest")
    if not isinstance(sha, dict) or not sha:
        errs.append("sha384_manifest must be a non-empty {path: sha384} map")
    else:
        bad = [p for p, d in sha.items()
               if not re.fullmatch(r"[0-9a-f]{96}", str(d))]
        errs += [f"sha384_manifest[{p}]: not a SHA-384 hex digest" for p in bad]
    scores = m.get("gate_scores")
    if not isinstance(scores, dict) or not scores:
        errs.append("gate_scores must be a non-empty {metric: float} map")
    elif not all(isinstance(v, (int, float)) for v in scores.values()):
        errs.append("gate_scores values must be numeric")
    missing_gates = REQUIRED_GATES - set(m.get("gates_passed") or [])
    if missing_gates:
        errs.append(f"gates_passed missing {sorted(missing_gates)}")
    if not m.get("rsi_cycle_id"):
        errs.append("rsi_cycle_id required (provenance link into the RSI ledger)")
    if not m.get("promoted_at"):
        errs.append("promoted_at required")
    return errs


def _file_sha384(path: Path) -> str:
    h = hashlib.sha384()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_artifacts(manifest: dict, local_dir) -> "tuple[bool, list]":
    """Re-hash every pulled artifact against the manifest's SHA-384 map.

    Fails on a digest mismatch, a file the manifest promises but the pull
    lacks, or a file present on disk the manifest never vouched for (an
    unvouched file next to the weights is exactly what the hash map exists
    to catch).
    """
    local_dir = Path(local_dir)
    expected = dict((manifest or {}).get("sha384_manifest") or {})
    errors = []
    on_disk = {p.relative_to(local_dir).as_posix()
               for p in local_dir.rglob("*") if p.is_file()}
    on_disk.discard("manifest.json")
    for rel, digest in expected.items():
        if rel not in on_disk:
            errors.append(f"{rel}: promised by manifest, missing from pull")
        elif _file_sha384(local_dir / rel) != digest:
            errors.append(f"{rel}: SHA-384 mismatch")
    for rel in sorted(on_disk - set(expected)):
        errors.append(f"{rel}: present on disk but not vouched for by the manifest")
    return (not errors), errors
