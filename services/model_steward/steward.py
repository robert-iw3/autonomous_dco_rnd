"""
model_steward core - pull/verify/swap/probe/rollback state machine.

The serving plane's only writer of model weights. Promotion is pull-based:
the training plane publishes `nexus.models.promote` and this agent pulls the
version from the registry, verifies the manifest contract plus every artifact
hash, atomically re-pins the model's `current` symlink, restarts the serving
unit, probes readiness, and answers `nexus.models.promoted` or
`nexus.models.rejected`. A failed probe re-pins the previous version - the
same mechanism as promotion, in reverse.

Serving fails open, promotion fails closed: at boot the steward never blocks
serving on registry availability - the last pinned version keeps serving even
with the registry unreachable - but no version is ever pinned without a fully
verified manifest.

Local store layout (per model):
    <store>/<model_id>/versions/<version>/   pulled artifacts + manifest.json
    <store>/<model_id>/current  -> versions/<version>
    <store>/<model_id>/previous -> versions/<version>   (rollback target)

All IO (registry fetch, unit restart, readiness probe, NATS) is injected so
the whole flow is provable offline.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import shutil
from pathlib import Path

import manifest as mf

logger = logging.getLogger("nexus-model-steward")

SUBJECT_PROMOTE = "nexus.models.promote"
SUBJECT_PROMOTED = "nexus.models.promoted"
SUBJECT_REJECTED = "nexus.models.rejected"

PROMOTE_SCHEMA = "models_promote_v1"
ACK_SCHEMA = "models_ack_v1"

KEEP_VERSIONS = int(os.getenv("STEWARD_KEEP_VERSIONS", "3"))


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def parse_promote(payload: dict) -> "tuple[dict | None, str]":
    """Normalize a promote message; (None, reason) when malformed."""
    p = payload or {}
    if p.get("schema") != PROMOTE_SCHEMA:
        return None, f"unknown promote schema {p.get('schema')!r}"
    if p.get("model_id") not in mf.MODEL_IDS:
        return None, f"unknown model_id {p.get('model_id')!r}"
    if not mf.VERSION_RE.match(str(p.get("version", ""))):
        return None, f"malformed version {p.get('version')!r}"
    return {"model_id": p["model_id"], "version": p["version"],
            "bucket": p.get("bucket", "")}, ""


class LocalStore:
    """Versioned local model store with atomic current/previous pins."""

    def __init__(self, root):
        self.root = Path(root)

    def model_dir(self, model_id: str) -> Path:
        return self.root / model_id

    def version_dir(self, model_id: str, version: str) -> Path:
        return self.model_dir(model_id) / "versions" / version

    def _link(self, model_id: str, name: str) -> Path:
        return self.model_dir(model_id) / name

    def _pinned(self, model_id: str, name: str) -> "str | None":
        link = self._link(model_id, name)
        if not link.is_symlink():
            return None
        target = Path(os.readlink(link))
        return target.name if target.name else None

    def current_version(self, model_id: str) -> "str | None":
        return self._pinned(model_id, "current")

    def previous_version(self, model_id: str) -> "str | None":
        return self._pinned(model_id, "previous")

    def current_path(self, model_id: str) -> "Path | None":
        link = self._link(model_id, "current")
        return link if link.is_symlink() and link.exists() else None

    def list_versions(self, model_id: str) -> list:
        vdir = self.model_dir(model_id) / "versions"
        if not vdir.is_dir():
            return []
        return sorted(p.name for p in vdir.iterdir() if p.is_dir())

    def _set_link(self, model_id: str, name: str, version: str) -> None:
        link = self._link(model_id, name)
        link.parent.mkdir(parents=True, exist_ok=True)
        tmp = link.with_name(link.name + ".swap")
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        os.symlink(Path("versions") / version, tmp)
        os.replace(tmp, link)

    def pin(self, model_id: str, version: str) -> None:
        """Atomically point `current` at a stored version; the outgoing
        version becomes the rollback target."""
        if not self.version_dir(model_id, version).is_dir():
            raise FileNotFoundError(f"{model_id}/{version} not in local store")
        outgoing = self.current_version(model_id)
        if outgoing and outgoing != version:
            self._set_link(model_id, "previous", outgoing)
        self._set_link(model_id, "current", version)

    def rollback(self, model_id: str) -> "str | None":
        """Re-pin the previous version; returns it, or None without a target."""
        prev = self.previous_version(model_id)
        if prev is None or not self.version_dir(model_id, prev).is_dir():
            return None
        self._set_link(model_id, "current", prev)
        return prev

    def prune(self, model_id: str, keep: int = KEEP_VERSIONS) -> list:
        """Drop oldest unpinned versions beyond `keep`; returns removed names."""
        pinned = {self.current_version(model_id), self.previous_version(model_id)}
        versions = self.list_versions(model_id)
        removable = [v for v in versions if v not in pinned]
        removed = []
        excess = len(versions) - keep
        for v in removable:
            if excess <= 0:
                break
            shutil.rmtree(self.version_dir(model_id, v))
            removed.append(v)
            excess -= 1
        return removed


def _ack(subject: str, model_id: str, version: str, reason: str = "",
         rolled_back_to: "str | None" = None) -> dict:
    return {"subject": subject,
            "body": {"schema": ACK_SCHEMA, "model_id": model_id,
                     "version": version, "reason": reason,
                     "rolled_back_to": rolled_back_to, "at": _utcnow()}}


def handle_promotion(payload: dict, store: LocalStore, fetch, activate) -> dict:
    """Run one promotion end to end; returns the ack to publish.

    fetch(model_id, version, dest_dir) pulls the version's registry prefix
    (manifest.json included) into dest_dir and may raise on registry errors.
    activate(model_id, current_path) restarts the serving unit and returns
    True only when the readiness probe passes.
    """
    parsed, reason = parse_promote(payload)
    if parsed is None:
        mid = (payload or {}).get("model_id", "unknown")
        ver = (payload or {}).get("version", "unknown")
        return _ack(SUBJECT_REJECTED, mid, ver, f"malformed promote: {reason}")
    model_id, version = parsed["model_id"], parsed["version"]

    dest = store.version_dir(model_id, version)
    try:
        dest.mkdir(parents=True, exist_ok=True)
        fetch(model_id, version, dest)
    except Exception as e:
        shutil.rmtree(dest, ignore_errors=True)
        return _ack(SUBJECT_REJECTED, model_id, version, f"registry pull failed: {e}")

    manifest_path = dest / "manifest.json"
    if not manifest_path.exists():
        shutil.rmtree(dest, ignore_errors=True)
        return _ack(SUBJECT_REJECTED, model_id, version, "no manifest.json in version prefix")
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        shutil.rmtree(dest, ignore_errors=True)
        return _ack(SUBJECT_REJECTED, model_id, version, f"manifest unparseable: {e}")

    errs = mf.validate_manifest(manifest)
    if manifest.get("model_id") not in (None, model_id):
        errs.append(f"manifest model_id {manifest.get('model_id')!r} "
                    f"!= promoted {model_id!r}")
    if manifest.get("version") not in (None, version):
        errs.append(f"manifest version {manifest.get('version')!r} "
                    f"!= promoted {version!r}")
    if not errs:
        ok, hash_errs = mf.verify_artifacts(manifest, dest)
        if not ok:
            errs += hash_errs
    if errs:
        shutil.rmtree(dest, ignore_errors=True)
        return _ack(SUBJECT_REJECTED, model_id, version,
                    "unverifiable: " + "; ".join(errs))

    store.pin(model_id, version)
    if activate(model_id, store.current_path(model_id)):
        store.prune(model_id)
        return _ack(SUBJECT_PROMOTED, model_id, version, "verified and serving")

    rolled = store.rollback(model_id)
    if rolled:
        activate(model_id, store.current_path(model_id))
    return _ack(SUBJECT_REJECTED, model_id, version,
                "readiness probe failed after swap", rolled_back_to=rolled)


def boot_status(store: LocalStore, registry_reachable: bool) -> dict:
    """Serving-plane boot report. Serving never blocks on the registry: every
    model with a pinned local version serves it; an unreachable registry only
    means no *new* promotions can land."""
    models = {}
    for model_id in sorted(mf.MODEL_IDS):
        current = store.current_version(model_id)
        models[model_id] = {
            "current": current,
            "versions": store.list_versions(model_id),
            "serving": current is not None,
        }
    return {"registry_reachable": registry_reachable, "models": models,
            "at": _utcnow()}
