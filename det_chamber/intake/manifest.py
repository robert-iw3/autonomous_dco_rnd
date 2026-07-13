"""
Artifact manifest + chain-of-custody verification.

The acquisition agent writes a manifest alongside the artifact it uploads
to the quarantine bucket. The intake service recomputes the hash of the bytes it is
about to detonate and refuses to proceed unless they match the manifest exactly.
Pure stdlib so it is trivially unit-testable on any host.
"""

import hashlib
from dataclasses import dataclass

_REQUIRED = ("incident_id", "host", "src_path", "filename",
             "sha256", "size", "os_family", "acquired_at")
_OS_FAMILIES = ("windows", "linux")


class CustodyError(Exception):
    """Raised when acquired bytes do not match their manifest (tamper/corruption)."""


@dataclass(frozen=True)
class ArtifactManifest:
    incident_id: str
    host: str
    src_path: str
    filename: str
    sha256: str
    size: int
    os_family: str
    acquired_at: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def manifest_from_dict(d: dict) -> ArtifactManifest:
    missing = [k for k in _REQUIRED if k not in d or d[k] in (None, "")]
    if missing:
        raise ValueError(f"manifest missing required field(s): {', '.join(missing)}")
    os_family = str(d["os_family"]).lower()
    if os_family not in _OS_FAMILIES:
        raise ValueError(f"manifest os_family must be one of {_OS_FAMILIES}, got {os_family!r}")
    return ArtifactManifest(
        incident_id=str(d["incident_id"]),
        host=str(d["host"]),
        src_path=str(d["src_path"]),
        filename=str(d["filename"]),
        sha256=str(d["sha256"]).lower(),
        size=int(d["size"]),
        os_family=os_family,
        acquired_at=str(d["acquired_at"]),
    )


def verify_custody(data: bytes, manifest: ArtifactManifest) -> None:
    """Raise CustodyError unless ``data`` matches the manifest's sha256 AND size."""
    actual_size = len(data)
    if actual_size != manifest.size:
        raise CustodyError(
            f"size mismatch for {manifest.filename}: manifest={manifest.size} actual={actual_size}")
    actual_sha = sha256_bytes(data)
    if actual_sha != manifest.sha256:
        raise CustodyError(
            f"sha256 mismatch for {manifest.filename}: "
            f"manifest={manifest.sha256} actual={actual_sha}")
