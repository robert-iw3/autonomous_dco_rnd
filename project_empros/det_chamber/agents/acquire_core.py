"""
Acquisition core -- the canonical, tested contract the on-endpoint agents mirror.

Given a target file path on a compromised host, the agent must:
  1. validate the path (no wildcards, no traversal, not an OS-critical file),
  2. enforce a size cap,
  3. read the bytes -- NEVER execute the sample,
  4. build a chain-of-custody manifest (sha256 + size + provenance),
  5. package the artifact (zip) for safe transport (no auto-run in transit).
"""

import hashlib
import io
import os
import re
import zipfile
from datetime import datetime, timezone

DEFAULT_MAX_SIZE = 100 * 1024 * 1024  # 100 MB

# OS-critical paths that must never be acquired (avoids exfil of secrets / DoS by
# acquiring huge system files). Matched as normalized (lowercased, /-separated)
# substrings, so a poisoned alert cannot redirect acquisition at them.
LINUX_DENY = (
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh/",
    "/proc/", "/sys/", "/dev/", "/boot/", "/root/.ssh/", "/.ssh/id_",
)
WINDOWS_DENY = (
    "/windows/system32/config/", "/windows/ntds/", "ntds.dit",
    "/windows/system32/lsass", "pagefile.sys", "/system32/sam",
)


class AcquisitionError(Exception):
    """Raised when a target path is unsafe or acquisition cannot proceed."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _deny_for(os_family: str):
    return WINDOWS_DENY if str(os_family).lower() == "windows" else LINUX_DENY


def validate_request_path(path: str, *, os_family: str) -> str:
    """String-only safety check. Raises AcquisitionError on an unsafe path."""
    if not path or any(c in path for c in "*?[]"):
        raise AcquisitionError(f"empty path or wildcard not allowed: {path!r}")
    if ".." in re.split(r"[\\/]+", path):
        raise AcquisitionError(f"path traversal not allowed: {path!r}")
    norm = path.replace("\\", "/").lower().rstrip("/")
    for token in _deny_for(os_family):
        if token in norm:
            raise AcquisitionError(f"refusing OS-critical path (matches {token!r}): {path!r}")
    return path


def build_manifest(incident_id, host, src_path, data: bytes, os_family) -> dict:
    return {
        "incident_id": incident_id,
        "host": host,
        "src_path": src_path,
        "filename": os.path.basename(src_path.replace("\\", "/")),
        "sha256": sha256_bytes(data),
        "size": len(data),
        "os_family": str(os_family).lower(),
        "acquired_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def package(name: str, data: bytes) -> bytes:
    """Zip the artifact for transport (so it never auto-executes in transit)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return buf.getvalue()


def unpackage(blob: bytes, name: str) -> bytes:
    """Recover the original bytes from a packaged artifact (intake side)."""
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        return z.read(name)


def acquire(path: str, *, incident_id, host, os_family, max_size=DEFAULT_MAX_SIZE):
    """Filesystem acquisition on the endpoint. Returns (manifest, packaged_bytes)."""
    validate_request_path(path, os_family=os_family)
    if not os.path.isfile(path):
        raise AcquisitionError(f"not a regular file: {path!r}")
    size = os.path.getsize(path)
    if size > max_size:
        raise AcquisitionError(f"file exceeds size cap: {size} > {max_size}")
    with open(path, "rb") as f:        # READ ONLY -- the sample is never executed
        data = f.read()
    manifest = build_manifest(incident_id, host, path, data, os_family)
    return manifest, package(manifest["filename"], data)
