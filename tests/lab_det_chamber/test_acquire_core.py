"""
Lab det_chamber -- Phase 4: acquisition core (path safety + manifest + packaging).

The canonical, tested implementation of what the on-endpoint agents do: validate
the target path (no traversal/wildcards/OS-critical files), enforce a size cap,
read the bytes (NEVER execute), produce a chain-of-custody manifest, and package
the artifact for safe transport. The bash/PowerShell agents mirror this contract.
"""

import sys
import zipfile
import io
from pathlib import Path

import pytest

AGENTS = Path(__file__).resolve().parents[2] / "det_chamber" / "agents"
INTAKE = Path(__file__).resolve().parents[2] / "det_chamber" / "intake"
sys.path.insert(0, str(AGENTS))
sys.path.insert(0, str(INTAKE))

import acquire_core as ac   # noqa: E402
import manifest as mf       # noqa: E402  (intake's manifest -- proves cross-module parity)


# --- Path safety (string-based; runs on the worker for any target OS) ---------
def test_accepts_normal_paths():
    ac.validate_request_path("/home/user/Downloads/evil.bin", os_family="linux")
    ac.validate_request_path("C:\\Users\\Public\\evil.exe", os_family="windows")


@pytest.mark.parametrize("path", [
    "/etc/shadow", "/etc/sudoers", "/proc/1/mem", "/root/.ssh/id_rsa",
])
def test_rejects_linux_critical_paths(path):
    with pytest.raises(ac.AcquisitionError):
        ac.validate_request_path(path, os_family="linux")


@pytest.mark.parametrize("path", [
    "C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\NTDS\\ntds.dit",
])
def test_rejects_windows_critical_paths(path):
    with pytest.raises(ac.AcquisitionError):
        ac.validate_request_path(path, os_family="windows")


def test_rejects_path_traversal():
    with pytest.raises(ac.AcquisitionError):
        ac.validate_request_path("/var/log/../../etc/shadow", os_family="linux")


def test_rejects_wildcards():
    with pytest.raises(ac.AcquisitionError):
        ac.validate_request_path("/home/user/*.bin", os_family="linux")


# --- Acquire (FS-based; runs on the endpoint) --------------------------------
def _sample(tmp_path, data=b"\x4d\x5a benign sample bytes"):
    p = tmp_path / "evil.bin"
    p.write_bytes(data)
    return p, data


def test_acquire_builds_manifest_and_package(tmp_path):
    p, data = _sample(tmp_path)
    manifest, artifact = ac.acquire(str(p), incident_id="INC-1", host="ep-1", os_family="linux")
    assert manifest["sha256"] == ac.sha256_bytes(data)
    assert manifest["size"] == len(data)
    assert manifest["filename"] == "evil.bin"
    # package is a zip carrying exactly the original bytes (safe transport, no auto-run)
    with zipfile.ZipFile(io.BytesIO(artifact)) as z:
        assert z.read("evil.bin") == data


def test_manifest_is_consumable_by_intake_and_passes_custody(tmp_path):
    # The agent's manifest must be exactly what the intake service verifies.
    p, data = _sample(tmp_path)
    manifest, artifact = ac.acquire(str(p), incident_id="INC-1", host="ep-1", os_family="linux")
    m = mf.manifest_from_dict(manifest)           # intake parses it without error
    recovered = ac.unpackage(artifact, "evil.bin")
    mf.verify_custody(recovered, m)               # custody holds end-to-end


def test_acquire_enforces_size_cap(tmp_path):
    p, _ = _sample(tmp_path, data=b"x" * 5000)
    with pytest.raises(ac.AcquisitionError):
        ac.acquire(str(p), incident_id="INC-1", host="ep", os_family="linux", max_size=1024)


def test_acquire_never_executes_sample(tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("executed sample"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("ran subprocess"))
    p, _ = _sample(tmp_path)
    ac.acquire(str(p), incident_id="INC-1", host="ep", os_family="linux")
