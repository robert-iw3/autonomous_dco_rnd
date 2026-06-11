"""
Lab det_chamber -- Phase 2: intake service + chain of custody.

The intake service is the bridge between an acquired artifact sitting in the
quarantine bucket and a detonation. Its non-negotiable job is **chain of custody**:
the bytes it detonates must be byte-identical to what the acquisition agent
manifested (sha256 + size). A mismatch means tampering or corruption in transit --
the service must REFUSE to detonate and surface a custody failure, never silently
run a different file.

These tests drive that contract with all I/O injected (fetch/run-engine/publish are
mocks), so the logic is provable with no live NATS/MinIO/engine.

Subjects: nexus.detonation.intake (in) -> nexus.alerts.detonation (out).
"""

import sys
from pathlib import Path

import pytest

INTAKE_DIR = Path(__file__).resolve().parents[2] / "det_chamber" / "intake"
sys.path.insert(0, str(INTAKE_DIR))

import manifest as mf          # noqa: E402
import intake_service as isvc  # noqa: E402

GOOD_BYTES = b"\x4d\x5a benign EICAR-style fixture payload"


def _manifest_dict(data=GOOD_BYTES, os_family="windows", **over):
    d = {
        "incident_id": "INC-123",
        "host": "WIN-EP-07",
        "src_path": "C:\\Users\\Public\\evil.exe",
        "filename": "evil.exe",
        "sha256": mf.sha256_bytes(data),
        "size": len(data),
        "os_family": os_family,
        "acquired_at": "2026-06-10T12:00:00Z",
    }
    d.update(over)
    return d


# --- 1. Chain of custody -----------------------------------------------------
def test_verify_custody_passes_on_match():
    m = mf.manifest_from_dict(_manifest_dict())
    mf.verify_custody(GOOD_BYTES, m)  # must not raise


def test_verify_custody_fails_on_hash_mismatch():
    m = mf.manifest_from_dict(_manifest_dict())
    with pytest.raises(mf.CustodyError):
        mf.verify_custody(b"tampered-in-transit", m)


def test_verify_custody_fails_on_size_mismatch():
    m = mf.manifest_from_dict(_manifest_dict(size=999999))
    with pytest.raises(mf.CustodyError):
        mf.verify_custody(GOOD_BYTES, m)


def test_manifest_requires_all_fields():
    bad = _manifest_dict()
    del bad["sha256"]
    with pytest.raises(ValueError):
        mf.manifest_from_dict(bad)


# --- 2. OS-family routing (Phase 3 makes the Linux analyzer real) ------------
def test_select_analyzer_routes_by_os():
    assert isvc.select_analyzer("windows") == "windows_engine"
    assert isvc.select_analyzer("linux") == "linux_sandbox"


def test_select_analyzer_rejects_unknown_os():
    with pytest.raises(ValueError):
        isvc.select_analyzer("solaris")


# --- 3. handle_intake orchestration (I/O injected) ---------------------------
class _Spy:
    def __init__(self, summary=None):
        self.run_calls = []
        self.published = []
        self._summary = summary or {"verdict": "malicious", "yara_matches": ["X"]}

    def fetch(self, ref):
        return GOOD_BYTES

    def run_engine(self, data, manifest, analyzer):
        self.run_calls.append((analyzer, manifest.sha256))
        return self._summary

    def publish(self, subject, event):
        self.published.append((subject, event))


def test_handle_intake_happy_path_detonates_and_publishes():
    spy = _Spy()
    req = {"artifact_ref": "s3://nexus-quarantine/INC-123/evil.exe.zip",
           "manifest": _manifest_dict()}
    event = isvc.handle_intake(req, fetch_artifact=spy.fetch,
                               run_engine=spy.run_engine, publish=spy.publish)
    # detonated exactly once, with the routed analyzer
    assert spy.run_calls == [("windows_engine", req["manifest"]["sha256"])]
    # published to the alerts subject with a complete result envelope
    assert spy.published and spy.published[0][0] == isvc.SUBJECT_ALERTS
    assert event["status"] == "detonated"
    for key in ("incident_id", "sha256", "os_family", "analyzer", "status", "summary"):
        assert key in event
    assert event["incident_id"] == "INC-123"
    assert event["summary"]["verdict"] == "malicious"


def test_handle_intake_refuses_to_detonate_on_custody_failure():
    spy = _Spy()
    # fetch returns bytes that do NOT match the manifest sha256
    spy.fetch = lambda ref: b"swapped-payload"
    req = {"artifact_ref": "s3://nexus-quarantine/INC-123/evil.exe.zip",
           "manifest": _manifest_dict()}
    event = isvc.handle_intake(req, fetch_artifact=spy.fetch,
                               run_engine=spy.run_engine, publish=spy.publish)
    # THE critical invariant: no detonation on a broken chain of custody
    assert spy.run_calls == [], "engine must NOT run when custody verification fails"
    assert event["status"] == "custody_failed"
    # a custody failure is still surfaced (acked + alerted, never silently dropped)
    assert spy.published and spy.published[0][1]["status"] == "custody_failed"


def test_handle_intake_routes_linux_artifact():
    spy = _Spy()
    req = {"artifact_ref": "s3://nexus-quarantine/INC-9/sample.elf",
           "manifest": _manifest_dict(os_family="linux", filename="sample.elf")}
    event = isvc.handle_intake(req, fetch_artifact=spy.fetch,
                               run_engine=spy.run_engine, publish=spy.publish)
    assert event["analyzer"] == "linux_sandbox"
    assert spy.run_calls[0][0] == "linux_sandbox"


def test_subjects_are_the_agreed_contract():
    assert isvc.SUBJECT_INTAKE == "nexus.detonation.intake"
    assert isvc.SUBJECT_ALERTS == "nexus.alerts.detonation"
