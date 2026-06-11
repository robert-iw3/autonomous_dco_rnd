"""
Lab det_chamber -- endpoint outbound transmission (Phase 8).

Acquisition rides the same OUTBOUND HTTPS channel sensors already use: 
a separate lightweight acquisition agent polls ingress for tasks, 
acquires the file locally, and transmits it to core_ingress 
/api/v1/artifact with JWT + HMAC + the chain-of-custody manifest.

This covers the det_chamber-side pieces (agent transmission + worker enqueue);
the ingress endpoint contract is in lab_infra_contracts/test_ingress_artifact.py.
"""

import hashlib
import hmac as _hmac
import io
import sys
import zipfile
from pathlib import Path

import pytest

AGENTS = Path(__file__).resolve().parents[2] / "det_chamber" / "agents"
INTAKE = Path(__file__).resolve().parents[2] / "det_chamber" / "intake"
sys.path.insert(0, str(AGENTS))
sys.path.insert(0, str(INTAKE))

import acquire_core as ac        # noqa: E402
import acquisition_agent as agent  # noqa: E402
import acquire_worker as aw       # noqa: E402

SECRET = b"lab-integrity-secret"


def _task(tmp_path, data=b"MZ benign", **over):
    p = tmp_path / "evil.exe"
    p.write_bytes(data)
    t = {"incident_id": "INC-T", "host": "EP-1", "file_path": str(p),
         "os_family": "windows", "reason": "confirmed TP"}
    t.update(over)
    return t, data


# --- Agent: acquire + build authenticated outbound upload --------------------
def test_agent_builds_authenticated_artifact_upload(tmp_path):
    task, data = _task(tmp_path)
    headers, body = agent.acquire_and_build_upload(task, hmac_secret=SECRET)
    # chain-of-custody header == sha256 of the original bytes
    assert headers["X-Artifact-SHA256"] == ac.sha256_bytes(data)
    assert headers["X-Incident-Id"] == "INC-T" and headers["X-Os-Family"] == "windows"
    # HMAC over the transmitted body, verifiable by ingress with the shared secret
    expected = _hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    assert headers[agent.HDR_ARTIFACT_HMAC] == expected
    # body is the zipped artifact (never executed in transit)
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        assert z.read("evil.exe") == data


def test_agent_refuses_unsafe_path(tmp_path):
    task, _ = _task(tmp_path, file_path="/etc/../etc/shadow", os_family="linux")
    with pytest.raises(ac.AcquisitionError):
        agent.acquire_and_build_upload(task, hmac_secret=SECRET)


def test_agent_targets_outbound_ingress_endpoint():
    # The agent transmits to ingress over HTTPS (outbound), not a direct bucket write.
    assert agent.ARTIFACT_ENDPOINT == "/api/v1/artifact"
    assert agent.TASKS_ENDPOINT == "/api/v1/tasks"


# --- Worker: enqueue a task keyed by host (the agent polls it) ---------------
def test_worker_enqueues_task_keyed_by_host(tmp_path):
    task, _ = _task(tmp_path)
    enqueued = []
    out = aw.enqueue_acquisition_task(
        {"incident_id": "INC-T", "host": "EP-1", "file_path": task["file_path"],
         "os_family": "windows", "reason": "TP"},
        enqueue=lambda host, t: enqueued.append((host, t)))
    assert enqueued and enqueued[0][0] == "EP-1"
    assert out["file_path"] == task["file_path"]


def test_worker_denied_path_never_enqueues():
    calls = []
    with pytest.raises(ac.AcquisitionError):
        aw.enqueue_acquisition_task(
            {"incident_id": "X", "host": "EP", "file_path": "/etc/shadow",
             "os_family": "linux", "reason": "r"},
            enqueue=lambda h, t: calls.append((h, t)))
    assert calls == [], "an unsafe path must never be enqueued for collection"
