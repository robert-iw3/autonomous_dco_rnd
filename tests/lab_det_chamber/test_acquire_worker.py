"""
Lab det_chamber -- Phase 4: acquire worker orchestration.

worker_acquire consumes nexus.acquire.request, vets the requested path, dispatches
the on-endpoint agent (over the ssh_playbook_v1 SSH/WinRM executor), uploads the
artifact to the quarantine bucket, and emits nexus.detonation.intake for the
detonation service. I/O is injected so the orchestration is provable with mocks.

This also proves the Phase 4 -> Phase 2/3 seam: the worker's emitted intake message
feeds handle_intake, custody passes, and the sample is detonated.
"""

import sys
from pathlib import Path

import pytest

AGENTS = Path(__file__).resolve().parents[2] / "det_chamber" / "agents"
INTAKE = Path(__file__).resolve().parents[2] / "det_chamber" / "intake"
ENGINE = Path(__file__).resolve().parents[2] / "det_chamber" / "engine"
for p in (AGENTS, INTAKE, ENGINE):
    sys.path.insert(0, str(p))

import acquire_core as ac        # noqa: E402
import acquire_worker as aw      # noqa: E402
import intake_service as isvc    # noqa: E402
import engine_runner as runner   # noqa: E402

ELF = b"\x7fELF benign acquired payload"


def _request(file_path="/home/user/s.elf", os_family="linux"):
    return {"incident_id": "INC-7", "host": "ep-7", "file_path": file_path,
            "os_family": os_family, "reason": "host_expert confirmed TP"}


def _agent_on_endpoint(tmp_path):
    """A fake on-endpoint agent: writes the file, runs acquire_core against it."""
    p = tmp_path / "s.elf"
    p.write_bytes(ELF)

    def run_playbook(req):
        return ac.acquire(str(p), incident_id=req["incident_id"], host=req["host"],
                          os_family=req["os_family"])
    return run_playbook


def test_subject_contract():
    assert aw.SUBJECT_ACQUIRE == "nexus.acquire.request"
    assert aw.SUBJECT_INTAKE == isvc.SUBJECT_INTAKE == "nexus.detonation.intake"


def test_happy_path_uploads_and_emits_intake(tmp_path):
    store, published = {}, []

    def upload(incident_id, filename, artifact):
        ref = f"s3://nexus-quarantine/{incident_id}/{filename}.zip"
        store[ref] = artifact
        return ref

    msg = aw.handle_acquire_request(
        _request(), run_playbook=_agent_on_endpoint(tmp_path),
        upload=upload, publish=lambda s, e: published.append((s, e)))

    assert published and published[0][0] == aw.SUBJECT_INTAKE
    assert msg["artifact_ref"] in store
    assert msg["manifest"]["sha256"] == ac.sha256_bytes(ELF)


def test_path_safety_blocks_dispatch(tmp_path):
    calls = []
    with pytest.raises(ac.AcquisitionError):
        aw.handle_acquire_request(
            _request(file_path="/etc/shadow"),
            run_playbook=lambda req: calls.append(req),
            upload=lambda *a: calls.append("up"),
            publish=lambda *a: calls.append("pub"))
    assert calls == [], "a denied path must never dispatch the agent, upload, or publish"


def test_worker_output_feeds_intake_and_detonates(tmp_path):
    # Phase 4 -> 2 -> 3: the emitted intake message is consumed by handle_intake,
    # custody passes, and engine_runner detonates the ELF.
    store, intake_published = {}, []

    def upload(incident_id, filename, artifact):
        ref = f"s3://nexus-quarantine/{incident_id}/{filename}.zip"
        store[ref] = artifact
        return ref

    intake_req = aw.handle_acquire_request(
        _request(), run_playbook=_agent_on_endpoint(tmp_path),
        upload=upload, publish=lambda s, e: None)

    def fetch(ref):  # intake fetches the zip and recovers the raw bytes
        return ac.unpackage(store[ref], intake_req["manifest"]["filename"])

    event = isvc.handle_intake(
        intake_req, fetch_artifact=fetch,
        run_engine=lambda d, m, a: runner.detonate_single(d, m, a, mock=True),
        publish=lambda s, e: intake_published.append((s, e)))

    assert event["status"] == "detonated"
    assert event["analyzer"] == "linux_sandbox"
    assert event["summary"]["static"]["elf"]["is_elf"] is True
