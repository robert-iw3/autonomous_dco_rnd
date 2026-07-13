"""
Lab det_chamber -- Phase 3: os_family routing end to end.

intake routed by label in Phase 2; Phase 3 makes the labels real:
  windows_engine -> Windows engine path,  linux_sandbox -> Linux analyzer.
engine_runner.detonate_single is the single dispatch point the intake service calls
as its run_engine. Both paths return the SAME uniform file-record envelope, so the
nexus.alerts.detonation result is os-agnostic.
"""

import sys
from pathlib import Path

import pytest

ENGINE = Path(__file__).resolve().parents[2] / "det_chamber" / "engine"
INTAKE = Path(__file__).resolve().parents[2] / "det_chamber" / "intake"
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(INTAKE))

import summary_schema as schema   # noqa: E402
import engine_runner as runner    # noqa: E402
import manifest as mf             # noqa: E402
import intake_service as isvc     # noqa: E402

DATA = b"\x7fELF benign fixture bytes"


def _manifest(os_family, filename):
    return mf.manifest_from_dict({
        "incident_id": "INC-OS", "host": "ep", "src_path": "/tmp/x",
        "filename": filename, "sha256": mf.sha256_bytes(DATA), "size": len(DATA),
        "os_family": os_family, "acquired_at": "2026-06-10T00:00:00Z",
    })


def test_linux_label_routes_to_linux_analyzer():
    rec = runner.detonate_single(DATA, _manifest("linux", "s.elf"), "linux_sandbox", mock=True)
    assert "elf" in rec["static"], "linux_sandbox must produce ELF static analysis"


def test_windows_label_routes_to_windows_engine():
    rec = runner.detonate_single(DATA, _manifest("windows", "s.exe"), "windows_engine", mock=True)
    assert "pefile" in rec["static"], "windows_engine must produce PE static analysis"


def test_unknown_analyzer_rejected():
    with pytest.raises(ValueError):
        runner.detonate_single(DATA, _manifest("linux", "s"), "bsd_jail", mock=True)


def test_both_paths_emit_uniform_envelope():
    for analyzer, fn in (("linux_sandbox", "s.elf"), ("windows_engine", "s.exe")):
        rec = runner.detonate_single(DATA, _manifest(analyzer.split("_")[0] if analyzer.startswith("linux") else "windows", fn), analyzer, mock=True)
        assert set(rec) == set(schema.FILE_RECORD_KEYS)


def test_intake_uses_runner_to_route_linux_end_to_end():
    # Wire the real dispatcher as intake's run_engine; only the analyzers are mocked.
    published = []
    req = {"artifact_ref": "s3://nexus-quarantine/INC-OS/s.elf",
           "manifest": {
               "incident_id": "INC-OS", "host": "ep", "src_path": "/tmp/x",
               "filename": "s.elf", "sha256": mf.sha256_bytes(DATA), "size": len(DATA),
               "os_family": "linux", "acquired_at": "2026-06-10T00:00:00Z"}}
    event = isvc.handle_intake(
        req,
        fetch_artifact=lambda ref: DATA,
        run_engine=lambda data, manifest, analyzer: runner.detonate_single(data, manifest, analyzer, mock=True),
        publish=lambda subj, ev: published.append((subj, ev)),
    )
    assert event["analyzer"] == "linux_sandbox"
    assert event["status"] == "detonated"
    assert event["summary"]["static"]["elf"]["is_elf"] is True
    assert published[0][0] == isvc.SUBJECT_ALERTS
