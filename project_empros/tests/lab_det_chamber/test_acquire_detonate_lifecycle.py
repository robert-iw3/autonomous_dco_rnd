"""
Lab det_chamber -- Phase 7: full-lifecycle capstone E2E.

One test walks the entire live acquisition & detonation lifecycle using the REAL
modules from every phase, with only the I/O boundaries mocked (endpoint dispatch,
quarantine bucket, the Windows-only detonation tools). It proves the pieces compose
end to end:

  investigation TP (swarm)            -> AcquisitionRequestSchema + confidence gate   [P5]
  agent deploys + acquires (endpoint) -> zip + sha256 + manifest, NEVER executes      [P4]
  deliver to chamber                  -> quarantine bucket -> nexus.detonation.intake  [P4/2]
  intake                              -> CHAIN OF CUSTODY -> os-routed detonation      [P2/3]
  result to swarm                     -> nexus.alerts.detonation envelope              [P2]
  verdict                             -> contain (malicious) / restore (FP)            [P5]

Plus the negative invariants: path traversal / oversize rejected, a broken chain
of custody never detonates, and a low-confidence call never acquires.

Fixtures are benign (synthetic PE/ELF headers) -- never live malware.
"""

import struct
import sys
import types
import zipfile
import io
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DC = REPO / "det_chamber"
HUNTER = REPO / "analytics" / "llm_hunter"
for p in (DC / "engine", DC / "intake", DC / "agents", HUNTER, HUNTER / "tools"):
    sys.path.insert(0, str(p))


# -- Stub langchain_core so the swarm trigger modules import (pydantic is real) --
def _stub(name):
    if name not in sys.modules:
        m = types.ModuleType(name); m.__path__ = []
        sys.modules[name] = m
    return sys.modules[name]


_lc = _stub("langchain_core")
_msg = _stub("langchain_core.messages")
for n in ("BaseMessage", "HumanMessage", "RemoveMessage"):
    setattr(_msg, n, type(n, (), {"__init__": lambda self, content="", **k: None}))
_lc.messages = _msg
_tools = _stub("langchain_core.tools")
_tools.BaseTool = type("BaseTool", (), {"name": "", "description": "", "args_schema": None})

# det_chamber side (stdlib)
import acquire_core as ac          # noqa: E402
import manifest as mf              # noqa: E402
import intake_service as isvc      # noqa: E402
import engine_runner as runner     # noqa: E402
# swarm side
import state                       # noqa: E402
import acquire_detonate as ad      # noqa: E402
import detonation_enrichment as de # noqa: E402


def _pe_fixture():
    # Minimal PE-ish bytes: MZ header (never parsed/executed in the lifecycle).
    return b"MZ" + b"\x90" * 64 + b"benign-pe-fixture"


def _elf_fixture():
    return b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + struct.pack("<HH", 2, 0x3E) + b"\x00" * 40


class _Bucket(dict):
    """A stand-in quarantine bucket: artifact_ref -> packaged bytes."""


def _acquire_to_bucket(tmp_path, data, filename, incident, host, os_family):
    """Steps 1-4 up to the bucket: gate -> request -> on-endpoint acquire -> upload."""
    endpoint_file = tmp_path / filename
    endpoint_file.write_bytes(data)

    # 1. Swarm: host_expert confirmed TP -> gated request emission (real tool).
    assert ad.should_acquire(0.93) is True
    emitted = []
    import unittest.mock as _m
    with _m.patch.object(ad, "_publish", lambda s, p: emitted.append((s, p))):
        tool = ad.AcquireAndDetonateTool()
        out = tool._run(incident_id=incident, host=host, file_path=str(endpoint_file),
                        os_family=os_family, confidence=0.93, reason="confirmed TP")
    assert emitted and emitted[0][0] == ad.ACQUIRE_SUBJECT == "nexus.acquire.request"
    assert "detonat" in out.lower()
    # the emitted request validates as the schema (first-line safety)
    state.AcquisitionRequestSchema(**{k: emitted[0][1][k] for k in
                                      ("incident_id", "host", "file_path", "os_family", "confidence", "reason")})

    # 2-3. Endpoint agent acquires: zip + sha256 + manifest, reads bytes (never runs).
    manifest, artifact = ac.acquire(str(endpoint_file), incident_id=incident, host=host, os_family=os_family)
    assert manifest["sha256"] == ac.sha256_bytes(data)
    with zipfile.ZipFile(io.BytesIO(artifact)) as z:
        assert z.read(filename) == data

    # 4. Upload to the quarantine bucket.
    bucket = _Bucket()
    ref = f"s3://nexus-quarantine/{incident}/{filename}.zip"
    bucket[ref] = artifact
    return {"artifact_ref": ref, "manifest": manifest}, bucket


def _detonate(intake_req, bucket, *, yara_hit, verdict=None):
    """Steps 4-5: intake verifies custody, runs the real os-routed engine, publishes."""
    published = []

    def fetch(ref):
        return ac.unpackage(bucket[ref], intake_req["manifest"]["filename"])

    def run_engine(data, manifest, analyzer):
        # Real engine_runner dispatch (os routing + writes-never-executes); then
        # reflect what the isolated-VM YARA/verdict produced.
        rec = runner.detonate_single(data, manifest, analyzer, mock=True)
        if yara_hit:
            rec["static"]["yara_matches"] = ["Win.Trojan.Agent"]
        if verdict:
            rec["static"]["verdict"] = verdict
            rec["verdict"] = verdict
        return rec

    event = isvc.handle_intake(intake_req, fetch_artifact=fetch, run_engine=run_engine,
                               publish=lambda s, e: published.append((s, e)))
    assert published and published[0][0] == isvc.SUBJECT_ALERTS == "nexus.alerts.detonation"
    return event


# --- Happy path A: malicious Windows file -> containment ---------------------
def test_lifecycle_malicious_windows_drives_containment(tmp_path):
    intake_req, bucket = _acquire_to_bucket(
        tmp_path, _pe_fixture(), "evil.exe", "INC-CAP-1", "WIN-EP-01", "windows")

    event = _detonate(intake_req, bucket, yara_hit=True)
    assert event["status"] == "detonated"
    assert event["analyzer"] == "windows_engine"          # os routing
    assert event["sha256"] == intake_req["manifest"]["sha256"]   # custody preserved end to end

    # 6. Swarm verdict: malicious -> evidence-backed containment.
    action = de.enrichment_decision(event, had_containment=False)
    assert action["action_type"] == "isolate_host"
    state.SoarExecutionSchema(**action)                   # valid SOAR action


# --- Happy path B: benign Linux file after containment -> restore (FP) -------
def test_lifecycle_benign_linux_after_containment_drives_restore(tmp_path):
    intake_req, bucket = _acquire_to_bucket(
        tmp_path, _elf_fixture(), "sample.elf", "INC-CAP-2", "LIN-EP-02", "linux")

    event = _detonate(intake_req, bucket, yara_hit=False, verdict="benign")
    assert event["status"] == "detonated"
    assert event["analyzer"] == "linux_sandbox"           # ELF routed to the Linux analyzer
    assert event["summary"]["static"]["elf"]["is_elf"] is True

    # 6. Verdict benign + we had contained -> restore (false positive).
    action = de.enrichment_decision(event, had_containment=True)
    assert action["action_type"] == "restore"
    state.SoarExecutionSchema(**action)


# --- Negative invariants (the safety guarantees, end to end) -----------------
def test_traversal_path_never_acquires(tmp_path):
    with pytest.raises(ac.AcquisitionError):
        ac.acquire("/var/log/../../etc/shadow", incident_id="X", host="h", os_family="linux")


def test_oversized_file_never_acquires(tmp_path):
    p = tmp_path / "big.bin"; p.write_bytes(b"x" * 4096)
    with pytest.raises(ac.AcquisitionError):
        ac.acquire(str(p), incident_id="X", host="h", os_family="linux", max_size=1024)


def test_broken_chain_of_custody_never_detonates(tmp_path):
    intake_req, bucket = _acquire_to_bucket(
        tmp_path, _pe_fixture(), "evil.exe", "INC-CAP-3", "WIN-EP-03", "windows")
    # Tamper with the artifact in the bucket after the manifest was written.
    bucket[intake_req["artifact_ref"]] = ac.package("evil.exe", b"swapped-bytes")
    ran = []
    event = isvc.handle_intake(
        intake_req,
        fetch_artifact=lambda ref: ac.unpackage(bucket[ref], "evil.exe"),
        run_engine=lambda *a: ran.append(a),
        publish=lambda s, e: None)
    assert event["status"] == "custody_failed"
    assert ran == [], "a broken chain of custody must never reach the engine"


def test_low_confidence_never_acquires(monkeypatch):
    emitted = []
    monkeypatch.setattr(ad, "_publish", lambda s, p: emitted.append((s, p)))
    out = ad.AcquireAndDetonateTool()._run(
        incident_id="X", host="h", file_path="/home/u/x.bin", os_family="linux",
        confidence=0.40, reason="weak")
    assert "refus" in out.lower() and emitted == []
