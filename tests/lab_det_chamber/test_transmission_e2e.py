"""
Lab det_chamber -- endpoint→ingress→intake transmission, validated end to end.

This is the integration proof that the file actually gets CAPTURED on the endpoint
and travels the authenticated transmission layer to a detonation -- not just that
each piece works in isolation. Only the wire boundaries (HTTPS, NATS, S3) are
simulated; the REAL logic runs at every hop:

  endpoint  : acquisition_agent.acquire_and_build_upload  (real capture: read→zip→
              sha256→manifest, NEVER execute) + HMAC over the body
  ingress   : verify the HMAC (same HMAC-SHA256 the Rust ingress uses) + require
              the sha256 custody header, then relay {manifest, artifact}
  intake    : store to the (mock) quarantine bucket, CHAIN-OF-CUSTODY verify after
              unzip, os-route, detonate
  result    : nexus.alerts.detonation verdict

Plus the failure modes that must hold across the wire: a tampered body fails the
ingress HMAC; a body that passes HMAC but whose contents don't match the manifest
fails the intake custody check -- so neither ever detonates.
"""

import hashlib
import hmac as _hmac
import sys
from pathlib import Path

import pytest

DC = Path(__file__).resolve().parents[2] / "det_chamber"
for p in (DC / "engine", DC / "intake", DC / "agents"):
    sys.path.insert(0, str(p))

import acquire_core as ac          # noqa: E402
import acquisition_agent as agent  # noqa: E402
import intake_service as isvc      # noqa: E402
import engine_runner as runner     # noqa: E402

SECRET = b"shared-integrity-hmac-secret"


# ── Faithful re-implementations of the wire boundaries (Rust ingress / S3) ───
def ingress_receive(headers: dict, body: bytes, *, hmac_secret: bytes) -> dict:
    """What core_ingress /api/v1/artifact does: JWT (assumed) → HMAC verify body →
    require the sha256 custody header → relay the intake (manifest in headers)."""
    provided = headers.get(agent.HDR_ARTIFACT_HMAC, "")
    expected = _hmac.new(hmac_secret, body, hashlib.sha256).hexdigest()
    if not provided or provided != expected:
        raise PermissionError("ingress: artifact HMAC verification failed")
    if not headers.get("X-Artifact-SHA256"):
        raise ValueError("ingress: missing chain-of-custody sha256 header")
    manifest = {
        "incident_id": headers["X-Incident-Id"], "host": headers["X-Sensor-Id"],
        "src_path": headers["X-Src-Path"], "filename": headers["X-Artifact-Filename"],
        "sha256": headers["X-Artifact-SHA256"], "size": int(headers["X-Artifact-Size"]),
        "os_family": headers["X-Os-Family"], "acquired_at": "2026-06-10T00:00:00Z",
    }
    return {"manifest": manifest, "artifact": body}


def _run_chain(tmp_path, data, filename, os_family, *, tamper_body=None, yara=True):
    """Capture on the endpoint → ingress → intake/detonate. Returns the event."""
    src = tmp_path / filename
    src.write_bytes(data)
    task = {"incident_id": "INC-E2E", "host": "EP-9", "file_path": str(src),
            "os_family": os_family, "reason": "confirmed TP"}

    # 1. ENDPOINT: real capture + authenticated upload.
    headers, body = agent.acquire_and_build_upload(task, hmac_secret=SECRET)
    if tamper_body is not None:
        body = tamper_body                      # corruption/tamper in transit

    # 2. INGRESS: verify + relay.
    relayed = ingress_receive(headers, body, hmac_secret=SECRET)

    # 3. STORAGE + INTAKE: store to the (mock) quarantine bucket, then detonate.
    bucket = {}
    ref = f"s3://nexus-quarantine/{relayed['manifest']['incident_id']}/{relayed['manifest']['filename']}.zip"
    bucket[ref] = relayed["artifact"]           # intake persists the relayed body
    intake_req = {"artifact_ref": ref, "manifest": relayed["manifest"]}

    published = []

    def run_engine(d, m, a):
        rec = runner.detonate_single(d, m, a, mock=True)
        if yara:
            rec["static"]["yara_matches"] = ["Win.Trojan.Agent"]
        return rec

    return isvc.handle_intake(
        intake_req,
        fetch_artifact=lambda r: ac.unpackage(bucket[r], relayed["manifest"]["filename"]),
        run_engine=run_engine,
        publish=lambda s, e: published.append((s, e))), published


# ── Happy path: file captured + detonated, custody preserved end to end ──────
def test_windows_file_captured_transmitted_and_detonated(tmp_path):
    data = b"MZ" + b"\x90" * 80 + b"captured-on-endpoint"
    event, published = _run_chain(tmp_path, data, "evil.exe", "windows")
    assert event["status"] == "detonated"
    assert event["analyzer"] == "windows_engine"
    # the sha256 that the agent computed on the endpoint survived every hop
    assert event["sha256"] == ac.sha256_bytes(data)
    assert published and published[0][0] == "nexus.alerts.detonation"


def test_linux_elf_captured_transmitted_and_detonated(tmp_path):
    import struct
    data = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + struct.pack("<HH", 2, 0x3E) + b"\x00" * 40
    event, _ = _run_chain(tmp_path, data, "sample.elf", "linux", yara=False)
    assert event["status"] == "detonated" and event["analyzer"] == "linux_sandbox"
    assert event["summary"]["static"]["elf"]["is_elf"] is True


# ── The wire-integrity guarantees ────────────────────────────────────────────
def test_tampered_body_rejected_at_ingress(tmp_path):
    data = b"MZ original captured bytes"
    with pytest.raises(PermissionError):
        _run_chain(tmp_path, data, "evil.exe", "windows",
                   tamper_body=ac.package("evil.exe", b"swapped-in-transit"))


def test_custody_mismatch_never_detonates(tmp_path):
    # Forge a body whose HMAC is valid (attacker knows the secret) but whose
    # CONTENTS differ from the manifest sha256 -- intake custody must still refuse.
    src = tmp_path / "evil.exe"; src.write_bytes(b"MZ real")
    task = {"incident_id": "INC-X", "host": "EP", "file_path": str(src),
            "os_family": "windows", "reason": "TP"}
    headers, _ = agent.acquire_and_build_upload(task, hmac_secret=SECRET)
    forged = ac.package("evil.exe", b"DIFFERENT payload")
    headers[agent.HDR_ARTIFACT_HMAC] = _hmac.new(SECRET, forged, hashlib.sha256).hexdigest()
    relayed = ingress_receive(headers, forged, hmac_secret=SECRET)   # passes HMAC
    ran = []
    event = isvc.handle_intake(
        {"artifact_ref": "s3://q/x.zip", "manifest": relayed["manifest"]},
        fetch_artifact=lambda r: ac.unpackage(forged, "evil.exe"),
        run_engine=lambda *a: ran.append(a),
        publish=lambda s, e: None)
    assert event["status"] == "custody_failed" and ran == []
