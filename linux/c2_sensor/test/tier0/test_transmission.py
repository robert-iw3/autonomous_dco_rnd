"""
Tier-0 - Transmission-layer tests for linux/c2_sensor.

Validates the wire protocol against the core_ingress contract
(middleware/src/core_ingress/src/integrity.rs):

  * HMAC-SHA256(payload || BE64(seq) || sensor_id_utf8 || BE64(ts))
  * Required headers: X-Sensor-Id, X-Sensor-Type, X-Batch-Sequence,
    X-Batch-Timestamp, X-Batch-HMAC
  * Content-Type: application/vnd.apache.parquet
  * Authorization: Bearer <token>
  * gateway_url path == /api/v1/telemetry  (a prior misconfiguration pointed
    this at /api/v1/sensor/telemetry and 404'd against the real ingress)

Runs an in-process HTTP server (no Docker) acting as a stub Nexus gateway
and drives a real LineageStamper + the forwarder's header-construction path
against it end to end with synthetic Parquet bytes.
"""

import hashlib
import hmac as hmac_mod
import json
import os
import struct
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest
import requests

from batch_integrity import (
    LineageStamper,
    HDR_BATCH_SEQUENCE,
    HDR_BATCH_HMAC,
    HDR_BATCH_TIMESTAMP,
    HDR_SENSOR_ID,
    HDR_SENSOR_TYPE,
)

pytestmark = pytest.mark.tier0

EXPECTED_GATEWAY_PATH = "/api/v1/telemetry"
EXPECTED_CONTENT_TYPE = "application/vnd.apache.parquet"
EXPECTED_SENSOR_TYPE = "linux-c2-sensor"

def _reference_hmac(secret: bytes, payload: bytes, sequence: int, sensor_id: str, timestamp: int) -> str:
    """Independent re-derivation of the core_ingress HMAC formula for cross-checking."""
    mac = hmac_mod.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()

# -----------------------------------------------------------------------------
# LineageStamper HMAC contract conformance
# -----------------------------------------------------------------------------

class TestLineageStamperHmac:
    SECRET = "unit-test-shared-secret"
    SENSOR_ID = "test-host-01"

    def _stamper(self, tmp_path):
        return LineageStamper(self.SENSOR_ID, self.SECRET, str(tmp_path / "baseline.db"))

    def test_hmac_matches_independent_reference_implementation(self, tmp_path):
        stamper = self._stamper(tmp_path)
        payload = b"synthetic-parquet-bytes-001"
        envelope = stamper.stamp(payload)

        expected = _reference_hmac(
            self.SECRET.encode("utf-8"), payload,
            envelope["sequence"], envelope["sensor_id"], envelope["timestamp"],
        )
        assert envelope["hmac_hex"] == expected

    def test_hmac_is_64_lowercase_hex_chars(self, tmp_path):
        envelope = self._stamper(tmp_path).stamp(b"abc")
        assert len(envelope["hmac_hex"]) == 64
        assert all(c in "0123456789abcdef" for c in envelope["hmac_hex"])

    def test_sequence_strictly_monotonic_and_persisted(self, tmp_path):
        db_path = str(tmp_path / "baseline.db")
        s1 = LineageStamper(self.SENSOR_ID, self.SECRET, db_path)
        e1 = s1.stamp(b"batch-1")
        e2 = s1.stamp(b"batch-2")
        assert e2["sequence"] == e1["sequence"] + 1

        # New stamper instance against the same DB resumes from the persisted value
        s2 = LineageStamper(self.SENSOR_ID, self.SECRET, db_path)
        e3 = s2.stamp(b"batch-3")
        assert e3["sequence"] == e2["sequence"] + 1

    def test_tamper_changes_hmac(self, tmp_path):
        stamper = self._stamper(tmp_path)
        e1 = stamper.stamp(b"original-bytes")
        # Re-derive HMAC over mutated bytes at the same sequence/timestamp
        tampered = _reference_hmac(
            self.SECRET.encode("utf-8"), b"original-Bytes",
            e1["sequence"], e1["sensor_id"], e1["timestamp"],
        )
        assert tampered != e1["hmac_hex"]

# -----------------------------------------------------------------------------
# Header construction
# -----------------------------------------------------------------------------

class TestBuildHeaders:
    def test_all_five_integrity_and_identity_headers_present(self, tmp_path):
        stamper = LineageStamper("host-x", "secret", str(tmp_path / "b.db"))
        envelope = stamper.stamp(b"payload")
        base = {
            "Content-Type": EXPECTED_CONTENT_TYPE,
            "Authorization": "Bearer token123",
            HDR_SENSOR_TYPE: EXPECTED_SENSOR_TYPE,
        }
        headers = stamper.build_headers(envelope, base)

        for required in (HDR_SENSOR_ID, HDR_SENSOR_TYPE, HDR_BATCH_SEQUENCE,
                         HDR_BATCH_TIMESTAMP, HDR_BATCH_HMAC):
            assert required in headers, f"missing required header {required}"

        assert headers["Content-Type"] == EXPECTED_CONTENT_TYPE
        assert headers["Authorization"] == "Bearer token123"
        assert headers[HDR_SENSOR_ID] == "host-x"
        assert headers[HDR_BATCH_HMAC] == envelope["hmac_hex"]
        assert headers[HDR_BATCH_SEQUENCE] == str(envelope["sequence"])
        assert headers[HDR_BATCH_TIMESTAMP] == str(envelope["timestamp"])

    def test_header_constant_names_match_ingress_contract(self):
        # axum/hyper HeaderMap normalises to lowercase, so case differences are
        # harmless on the wire, but the *names* (modulo case) must match exactly.
        assert HDR_SENSOR_ID.lower() == "x-sensor-id"
        assert HDR_SENSOR_TYPE.lower() == "x-sensor-type"
        assert HDR_BATCH_SEQUENCE.lower() == "x-batch-sequence"
        assert HDR_BATCH_TIMESTAMP.lower() == "x-batch-timestamp"
        assert HDR_BATCH_HMAC.lower() == "x-batch-hmac"

# -----------------------------------------------------------------------------
# Config / gateway URL contract (regression guard for the wrong-path bug:
# config.toml previously pointed at /api/v1/sensor/telemetry, which 404s
# against the real core_ingress route table -- only /api/v1/telemetry exists)
# -----------------------------------------------------------------------------

class TestGatewayUrlContract:
    def test_deploy_config_points_at_registered_ingress_route(self, repo_root):
        cfg_path = os.path.join(repo_root, "deploy", "config.toml")
        with open(cfg_path, "rb") as f:
            cfg = tomllib.load(f)
        url = cfg["nexus"]["gateway_url"]
        assert urlparse(url).path == EXPECTED_GATEWAY_PATH, (
            f"deploy/config.toml gateway_url path {urlparse(url).path!r} "
            f"does not match the only registered ingress route {EXPECTED_GATEWAY_PATH!r}"
        )

    def test_forwarder_default_fallback_points_at_registered_ingress_route(self, python_engine_dir):
        # NexusForwarder.__init__ falls back to a hardcoded default when
        # nexus.gateway_url is absent from config -- that default must also
        # resolve to a route the ingress actually serves.
        src = open(os.path.join(python_engine_dir, "nexus_forwarder.py")).read()
        assert f'"https://nexus-edge.local/{EXPECTED_GATEWAY_PATH.lstrip("/")}"' in src, (
            "NexusForwarder default gateway_url fallback no longer matches "
            f"the registered ingress route {EXPECTED_GATEWAY_PATH!r}"
        )

# -----------------------------------------------------------------------------
# End-to-end mock-ingress transmission test
# -----------------------------------------------------------------------------

class _CapturingHandler(BaseHTTPRequestHandler):
    captured = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": body,
        }
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args, **kwargs):
        pass  # silence default stderr logging

@pytest.fixture()
def mock_ingress():
    _CapturingHandler.captured = None
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}{EXPECTED_GATEWAY_PATH}"
    finally:
        server.shutdown()
        thread.join(timeout=5)

class TestEndToEndTransmission:
    SECRET = "e2e-shared-secret"
    SENSOR_ID = "e2e-sensor-host"

    def test_synthetic_batch_is_accepted_and_self_consistent(self, tmp_path, mock_ingress):
        stamper = LineageStamper(self.SENSOR_ID, self.SECRET, str(tmp_path / "baseline.db"))
        synthetic_parquet = b"PAR1" + os.urandom(256) + b"PAR1"  # not a real parquet file -- wire-format only

        envelope = stamper.stamp(synthetic_parquet)
        headers = stamper.build_headers(envelope, {
            "Content-Type": EXPECTED_CONTENT_TYPE,
            "Authorization": "Bearer test-token",
            HDR_SENSOR_TYPE: EXPECTED_SENSOR_TYPE,
        })

        resp = requests.post(mock_ingress, data=synthetic_parquet, headers=headers, timeout=10)
        assert resp.status_code == 202

        captured = _CapturingHandler.captured
        assert captured is not None
        assert captured["path"] == EXPECTED_GATEWAY_PATH
        assert captured["body"] == synthetic_parquet
        assert captured["headers"]["Content-Type"] == EXPECTED_CONTENT_TYPE
        assert captured["headers"]["Authorization"] == "Bearer test-token"
        assert captured["headers"][HDR_SENSOR_TYPE] == EXPECTED_SENSOR_TYPE
        assert captured["headers"][HDR_SENSOR_ID] == self.SENSOR_ID

        # Re-derive the HMAC server-side exactly as core_ingress would and confirm match
        server_side = _reference_hmac(
            self.SECRET.encode("utf-8"),
            captured["body"],
            int(captured["headers"][HDR_BATCH_SEQUENCE]),
            captured["headers"][HDR_SENSOR_ID],
            int(captured["headers"][HDR_BATCH_TIMESTAMP]),
        )
        assert server_side == captured["headers"][HDR_BATCH_HMAC]

    def test_tampered_payload_is_rejected_by_hmac_recheck(self, tmp_path, mock_ingress):
        """Simulates what core_ingress does: recompute HMAC over the bytes actually
        received and compare. A payload mutated in flight must fail verification --
        proving the stamped HMAC binds to the exact bytes transmitted."""
        stamper = LineageStamper(self.SENSOR_ID, self.SECRET, str(tmp_path / "baseline.db"))
        original = b"original-payload-bytes-0123456789"
        envelope = stamper.stamp(original)
        headers = stamper.build_headers(envelope, {"Content-Type": EXPECTED_CONTENT_TYPE})

        tampered = bytearray(original)
        tampered[0] ^= 0xFF

        resp = requests.post(mock_ingress, data=bytes(tampered), headers=headers, timeout=10)
        assert resp.status_code == 202  # the stub always 202s; verification happens server-side

        captured = _CapturingHandler.captured
        recomputed = _reference_hmac(
            self.SECRET.encode("utf-8"),
            captured["body"],
            int(captured["headers"][HDR_BATCH_SEQUENCE]),
            captured["headers"][HDR_SENSOR_ID],
            int(captured["headers"][HDR_BATCH_TIMESTAMP]),
        )
        assert recomputed != captured["headers"][HDR_BATCH_HMAC], (
            "HMAC must NOT validate when transmitted bytes differ from the stamped payload"
        )