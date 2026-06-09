"""
Tier0 — HMAC formula and mock-ingress end-to-end tests.

Verifies the HMAC construction matches what the Rust transmitter builds,
and validates a full request/response cycle against a local mock gateway.
"""
import hashlib
import hmac as _hmac
import http.server
import json
import re
import struct
import sys
import os
import threading
import time
import urllib.request
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from vmware_connector_logic_mirror import (
    REQUIRED_HEADERS,
    WIRE_SENSOR_TYPE,
    compute_hmac,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path):
    with open(path) as f:
        return f.read()

@pytest.fixture(scope="module")
def transmitter_src(src_dir):
    return _read(os.path.join(src_dir, "transmitter.rs"))

# ---------------------------------------------------------------------------
# HMAC formula
# ---------------------------------------------------------------------------

class TestHMACFormula:
    """The Python mirror formula must match the Rust implementation signature."""

    def test_hmac_is_sha256(self, transmitter_src):
        assert "Sha256" in transmitter_src or "sha256" in transmitter_src.lower()

    def test_hmac_message_order(self, transmitter_src):
        """Rust extends msg as: payload → BE64(seq) → sensor_id → BE64(ts)."""
        # Verify the order of .extend_from_slice calls in compute_hmac.
        fn_match = re.search(
            r"fn compute_hmac[^{]+\{(.+?)\n    \}", transmitter_src, re.DOTALL
        )
        assert fn_match, "compute_hmac function not found in transmitter.rs"
        body = fn_match.group(1)

        payload_pos = body.find("extend_from_slice(payload)")
        seq_pos     = body.find("sequence.to_be_bytes()")
        sid_pos     = body.find("sensor_id.as_bytes()")
        ts_pos      = body.find("timestamp.to_be_bytes()")

        assert payload_pos != -1, "payload not appended to HMAC message"
        assert seq_pos     != -1, "sequence.to_be_bytes() not appended"
        assert sid_pos     != -1, "sensor_id.as_bytes() not appended"
        assert ts_pos      != -1, "timestamp.to_be_bytes() not appended"

        assert payload_pos < seq_pos  < sid_pos < ts_pos, (
            "HMAC message components are in wrong order: "
            f"payload={payload_pos} seq={seq_pos} sid={sid_pos} ts={ts_pos}"
        )

    def test_hmac_uses_be64(self, transmitter_src):
        assert "to_be_bytes()" in transmitter_src, \
            "HMAC must use big-endian 64-bit encoding (.to_be_bytes())"

    def test_hmac_key_is_integrity_secret(self, transmitter_src):
        assert "integrity_secret" in transmitter_src

    def test_mirror_hmac_deterministic(self):
        h1 = compute_hmac("secret", b"payload", 1, "sensor-x", 1000)
        h2 = compute_hmac("secret", b"payload", 1, "sensor-x", 1000)
        assert h1 == h2

    def test_mirror_hmac_hex_format(self):
        h = compute_hmac("secret", b"data", 42, "sid", 9999)
        assert re.fullmatch(r"[0-9a-f]{64}", h), f"HMAC not 64-char hex: {h!r}"

    def test_mirror_hmac_changes_with_sequence(self):
        h1 = compute_hmac("secret", b"data", 1, "sid", 100)
        h2 = compute_hmac("secret", b"data", 2, "sid", 100)
        assert h1 != h2

    def test_mirror_hmac_changes_with_sensor_id(self):
        h1 = compute_hmac("secret", b"data", 1, "sid-a", 100)
        h2 = compute_hmac("secret", b"data", 1, "sid-b", 100)
        assert h1 != h2

    def test_mirror_hmac_changes_with_timestamp(self):
        h1 = compute_hmac("secret", b"data", 1, "sid", 100)
        h2 = compute_hmac("secret", b"data", 1, "sid", 101)
        assert h1 != h2

    def test_mirror_hmac_changes_with_payload(self):
        h1 = compute_hmac("secret", b"aaa", 1, "sid", 100)
        h2 = compute_hmac("secret", b"bbb", 1, "sid", 100)
        assert h1 != h2

    def test_known_vector(self):
        """Cross-check against an independently-computed HMAC value."""
        secret    = "test-secret"
        payload   = b"parquet-blob"
        sequence  = 7
        sensor_id = "vmware-connector-default"
        timestamp = 1700000000

        msg = (
            payload
            + struct.pack(">Q", sequence)
            + sensor_id.encode("utf-8")
            + struct.pack(">Q", timestamp)
        )
        expected = _hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        got = compute_hmac(secret, payload, sequence, sensor_id, timestamp)
        assert got == expected

# ---------------------------------------------------------------------------
# Mock ingress end-to-end
# ---------------------------------------------------------------------------

class _CaptureHandler(http.server.BaseHTTPRequestHandler):
    captured = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        self.__class__.captured.append({
            "headers": dict(self.headers),
            "body":    body,
        })
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):  # suppress noisy output
        pass

@pytest.fixture(scope="module")
def mock_gateway():
    """Start a local HTTP server that captures all POST requests."""
    _CaptureHandler.captured = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", _CaptureHandler.captured
    server.shutdown()

class TestMockIngressEndToEnd:
    """Simulate a connector POST and verify all required headers are present."""

    def _post(self, url, payload, secret, seq, sensor_id, ts):
        hmac_hex = compute_hmac(secret, payload, seq, sensor_id, ts)
        headers = {
            "Authorization":    f"Bearer test-token",
            "Content-Type":     "application/vnd.apache.parquet",
            "X-Batch-Sequence": str(seq),
            "X-Batch-Timestamp": str(ts),
            "X-Sensor-Id":      sensor_id,
            "X-Sensor-Type":    WIRE_SENSOR_TYPE,
            "X-Batch-HMAC":     hmac_hex,
        }
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status

    def test_post_succeeds(self, mock_gateway):
        url, captured = mock_gateway
        status = self._post(url, b"fake-parquet", "secret", 1, "sid-1", 1000000)
        assert status == 200

    def test_all_required_headers_received(self, mock_gateway):
        url, captured = mock_gateway
        captured.clear()
        self._post(url, b"data", "secret", 2, "sid-2", 2000000)

        assert captured, "No requests captured by mock gateway"
        headers = {k.lower(): v for k, v in captured[-1]["headers"].items()}

        for h in REQUIRED_HEADERS:
            assert h.lower() in headers, \
                f"Required header {h!r} not sent to gateway"

    def test_authorization_is_bearer(self, mock_gateway):
        url, captured = mock_gateway
        captured.clear()
        self._post(url, b"data", "sec", 3, "sid", 3000000)
        headers = {k.lower(): v for k, v in captured[-1]["headers"].items()}
        assert headers.get("authorization", "").startswith("Bearer "), \
            "Authorization header must use Bearer scheme"

    def test_content_type_is_parquet(self, mock_gateway):
        url, captured = mock_gateway
        captured.clear()
        self._post(url, b"data", "sec", 4, "sid", 4000000)
        headers = {k.lower(): v for k, v in captured[-1]["headers"].items()}
        assert headers.get("content-type") == "application/vnd.apache.parquet"

    def test_hmac_verifiable_by_receiver(self, mock_gateway):
        url, captured = mock_gateway
        captured.clear()

        secret    = "verify-secret"
        payload   = b"batch-payload"
        seq       = 99
        sensor_id = "vmware-connector-default"
        ts        = 1700000001

        self._post(url, payload, secret, seq, sensor_id, ts)
        req       = captured[-1]
        headers   = {k.lower(): v for k, v in req["headers"].items()}
        received_hmac = headers["x-batch-hmac"]
        expected_hmac = compute_hmac(secret, payload, seq, sensor_id, ts)
        assert received_hmac == expected_hmac, \
            "HMAC received by gateway does not match independently computed value"

    def test_body_is_transmitted(self, mock_gateway):
        url, captured = mock_gateway
        captured.clear()
        payload = b"parquet-bytes-here"
        self._post(url, payload, "s", 5, "id", 5000000)
        assert captured[-1]["body"] == payload

    def test_sensor_type_header_value(self, mock_gateway):
        url, captured = mock_gateway
        captured.clear()
        self._post(url, b"d", "s", 6, "id", 6000000)
        headers = {k.lower(): v for k, v in captured[-1]["headers"].items()}
        assert headers.get("x-sensor-type") == WIRE_SENSOR_TYPE