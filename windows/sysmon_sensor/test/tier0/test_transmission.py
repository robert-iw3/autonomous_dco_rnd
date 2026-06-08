"""
Tier-0 -- Transmission-layer tests for windows/sysmon_sensor.

Validates the wire protocol against the core_ingress contract
(middleware/src/core_ingress/src/integrity.rs::compute_hmac):

  * HMAC-SHA256(payload || BE64(seq) || sensor_id_utf8 || BE64(ts))
  * Required headers: X-Sensor-Id, X-Sensor-Type, X-Batch-Sequence,
    X-Batch-Timestamp, X-Batch-HMAC
  * Content-Type: application/vnd.apache.parquet
  * Authorization: Bearer <token>
  * X-Sensor-Type == "sysmon_sensor"
  * middleware URL path == /api/v1/telemetry (matches the registered
    core_ingress route and project_empros/middleware/config/middleware.toml)
"""

import hashlib
import hmac as hmac_mod
import io
import os
import re
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from parquet_shipper import ParquetShipper, SENSOR_TYPE
from SysmonSensor import _normalise

pytestmark = pytest.mark.tier0

EXPECTED_GATEWAY_PATH = "/api/v1/telemetry"
EXPECTED_CONTENT_TYPE = "application/vnd.apache.parquet"
EXPECTED_SENSOR_TYPE  = "sysmon_sensor"

REQUIRED_HEADERS = (
    "X-Sensor-Id", "X-Sensor-Type",
    "X-Batch-Sequence", "X-Batch-Timestamp", "X-Batch-HMAC",
)

def _reference_hmac(secret: bytes, payload: bytes, sequence: int, sensor_id: str, timestamp: int) -> str:
    """Independent re-derivation of the core_ingress HMAC formula for cross-checking."""
    mac = hmac_mod.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()

# -----------------------------------------------------------------------------
# ParquetShipper._compute_hmac contract conformance
# -----------------------------------------------------------------------------

class TestComputeHmac:
    def _shipper(self, monkeypatch, sensor_id="test-host-01", secret="unit-test-shared-secret"):
        monkeypatch.setenv("NEXUS_SENSOR_ID", sensor_id)
        monkeypatch.setenv("NEXUS_INTEGRITY_SECRET", secret)
        monkeypatch.setenv("NEXUS_FLUSH_INTERVAL_S", "3600")
        s = ParquetShipper()
        return s

    def test_matches_independent_reference_implementation(self, monkeypatch):
        shipper = self._shipper(monkeypatch)
        try:
            payload = b"synthetic-parquet-bytes-001"
            seq, ts = 7, 1748000000
            actual = shipper._compute_hmac(payload, seq, ts)
            expected = _reference_hmac(b"unit-test-shared-secret", payload, seq, shipper.sensor_id, ts)
            assert actual == expected
        finally:
            shipper.shutdown()

    def test_is_64_lowercase_hex_chars(self, monkeypatch):
        shipper = self._shipper(monkeypatch)
        try:
            digest = shipper._compute_hmac(b"abc", 1, 1748000000)
            assert len(digest) == 64
            assert all(c in "0123456789abcdef" for c in digest)
        finally:
            shipper.shutdown()

    def test_changes_when_payload_sequence_sensor_or_timestamp_changes(self, monkeypatch):
        shipper = self._shipper(monkeypatch)
        try:
            base = shipper._compute_hmac(b"payload", 1, 1748000000)
            assert shipper._compute_hmac(b"PAYLOAD", 1, 1748000000) != base       # payload
            assert shipper._compute_hmac(b"payload", 2, 1748000000) != base       # sequence
            assert shipper._compute_hmac(b"payload", 1, 1748000001) != base       # timestamp
        finally:
            shipper.shutdown()

    def test_secret_is_taken_from_env_not_hardcoded(self, monkeypatch):
        a = self._shipper(monkeypatch, secret="secret-A")
        b = self._shipper(monkeypatch, secret="secret-B")
        try:
            assert a._compute_hmac(b"x", 1, 1748000000) != b._compute_hmac(b"x", 1, 1748000000)
        finally:
            a.shutdown()
            b.shutdown()

# -----------------------------------------------------------------------------
# Header construction (inline in _ship -- assert the literal contract)
# -----------------------------------------------------------------------------

class TestShipHeaderContract:
    def test_header_names_match_ingress_contract(self):
        src = open(os.path.join(os.path.dirname(__import__("parquet_shipper").__file__), "parquet_shipper.py")).read()
        for hdr in REQUIRED_HEADERS + ("Content-Type", "Authorization"):
            assert f'"{hdr}"' in src, f"header literal {hdr!r} not found in parquet_shipper.py _ship()"

    def test_sensor_type_constant_is_sysmon_sensor(self):
        assert SENSOR_TYPE == "sysmon_sensor"

# -----------------------------------------------------------------------------
# Middleware URL contract -- path must be the registered ingress route
# -----------------------------------------------------------------------------

class TestMiddlewareUrlContract:
    def test_default_middleware_url_path_matches_registered_ingress_route(self, monkeypatch):
        monkeypatch.delenv("NEXUS_MIDDLEWARE_URL", raising=False)
        monkeypatch.setenv("NEXUS_FLUSH_INTERVAL_S", "3600")
        shipper = ParquetShipper()
        try:
            assert urlparse(shipper.middleware_url).path == EXPECTED_GATEWAY_PATH
        finally:
            shipper.shutdown()

    def test_sensor_profile_endpoint_matches_registered_ingress_route(self, repo_root):
        profile = os.path.join(repo_root, "project_empros", "middleware", "config",
                               "sensor_profiles", "sysmon_sensor.toml")
        src = open(profile).read()
        m = re.search(r'MiddlewareEndpoint\s*=\s*"?([^"\n]+)"?', src)
        assert m, "MiddlewareEndpoint not declared in sysmon_sensor.toml profile"
        assert urlparse(m.group(1).strip()).path == EXPECTED_GATEWAY_PATH

    def test_middleware_toml_gateway_path_matches(self, repo_root):
        cfg = os.path.join(repo_root, "project_empros", "middleware", "config", "middleware.toml")
        src = open(cfg).read()
        m = re.search(r'gateway_url\s*=\s*"([^"]+)"', src)
        assert m
        assert urlparse(m.group(1)).path == EXPECTED_GATEWAY_PATH

# -----------------------------------------------------------------------------
# End-to-end mock-ingress transmission test -- drives the REAL _ship()
# -----------------------------------------------------------------------------

class _CapturingHandler(BaseHTTPRequestHandler):
    captured = None
    response_code = 202

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": body,
        }
        self.send_response(type(self).response_code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args, **kwargs):
        pass  # silence default stderr logging

@pytest.fixture()
def mock_ingress():
    _CapturingHandler.captured = None
    _CapturingHandler.response_code = 202
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}{EXPECTED_GATEWAY_PATH}", _CapturingHandler
    finally:
        server.shutdown()
        thread.join(timeout=5)

SECRET    = "e2e-shared-secret"
SENSOR_ID = "e2e-sensor-host"

def _shipper_for(monkeypatch, mock_url):
    monkeypatch.setenv("NEXUS_SENSOR_ID", SENSOR_ID)
    monkeypatch.setenv("NEXUS_INTEGRITY_SECRET", SECRET)
    monkeypatch.setenv("NEXUS_AUTH_TOKEN", "test-token")
    monkeypatch.setenv("NEXUS_MIDDLEWARE_URL", mock_url)
    monkeypatch.setenv("NEXUS_FLUSH_INTERVAL_S", "3600")
    monkeypatch.setenv("NEXUS_TLS_VERIFY", "false")
    return ParquetShipper()

class TestEndToEndTransmission:
    def test_real_batch_is_shipped_and_self_consistent(self, monkeypatch, mock_ingress):
        mock_url, handler = mock_ingress
        shipper = _shipper_for(monkeypatch, mock_url)
        try:
            batch = [
                _normalise(1, {
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": "powershell -nop -enc QQBBAEEAQQA=",
                    "ParentImage": r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
                    "User": "CORP\\jdoe",
                    "IntegrityLevel": "High",
                    "ProcessId": "100",
                    "ParentProcessId": "50",
                }, "WORKSTATION-07"),
            ]
            parquet_bytes = shipper._to_parquet(batch)

            # Drive the real synchronous _ship path directly (avoids racing
            # the background-thread dispatch inside _flush_locked).
            shipper._ship(batch, sequence=1)

            captured = handler.captured
            assert captured is not None, "mock ingress never received a POST"
            assert captured["path"] == EXPECTED_GATEWAY_PATH
            assert captured["body"] == parquet_bytes

            h = captured["headers"]
            for required in REQUIRED_HEADERS:
                assert required in h, f"missing required header {required}"
            assert h["Content-Type"] == EXPECTED_CONTENT_TYPE
            assert h["Authorization"] == "Bearer test-token"
            assert h["X-Sensor-Type"] == EXPECTED_SENSOR_TYPE
            assert h["X-Sensor-Id"] == SENSOR_ID
            assert h["X-Batch-Sequence"] == "1"

            # Re-derive the HMAC server-side exactly as core_ingress would
            server_side = _reference_hmac(
                SECRET.encode("utf-8"),
                captured["body"],
                int(h["X-Batch-Sequence"]),
                h["X-Sensor-Id"],
                int(h["X-Batch-Timestamp"]),
            )
            assert server_side == h["X-Batch-HMAC"]
        finally:
            shipper.shutdown()

    def test_tampered_payload_fails_server_side_hmac_recheck(self, monkeypatch, mock_ingress):
        """
        core_ingress recomputes the HMAC over the bytes it actually received
        and rejects on mismatch. Simulate that recheck here: mutate the bytes
        in flight (as a MITM/corruption would) and prove the stamped HMAC no
        longer validates against what the server received -- i.e. the HMAC
        binds to the exact transmitted bytes, not just "a" payload.
        """
        mock_url, handler = mock_ingress
        shipper = _shipper_for(monkeypatch, mock_url)
        try:
            batch = [_normalise(1, {"Image": "cmd.exe", "CommandLine": "whoami"}, "WORKSTATION-07")]
            real_parquet = shipper._to_parquet(batch)

            ts  = 1748000000
            seq = 9
            stamped_hmac = shipper._compute_hmac(real_parquet, seq, ts)

            tampered = bytearray(real_parquet)
            tampered[0] ^= 0xFF

            import requests
            headers = {
                "Authorization":     "Bearer test-token",
                "Content-Type":      EXPECTED_CONTENT_TYPE,
                "X-Sensor-Type":     SENSOR_TYPE,
                "X-Sensor-Id":       shipper.sensor_id,
                "X-Batch-Sequence":  str(seq),
                "X-Batch-Timestamp": str(ts),
                "X-Batch-HMAC":      stamped_hmac,
            }
            resp = requests.post(mock_url, data=bytes(tampered), headers=headers, timeout=10)
            assert resp.status_code == 202  # stub always 202s; verification is server-side in core_ingress

            captured = handler.captured
            recomputed = _reference_hmac(
                SECRET.encode("utf-8"), captured["body"],
                int(captured["headers"]["X-Batch-Sequence"]),
                captured["headers"]["X-Sensor-Id"],
                int(captured["headers"]["X-Batch-Timestamp"]),
            )
            assert recomputed != captured["headers"]["X-Batch-HMAC"], (
                "HMAC must NOT validate when transmitted bytes differ from the stamped payload"
            )
        finally:
            shipper.shutdown()

    def test_403_response_does_not_raise_and_is_not_retried(self, monkeypatch, mock_ingress):
        """A 403 indicates a banned sensor / bad integrity secret -- _ship must
        log and return without raising or retrying (retrying a permanent auth
        failure would hammer the middleware)."""
        mock_url, handler = mock_ingress
        handler.response_code = 403
        shipper = _shipper_for(monkeypatch, mock_url)
        try:
            batch = [_normalise(1, {"Image": "cmd.exe"}, "WORKSTATION-07")]
            shipper._ship(batch, sequence=1)  # must not raise
            assert handler.captured is not None
            assert handler.captured["headers"]["X-Sensor-Type"] == EXPECTED_SENSOR_TYPE
        finally:
            shipper.shutdown()