"""
Tier-0 -- Transmission-layer conformance for the Nexus GCP connectors.
"""
import re
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest

from gcp_connectors_logic_mirror import (
    compute_hmac,
    sensor_id_for_vpc,
    REQUIRED_HEADERS,
    CONTENT_TYPE,
    WIRE_SENSOR_TYPE,
    HDR_SENSOR_ID,
    HDR_SENSOR_TYPE,
    HDR_BATCH_SEQUENCE,
    HDR_BATCH_TIMESTAMP,
    HDR_BATCH_HMAC,
)

pytestmark = pytest.mark.tier0

import os
def _read(*parts):
    with open(os.path.join(*parts)) as fh:
        return fh.read()

SECRET    = b"gcp-connector-tier0-integrity-secret"
SENSOR_ID = sensor_id_for_vpc("test-project", "lab", "us-central1", "default")

def _reference_hmac(payload: bytes, sequence: int, sensor_id: str, ts: int) -> str:
    import hashlib
    import hmac as hmac_mod
    mac = hmac_mod.new(SECRET, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", ts))
    return mac.hexdigest()

# ---------------------------------------------------------------------------
# HMAC formula contract
# ---------------------------------------------------------------------------

class TestComputeHmacContract:
    def test_matches_independent_reference(self):
        payload = b"synthetic-gcp-connector-parquet-batch"
        assert compute_hmac(SECRET, payload, 1, SENSOR_ID, 1_700_000_000) == \
            _reference_hmac(payload, 1, SENSOR_ID, 1_700_000_000)

    def test_is_64_char_lowercase_hex(self):
        digest = compute_hmac(SECRET, b"x", 1, SENSOR_ID, 1)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_byte_order_is_payload_then_be64_seq_then_id_then_be64_ts(self):
        payload = b"order-sensitive-gcp-batch-bytes"
        seq, ts  = 3, 1_700_000_300

        correct = compute_hmac(SECRET, payload, seq, SENSOR_ID, ts)

        import hashlib
        import hmac as hmac_mod
        wrong = hmac_mod.new(SECRET, digestmod=hashlib.sha256)
        wrong.update(SENSOR_ID.encode("utf-8"))
        wrong.update(struct.pack("<Q", seq))
        wrong.update(struct.pack("<Q", ts))
        wrong.update(payload)
        assert correct != wrong.hexdigest()

    def test_sequence_changes_digest(self):
        payload = b"same-gcp-batch-bytes"
        ts = 1_700_000_000
        d1 = compute_hmac(SECRET, payload, 1, SENSOR_ID, ts)
        d2 = compute_hmac(SECRET, payload, 2, SENSOR_ID, ts)
        assert d1 != d2

    def test_tampered_payload_fails_recheck(self):
        payload = b"original-gcp-connector-batch-bytes"
        seq, ts = 7, 1_700_000_500
        digest = compute_hmac(SECRET, payload, seq, SENSOR_ID, ts)
        assert compute_hmac(SECRET, b"tampered-gcp-connector-batch-bytes!!", seq, SENSOR_ID, ts) != digest

    def test_mirror_matches_real_compute_hmac_source_byte_layout(self, connector_dir):
        src = _read(connector_dir, "src", "transmitter.rs")
        m = re.search(r"fn compute_hmac\(.*?\{(.*?)\n    \}", src, re.DOTALL)
        assert m, "could not locate compute_hmac() in transmitter.rs"
        body = m.group(1)
        order = re.findall(
            r"msg\.extend_from_slice\(&?(payload|sequence\.to_be_bytes\(\)|sensor_id\.as_bytes\(\)|timestamp\.to_be_bytes\(\))\)",
            body,
        )
        assert order == ["payload", "sequence.to_be_bytes()", "sensor_id.as_bytes()", "timestamp.to_be_bytes()"]

# ---------------------------------------------------------------------------
# Header contract
# ---------------------------------------------------------------------------

class TestRequiredHeaderContract:
    def test_required_headers_match_ingress_expectations(self):
        contract = {
            HDR_SENSOR_ID, HDR_SENSOR_TYPE, HDR_BATCH_SEQUENCE,
            HDR_BATCH_TIMESTAMP, HDR_BATCH_HMAC, "Content-Type", "Authorization",
        }
        assert contract == set(REQUIRED_HEADERS)
        assert len(REQUIRED_HEADERS) == 7

    def test_content_type_is_parquet(self):
        assert CONTENT_TYPE == "application/vnd.apache.parquet"

    def test_real_source_sends_exactly_seven_headers(self, connector_dir):
        src = _read(connector_dir, "src", "transmitter.rs")
        assert ".bearer_auth(&self.config.auth_token)" in src
        assert "pub auth_token: String," in _read(connector_dir, "src", "config.rs")
        assert 'env::var("AUTH_TOKEN")' in _read(connector_dir, "src", "config.rs")
        literal_headers = re.findall(r'\.header\("([A-Za-z-]+)",', src)
        assert set(literal_headers) | {"Authorization"} == set(REQUIRED_HEADERS)
        assert len(literal_headers) == 6

# ---------------------------------------------------------------------------
# In-process mock ingress
# ---------------------------------------------------------------------------

class _CapturingHandler(BaseHTTPRequestHandler):
    captured = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            "headers": self.headers,
            "body": body,
        }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass

@pytest.fixture()
def mock_ingress():
    _CapturingHandler.captured = None
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/v1/telemetry"
    finally:
        server.shutdown()
        thread.join(timeout=5)

def _post_synthetic_batch(url, payload, sequence, ts, sensor_type, sensor_id=SENSOR_ID, token="tier0-test-token"):
    import urllib.request
    digest = compute_hmac(SECRET, payload, sequence, sensor_id, ts)
    headers = {
        "Authorization":    f"Bearer {token}",
        "Content-Type":     CONTENT_TYPE,
        HDR_BATCH_SEQUENCE: str(sequence),
        HDR_BATCH_TIMESTAMP: str(ts),
        HDR_SENSOR_ID:      sensor_id,
        HDR_SENSOR_TYPE:    sensor_type,
        HDR_BATCH_HMAC:     digest,
    }
    req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, digest

class TestEndToEndTransmission:
    @pytest.mark.parametrize("connector", ["audit", "scc", "vpc"])
    def test_synthetic_batch_reaches_mock_ingress_with_valid_contract(self, mock_ingress, connector):
        payload = b"\x50\x41\x52\x31synthetic-gcp-" + connector.encode() + b"-parquet-bytes"
        sequence, ts = 1, 1_700_000_000
        sensor_type = WIRE_SENSOR_TYPE[connector]
        status, digest = _post_synthetic_batch(mock_ingress, payload, sequence, ts, sensor_type)
        assert status == 200

        captured = _CapturingHandler.captured
        assert captured["path"] == "/api/v1/telemetry"
        assert captured["body"] == payload

        h = captured["headers"]
        assert h["Content-Type"] == CONTENT_TYPE
        assert h[HDR_SENSOR_TYPE] == sensor_type
        assert h[HDR_SENSOR_ID] == SENSOR_ID
        assert h[HDR_BATCH_SEQUENCE] == str(sequence)
        assert h[HDR_BATCH_TIMESTAMP] == str(ts)
        assert h[HDR_BATCH_HMAC] == digest
        assert h["Authorization"].startswith("Bearer ")

        server_side = compute_hmac(SECRET, captured["body"], sequence, SENSOR_ID, ts)
        assert server_side == digest

    def test_tampered_in_flight_payload_breaks_hmac_recheck(self, mock_ingress):
        payload = b"original-gcp-connector-batch-bytes"
        sequence, ts = 2, 1_700_000_100
        _post_synthetic_batch(mock_ingress, payload, sequence, ts, WIRE_SENSOR_TYPE["audit"])
        captured = _CapturingHandler.captured
        digest = compute_hmac(SECRET, captured["body"], sequence, SENSOR_ID, ts)
        recheck = compute_hmac(SECRET, b"mutated-gcp-connector-batch-bytes!", sequence, SENSOR_ID, ts)
        assert recheck != digest
        assert captured["body"] == payload

    def test_sensor_id_binds_into_hmac_so_spoofed_project_fails(self, mock_ingress):
        """HMAC binds the sensor_id, preventing a compromised connector from
        impersonating a different GCP project/region pairing."""
        payload = b"impersonation-attempt-gcp-batch-bytes"
        sequence, ts = 5, 1_700_000_400
        digest = compute_hmac(SECRET, payload, sequence, SENSOR_ID, ts)
        spoofed_id = sensor_id_for_vpc("attacker-project", "prod", "eu-west1", "attacker-subnet")
        recheck = compute_hmac(SECRET, payload, sequence, spoofed_id, ts)
        assert recheck != digest

    def test_wire_sensor_type_distinguishes_connectors(self, mock_ingress):
        """Each connector must be individually identifiable by X-Sensor-Type."""
        seen = set()
        for i, connector in enumerate(("audit", "scc", "vpc"), start=10):
            payload = f"distinct-gcp-batch-{connector}".encode()
            _post_synthetic_batch(mock_ingress, payload, i, 1_700_001_000 + i, WIRE_SENSOR_TYPE[connector])
            seen.add(_CapturingHandler.captured["headers"][HDR_SENSOR_TYPE])
        assert seen == set(WIRE_SENSOR_TYPE.values())
        assert len(seen) == 3