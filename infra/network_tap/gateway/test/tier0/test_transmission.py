"""
Tier-0 -- Transmission-layer conformance for the network_tap (arkime-ml-gateway) sensor.
"""
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest

from network_tap_logic_mirror import (
    compute_hmac,
    REQUIRED_HEADERS,
    GATEWAY_COMPUTED_HEADERS,
    CONTENT_TYPE,
    WIRE_SENSOR_TYPE,
    HDR_SENSOR_ID,
    HDR_BATCH_SEQUENCE,
    HDR_BATCH_TIMESTAMP,
    HDR_BATCH_HMAC,
    sensor_id_for,
)

pytestmark = pytest.mark.tier0

SECRET = b"network-tap-tier0-integrity-secret"
SENSOR_ID = sensor_id_for("network-tap-alpha", WIRE_SENSOR_TYPE)

def _reference_hmac(payload: bytes, sequence: int, sensor_id: str, ts: int) -> str:
    """Independent re-derivation of the core_ingress / LineageStamper HMAC
    contract, cross-checked against network_tap_logic_mirror.compute_hmac
    (itself mirroring stamper.rs's LineageStamper::stamp)."""
    import hashlib
    import hmac as hmac_mod

    mac = hmac_mod.new(SECRET, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", ts))
    return mac.hexdigest()

# -----------------------------------------------------------------------------
# HMAC formula contract
# -----------------------------------------------------------------------------

class TestComputeHmacContract:
    def test_matches_independent_reference(self):
        payload = b"synthetic-network-tap-parquet-batch"
        assert compute_hmac(SECRET, payload, 1, SENSOR_ID, 1_700_000_000) == \
            _reference_hmac(payload, 1, SENSOR_ID, 1_700_000_000)

    def test_is_64_char_lowercase_hex(self):
        digest = compute_hmac(SECRET, b"x", 1, SENSOR_ID, 1)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_field_order_matches_documented_bug_fix(self):
        """stamper.rs documents that an earlier version used LE endianness and
        the wrong field order (seq_LE || ts_LE || sensor_id || parquet), which
        produced a different digest than the gateway expected and got every
        network_tap batch rejected with 400 / the sensor banned. Confirm our
        mirror's BE/payload-first ordering diverges from that broken
        historical ordering."""
        payload = b"order-sensitive-flow-batch-bytes"
        seq, ts = 3, 1_700_000_300

        correct = compute_hmac(SECRET, payload, seq, SENSOR_ID, ts)

        import hashlib
        import hmac as hmac_mod
        broken = hmac_mod.new(SECRET, digestmod=hashlib.sha256)
        broken.update(struct.pack("<Q", seq))          # wrong: LE, sequence first
        broken.update(struct.pack("<Q", ts))           # wrong: LE, timestamp second
        broken.update(SENSOR_ID.encode("utf-8"))
        broken.update(payload)                         # wrong: payload last
        assert correct != broken.hexdigest()

    def test_sequence_changes_digest(self):
        payload = b"same-flow-bytes"
        ts = 1_700_000_000
        d1 = compute_hmac(SECRET, payload, 1, SENSOR_ID, ts)
        d2 = compute_hmac(SECRET, payload, 2, SENSOR_ID, ts)
        assert d1 != d2

    def test_tampered_payload_fails_recheck(self):
        payload = b"original-flow-batch-bytes"
        seq, ts = 7, 1_700_000_500
        digest = compute_hmac(SECRET, payload, seq, SENSOR_ID, ts)
        assert compute_hmac(SECRET, b"tampered-flow-batch-bytes!!", seq, SENSOR_ID, ts) != digest

# -----------------------------------------------------------------------------
# Header contract
# -----------------------------------------------------------------------------

class TestRequiredHeaderContract:
    def test_required_headers_match_ingress_expectations(self):
        contract_headers = {
            HDR_SENSOR_ID, "X-Sensor-Type", HDR_BATCH_SEQUENCE,
            HDR_BATCH_TIMESTAMP, HDR_BATCH_HMAC, "Content-Type", "Authorization",
        }
        assert contract_headers == set(REQUIRED_HEADERS)

    def test_partition_headers_are_disjoint_from_integrity_contract(self):
        # X-Partition-Date / X-Partition-Hour are sensor-computed *and sent*
        # by network_tap (unlike sentinel, where they're purely gateway-side --
        # see nexus.rs:549-550 extract_partition_hints()). They must stay out
        # of the required-header *integrity* contract so a missing partition
        # hint never gets misdiagnosed as an HMAC/auth failure.
        assert set(GATEWAY_COMPUTED_HEADERS).isdisjoint(set(REQUIRED_HEADERS))

    def test_content_type_is_parquet(self):
        assert CONTENT_TYPE == "application/vnd.apache.parquet"

# -----------------------------------------------------------------------------
# In-process mock ingress -- captures and validates a synthetic POST built the
# same way transmit_loop() builds its real request (nexus.rs:542-551).
# -----------------------------------------------------------------------------

class _CapturingHandler(BaseHTTPRequestHandler):
    captured = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            "headers": self.headers,  # case-insensitive Message -- preserve live object
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

def _post_synthetic_batch(url, payload, sequence, ts, partition_date="2026-06-07", partition_hour="14",
                          token="tier0-test-token"):
    import urllib.request

    digest = compute_hmac(SECRET, payload, sequence, SENSOR_ID, ts)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": CONTENT_TYPE,
        "X-Sensor-Type": WIRE_SENSOR_TYPE,
        HDR_SENSOR_ID: SENSOR_ID,
        HDR_BATCH_SEQUENCE: str(sequence),
        HDR_BATCH_TIMESTAMP: str(ts),
        HDR_BATCH_HMAC: digest,
        "X-Partition-Date": partition_date,
        "X-Partition-Hour": partition_hour,
    }
    req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, digest

class TestEndToEndTransmission:
    def test_synthetic_batch_reaches_mock_ingress_with_valid_contract(self, mock_ingress):
        payload = b"\x50\x41\x52\x31synthetic-network-tap-parquet-bytes"
        sequence, ts = 1, 1_700_000_000
        status, digest = _post_synthetic_batch(mock_ingress, payload, sequence, ts)
        assert status == 200

        captured = _CapturingHandler.captured
        assert captured["path"] == "/api/v1/telemetry"
        assert captured["body"] == payload

        h = captured["headers"]
        assert h["Content-Type"] == CONTENT_TYPE
        assert h["X-Sensor-Type"] == WIRE_SENSOR_TYPE
        assert h[HDR_SENSOR_ID] == SENSOR_ID
        assert h[HDR_BATCH_SEQUENCE] == str(sequence)
        assert h[HDR_BATCH_TIMESTAMP] == str(ts)
        assert h[HDR_BATCH_HMAC] == digest
        assert h["Authorization"].startswith("Bearer ")
        assert h["X-Partition-Date"] == "2026-06-07"
        assert h["X-Partition-Hour"] == "14"

        # Server-side re-derivation must independently confirm the HMAC
        server_side = compute_hmac(SECRET, captured["body"], sequence, SENSOR_ID, ts)
        assert server_side == digest

    def test_tampered_in_flight_payload_breaks_hmac_recheck(self, mock_ingress):
        payload = b"original-network-tap-batch-bytes"
        sequence, ts = 2, 1_700_000_100
        _, digest = _post_synthetic_batch(mock_ingress, payload, sequence, ts)
        captured = _CapturingHandler.captured

        # Simulate on-the-wire tampering: re-derive the HMAC over different
        # bytes than what the gateway received -- it must not match.
        recheck = compute_hmac(SECRET, b"mutated-network-tap-batch-bytes!", sequence, SENSOR_ID, ts)
        assert recheck != digest
        assert captured["body"] == payload

    def test_sensor_id_binds_into_hmac_so_spoofed_identity_fails(self, mock_ingress):
        """A batch stamped for sensor "network-tap-alpha-network_tap" must not
        verify under a different claimed sensor_id -- the HMAC binds identity,
        preventing a compromised sensor from impersonating another tap."""
        payload = b"impersonation-attempt-batch-bytes"
        sequence, ts = 5, 1_700_000_400
        digest = compute_hmac(SECRET, payload, sequence, SENSOR_ID, ts)

        spoofed_id = "network-tap-bravo-network_tap"
        recheck = compute_hmac(SECRET, payload, sequence, spoofed_id, ts)
        assert recheck != digest