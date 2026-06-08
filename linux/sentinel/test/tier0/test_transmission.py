"""
Tier-0 -- Transmission-layer conformance for the linux_sentinel sensor.

linux-sentinel is a Rust binary with no embedded Python interpreter, so we
can't drive its real transmission task from pytest directly (that's what the
HMAC/round-trip `cargo test` coverage in test/tier1 is for). Instead this
module independently re-derives the two pieces of the wire contract that must
match byte-for-byte -- the HMAC formula (shared via nexus_integrity across
every Nexus sensor) and the required-header set -- and fires them at a real
in-process mock ingress server, exactly the way parquet_transmitter.rs's
forwarder builds its real POST, to validate the *contract* end to end with
synthetic batch bytes.
"""
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sentinel_logic_mirror import (
    compute_hmac,
    REQUIRED_HEADERS,
    CONTENT_TYPE,
    WIRE_SENSOR_TYPE,
    HDR_SENSOR_ID,
    HDR_BATCH_SEQUENCE,
    HDR_BATCH_TIMESTAMP,
    HDR_BATCH_HMAC,
)

pytestmark = pytest.mark.tier0

SECRET = b"sentinel-tier0-integrity-secret"
SENSOR_ID = "tier0-host-sentinel"

def _reference_hmac(payload: bytes, sequence: int, sensor_id: str, ts: int) -> str:
    """Independent re-derivation of the core_ingress / nexus_integrity HMAC
    contract, cross-checked against sentinel_logic_mirror.compute_hmac (itself
    mirroring LineageStamper::stamp)."""
    import hashlib
    import hmac as hmac_mod

    mac = hmac_mod.new(SECRET, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", ts))
    return mac.hexdigest()

class TestComputeHmacContract:
    def test_matches_independent_reference(self):
        payload = b"synthetic-sentinel-parquet-batch"
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
        sensor banned. Confirm our mirror's BE/payload-first ordering produces
        a digest that diverges from that broken historical ordering."""
        payload = b"order-sensitive-batch-bytes"
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
        payload = b"same-bytes"
        ts = 1_700_000_000
        d1 = compute_hmac(SECRET, payload, 1, SENSOR_ID, ts)
        d2 = compute_hmac(SECRET, payload, 2, SENSOR_ID, ts)
        assert d1 != d2

    def test_tampered_payload_fails_recheck(self):
        payload = b"original-batch-bytes"
        seq, ts = 7, 1_700_000_500
        digest = compute_hmac(SECRET, payload, seq, SENSOR_ID, ts)
        assert compute_hmac(SECRET, b"tampered-batch-bytes", seq, SENSOR_ID, ts) != digest

class TestRequiredHeaderContract:
    def test_required_headers_match_ingress_expectations(self):
        # src: project_empros/services/core_ingress -- required header set,
        # plus Authorization (bearer token, checked upstream of integrity).
        contract_headers = {
            HDR_SENSOR_ID, "X-Sensor-Type", HDR_BATCH_SEQUENCE,
            HDR_BATCH_TIMESTAMP, HDR_BATCH_HMAC, "Content-Type", "Authorization",
        }
        assert contract_headers == set(REQUIRED_HEADERS)

    def test_partition_headers_are_gateway_injected_not_sensor_sent(self, repo_root):
        # X-Partition-Date / X-Partition-Hour are computed server-side in
        # core_ingress from the verified batch timestamp and forwarded over NATS
        # to worker_s3_archive -- the sensor must never construct these itself.
        import os
        src = open(os.path.join(repo_root, "src", "siem", "parquet_transmitter.rs")).read()
        assert "X-Partition-Date" not in src
        assert "X-Partition-Hour" not in src

    def test_content_type_is_parquet(self):
        assert CONTENT_TYPE == "application/vnd.apache.parquet"

# -----------------------------------------------------------------------------
# In-process mock ingress -- captures and validates a synthetic POST built the
# same way parquet_transmitter.rs's forwarder builds its real request.
# -----------------------------------------------------------------------------
class _CapturingHandler(BaseHTTPRequestHandler):
    captured = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            # email.message.Message is case-insensitive on lookup -- urllib
            # canonicalizes outgoing header names (e.g. "X-Batch-Hmac" ->
            # "X-batch-hmac"), so preserve the live object rather than a dict.
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

def _post_synthetic_batch(url, payload, sequence, ts, token="tier0-test-token"):
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
    }
    req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, digest

class TestEndToEndTransmission:
    def test_synthetic_batch_reaches_mock_ingress_with_valid_contract(self, mock_ingress):
        payload = b"\x50\x41\x52\x31synthetic-sentinel-parquet-bytes"
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

        # Server-side re-derivation must independently confirm the HMAC
        server_side = compute_hmac(SECRET, captured["body"], sequence, SENSOR_ID, ts)
        assert server_side == digest

    def test_tampered_in_flight_payload_breaks_hmac_recheck(self, mock_ingress):
        payload = b"original-sentinel-batch-bytes"
        sequence, ts = 2, 1_700_000_100
        _, digest = _post_synthetic_batch(mock_ingress, payload, sequence, ts)
        captured = _CapturingHandler.captured

        # Simulate on-the-wire tampering: re-derive the HMAC over different bytes
        # than what the gateway received -- it must not match the stamped digest.
        recheck = compute_hmac(SECRET, b"mutated-sentinel-batch-bytes!", sequence, SENSOR_ID, ts)
        assert recheck != digest
        assert captured["body"] == payload