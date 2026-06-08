"""
Tier-0 -- Transmission-layer conformance for the falco_runtime (k8s) sensor.

The transmitter is a Rust binary with no embedded Python interpreter, so we
can't drive its real `transmit_parquet()` coroutine from pytest directly.
Instead this module independently re-derives the two pieces of the wire
contract that must match byte-for-byte -- the HMAC formula and the
required-header set -- and fires them at a real in-process mock ingress
server, exactly the way the transmitter's `transmit_parquet()` does, to
validate the *contract* end to end with synthetic batch bytes.
"""
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from falco_logic_mirror import (
    compute_hmac,
    REQUIRED_HEADERS,
    CONTENT_TYPE,
    SENSOR_TYPE,
)

pytestmark = pytest.mark.tier0

SECRET = b"falco-tier0-integrity-secret"
SENSOR_ID = "falco-runtime-tier0"

def _reference_hmac(payload: bytes, sequence: int, sensor_id: str, ts: int) -> str:
    """Independent re-derivation of the core_ingress HMAC contract, cross-checked
    against falco_logic_mirror.compute_hmac (itself mirroring Stamper::stamp)."""
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
        payload = b"synthetic-falco-parquet-batch"
        assert compute_hmac(SECRET, payload, 1, SENSOR_ID, 1_700_000_000) == \
            _reference_hmac(payload, 1, SENSOR_ID, 1_700_000_000)

    def test_is_64_char_lowercase_hex(self):
        digest = compute_hmac(SECRET, b"x", 1, SENSOR_ID, 1)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

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
    def test_required_headers_match_transmitter_source(self, repo_root):
        import os
        with open(os.path.join(repo_root, "transmitter", "src", "main.rs")) as fh:
            src = fh.read()
        # Every header in REQUIRED_HEADERS must appear as a literal .header(...)
        # call in transmit_parquet() -- cross-checks the mirror against source
        # rather than asserting a self-defined constant against itself.
        for header in REQUIRED_HEADERS:
            assert f'.header("{header}"' in src, f"transmit_parquet() doesn't send {header!r}"

    def test_partition_headers_are_sensor_sent_not_gateway_injected(self, repo_root):
        """Unlike linux_sentinel (where X-Partition-Date/Hour are injected by
        the gateway from the verified batch timestamp), falco_transmitter
        computes and sends them itself from wall-clock UTC at POST time
        (main.rs: `.header("X-Partition-Date", Utc::now()...)`). core_ingress
        forwards them downstream verbatim if present rather than requiring or
        overwriting them (main.rs:334-339, "Forward Hive partition hints if
        present"). Confirm they're sender-computed here, not part of the
        sensor's required/verified contract -- so REQUIRED_HEADERS correctly
        excludes them."""
        import os
        with open(os.path.join(repo_root, "transmitter", "src", "main.rs")) as fh:
            src = fh.read()
        assert '.header("X-Partition-Date", Utc::now()' in src
        assert '.header("X-Partition-Hour", Utc::now()' in src
        assert "X-Partition-Date" not in REQUIRED_HEADERS
        assert "X-Partition-Hour" not in REQUIRED_HEADERS

    def test_content_type_is_parquet(self):
        assert CONTENT_TYPE == "application/vnd.apache.parquet"

# -----------------------------------------------------------------------------
# In-process mock ingress -- captures and validates a synthetic POST built the
# same way main.rs's transmit_parquet() builds its real request.
# -----------------------------------------------------------------------------
class _CapturingHandler(BaseHTTPRequestHandler):
    captured = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).captured = {
            "path": self.path,
            # email.message.Message is case-insensitive on lookup -- urllib
            # canonicalizes outgoing header names (e.g. "X-Batch-HMAC" ->
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
    from datetime import datetime, timezone

    digest = compute_hmac(SECRET, payload, sequence, SENSOR_ID, ts)
    now = datetime.now(timezone.utc)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": CONTENT_TYPE,
        "X-Sensor-Type": SENSOR_TYPE,
        "X-Sensor-Id": SENSOR_ID,
        "X-Batch-Sequence": str(sequence),
        "X-Batch-Timestamp": str(ts),
        "X-Batch-HMAC": digest,
        "X-Partition-Date": now.strftime("%Y-%m-%d"),
        "X-Partition-Hour": now.strftime("%H"),
    }
    req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, digest

class TestEndToEndTransmission:
    def test_synthetic_batch_reaches_mock_ingress_with_valid_contract(self, mock_ingress):
        payload = b"\x50\x41\x52\x31synthetic-falco-runtime-parquet-bytes"
        sequence, ts = 1, 1_700_000_000
        status, digest = _post_synthetic_batch(mock_ingress, payload, sequence, ts)
        assert status == 200

        captured = _CapturingHandler.captured
        assert captured["path"] == "/api/v1/telemetry"
        assert captured["body"] == payload

        h = captured["headers"]
        assert h["Content-Type"] == CONTENT_TYPE
        assert h["X-Sensor-Type"] == SENSOR_TYPE
        assert h["X-Sensor-Id"] == SENSOR_ID
        assert h["X-Batch-Sequence"] == str(sequence)
        assert h["X-Batch-Timestamp"] == str(ts)
        assert h["X-Batch-HMAC"] == digest
        assert h["Authorization"].startswith("Bearer ")
        # Sensor-computed partition hints -- present, but not required/verified.
        assert h["X-Partition-Date"]
        assert h["X-Partition-Hour"]

        # Server-side re-derivation must independently confirm the HMAC
        server_side = compute_hmac(SECRET, captured["body"], sequence, SENSOR_ID, ts)
        assert server_side == digest

    def test_tampered_in_flight_payload_breaks_hmac_recheck(self, mock_ingress):
        payload = b"original-falco-batch-bytes"
        sequence, ts = 2, 1_700_000_100
        _, digest = _post_synthetic_batch(mock_ingress, payload, sequence, ts)
        captured = _CapturingHandler.captured

        # Simulate on-the-wire tampering: re-derive the HMAC over different bytes
        # than what the gateway received -- it must not match the stamped digest.
        recheck = compute_hmac(SECRET, b"mutated-falco-batch-bytes!", sequence, SENSOR_ID, ts)
        assert recheck != digest
        assert captured["body"] == payload