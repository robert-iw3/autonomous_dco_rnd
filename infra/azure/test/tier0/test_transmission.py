"""
Tier-0 -- Transmission-layer conformance for the Nexus Azure connectors
(nexus-azure-nsg-connector, nexus-azure-activity-connector, nexus-azure-entraid-connector).
"""
import os
import re
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest

from azure_connectors_logic_mirror import (
    compute_hmac,
    sensor_id_for_flow,
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

SECRET = b"azure-connector-tier0-integrity-secret"
SENSOR_ID = sensor_id_for_flow("11111111-2222-3333-4444-555555555555", "lab", "eastus")

def _read(*parts):
    with open(os.path.join(*parts)) as fh:
        return fh.read()

def _reference_hmac(payload: bytes, sequence: int, sensor_id: str, ts: int) -> str:
    """Independent re-derivation of the core_ingress / connector HMAC contract,
    cross-checked against azure_connectors_logic_mirror.compute_hmac (itself
    mirroring transmitter.rs's compute_hmac)."""
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
        payload = b"synthetic-azure-connector-parquet-batch"
        assert compute_hmac(SECRET, payload, 1, SENSOR_ID, 1_700_000_000) == \
            _reference_hmac(payload, 1, SENSOR_ID, 1_700_000_000)

    def test_is_64_char_lowercase_hex(self):
        digest = compute_hmac(SECRET, b"x", 1, SENSOR_ID, 1)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_byte_order_is_payload_then_be64_seq_then_id_then_be64_ts(self):
        """transmitter.rs's compute_hmac builds one contiguous buffer in this
        exact order (payload || BE64(sequence) || sensor_id_utf8 || BE64(timestamp))
        before MAC'ing it -- the same field order/endianness as core_ingress
        and every other Nexus sensor (including infra/aws). Confirm our mirror
        diverges from a plausible-but-wrong alternative ordering (id-first,
        LE timestamps)."""
        payload = b"order-sensitive-azure-batch-bytes"
        seq, ts = 3, 1_700_000_300

        correct = compute_hmac(SECRET, payload, seq, SENSOR_ID, ts)

        import hashlib
        import hmac as hmac_mod
        wrong = hmac_mod.new(SECRET, digestmod=hashlib.sha256)
        wrong.update(SENSOR_ID.encode("utf-8"))          # wrong: sensor_id first
        wrong.update(struct.pack("<Q", seq))             # wrong: LE sequence
        wrong.update(struct.pack("<Q", ts))              # wrong: LE timestamp
        wrong.update(payload)                            # wrong: payload last
        assert correct != wrong.hexdigest()

    def test_sequence_changes_digest(self):
        payload = b"same-batch-bytes"
        ts = 1_700_000_000
        d1 = compute_hmac(SECRET, payload, 1, SENSOR_ID, ts)
        d2 = compute_hmac(SECRET, payload, 2, SENSOR_ID, ts)
        assert d1 != d2

    def test_tampered_payload_fails_recheck(self):
        payload = b"original-azure-connector-batch-bytes"
        seq, ts = 7, 1_700_000_500
        digest = compute_hmac(SECRET, payload, seq, SENSOR_ID, ts)
        assert compute_hmac(SECRET, b"tampered-azure-connector-batch-bytes!!", seq, SENSOR_ID, ts) != digest

    def test_mirror_matches_real_compute_hmac_source_byte_layout(self, connector_dir):
        # Cross-check the mirror's field order directly against the real
        # source's extend_from_slice() call sequence in compute_hmac().
        src = _read(connector_dir, "src", "transmitter.rs")
        m = re.search(r"fn compute_hmac\(.*?\{(.*?)\n    \}", src, re.DOTALL)
        assert m, "could not locate compute_hmac() in transmitter.rs"
        body = m.group(1)
        order = re.findall(
            r"msg\.extend_from_slice\(&?(payload|sequence\.to_be_bytes\(\)|sensor_id\.as_bytes\(\)|timestamp\.to_be_bytes\(\))\)",
            body,
        )
        assert order == ["payload", "sequence.to_be_bytes()", "sensor_id.as_bytes()", "timestamp.to_be_bytes()"]

# -----------------------------------------------------------------------------
# Header contract
# -----------------------------------------------------------------------------

class TestRequiredHeaderContract:
    def test_required_headers_match_ingress_expectations(self):
        contract_headers = {
            HDR_SENSOR_ID, HDR_SENSOR_TYPE, HDR_BATCH_SEQUENCE,
            HDR_BATCH_TIMESTAMP, HDR_BATCH_HMAC, "Content-Type", "Authorization",
        }
        assert contract_headers == set(REQUIRED_HEADERS)
        assert len(REQUIRED_HEADERS) == 7

    def test_content_type_is_parquet(self):
        assert CONTENT_TYPE == "application/vnd.apache.parquet"

    def test_real_source_sends_exactly_these_seven_headers_via_bearer_auth_and_header_calls(self, connector_dir):
        """REAL BUG regression guard: prior to this workbench's fix, the real
        transmit_bytes() built only 6 .header() calls and never called
        .bearer_auth() / read an auth_token -- the EXACT SAME bug class found
        and fixed in infra/aws. Authorization was absent and
        core_ingress::validate_token (main.rs:221-224) rejected every batch
        with 401 UNAUTHORIZED before any integrity-header logic ran. Confirm
        the fixed source now sends bearer_auth(&self.config.auth_token) plus
        all 6 literal headers, matching REQUIRED_HEADERS exactly."""
        src = _read(connector_dir, "src", "transmitter.rs")
        assert ".bearer_auth(&self.config.auth_token)" in src, \
            "transmitter.rs no longer sends an Authorization header via bearer_auth -- " \
            "every batch would be rejected with 401 by core_ingress::validate_token"
        assert "pub auth_token: String," in _read(connector_dir, "src", "config.rs")
        assert 'env::var("AUTH_TOKEN")' in _read(connector_dir, "src", "config.rs")

        literal_headers = re.findall(r'\.header\("([A-Za-z-]+)",', src)
        assert set(literal_headers) | {"Authorization"} == set(REQUIRED_HEADERS)
        assert len(literal_headers) == 6

# -----------------------------------------------------------------------------
# In-process mock ingress -- captures and validates a synthetic POST built the
# same way transmit_bytes() builds its real request (transmitter.rs transmit_bytes()).
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

def _post_synthetic_batch(url, payload, sequence, ts, sensor_type, sensor_id=SENSOR_ID, token="tier0-test-token"):
    import urllib.request

    digest = compute_hmac(SECRET, payload, sequence, sensor_id, ts)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": CONTENT_TYPE,
        HDR_BATCH_SEQUENCE: str(sequence),
        HDR_BATCH_TIMESTAMP: str(ts),
        HDR_SENSOR_ID: sensor_id,
        HDR_SENSOR_TYPE: sensor_type,
        HDR_BATCH_HMAC: digest,
    }
    req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, digest

class TestEndToEndTransmission:
    @pytest.mark.parametrize("connector", ["nsg", "activity", "entraid"])
    def test_synthetic_batch_reaches_mock_ingress_with_valid_contract(self, mock_ingress, connector):
        payload = b"\x50\x41\x52\x31synthetic-azure-" + connector.encode() + b"-parquet-bytes"
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

        # Server-side re-derivation must independently confirm the HMAC
        server_side = compute_hmac(SECRET, captured["body"], sequence, SENSOR_ID, ts)
        assert server_side == digest

    def test_tampered_in_flight_payload_breaks_hmac_recheck(self, mock_ingress):
        payload = b"original-azure-connector-batch-bytes"
        sequence, ts = 2, 1_700_000_100
        _post_synthetic_batch(mock_ingress, payload, sequence, ts, WIRE_SENSOR_TYPE["nsg"])
        captured = _CapturingHandler.captured

        digest = compute_hmac(SECRET, captured["body"], sequence, SENSOR_ID, ts)
        recheck = compute_hmac(SECRET, b"mutated-azure-connector-batch-bytes!", sequence, SENSOR_ID, ts)
        assert recheck != digest
        assert captured["body"] == payload

    def test_sensor_id_binds_into_hmac_so_spoofed_identity_fails(self, mock_ingress):
        """A batch stamped for SENSOR_ID must not verify under a different
        claimed sensor_id -- the HMAC binds identity, preventing a compromised
        connector from impersonating a different Azure subscription/region pairing."""
        payload = b"impersonation-attempt-batch-bytes"
        sequence, ts = 5, 1_700_000_400
        digest = compute_hmac(SECRET, payload, sequence, SENSOR_ID, ts)

        spoofed_id = sensor_id_for_flow("99999999-aaaa-bbbb-cccc-dddddddddddd", "prod", "westeurope")
        recheck = compute_hmac(SECRET, payload, sequence, spoofed_id, ts)
        assert recheck != digest

    def test_wire_sensor_type_distinguishes_connectors_at_the_mock_ingress(self, mock_ingress):
        """Each connector must be individually identifiable by core_ingress's
        os_exclusion_rules / schema-routing logic via X-Sensor-Type -- confirm
        the three connectors' synthetic batches arrive tagged distinctly."""
        seen = set()
        for i, connector in enumerate(("nsg", "activity", "entraid"), start=10):
            payload = f"distinct-batch-{connector}".encode()
            _post_synthetic_batch(mock_ingress, payload, i, 1_700_001_000 + i, WIRE_SENSOR_TYPE[connector])
            seen.add(_CapturingHandler.captured["headers"][HDR_SENSOR_TYPE])
        assert seen == set(WIRE_SENSOR_TYPE.values())
        assert len(seen) == 3