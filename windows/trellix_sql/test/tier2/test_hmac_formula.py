"""
Prove _compute_hmac matches the Rust integrity.rs formula exactly.

The Rust compute_hmac in project_empros/services/core_ingress/src/integrity.rs:
    mac.update(parquet_bytes)
    mac.update(&sequence.to_be_bytes())   // 8-byte big-endian u64
    mac.update(sensor_id.as_bytes())      // raw UTF-8 bytes
    mac.update(&timestamp.to_be_bytes())  // 8-byte big-endian u64

Tests:
  - Output matches an independent computation of the same formula
  - Output is 64 lowercase hex characters (SHA-256 digest)
  - Changing any single input changes the output (input isolation)
  - Sequence uses big-endian encoding (not little-endian)
  - Timestamp uses big-endian encoding (not little-endian)
  - sensor_id is encoded as raw UTF-8 bytes
  - Update order is: payload → sequence → sensor_id → timestamp
    (not timestamp-first or any other order)
"""

from __future__ import annotations
import hashlib
import hmac as hmac_stdlib
import struct
import unittest.mock as mock
import pytest
import reader

# ---------------------------------------------------------------------------
# Deterministic test inputs
# ---------------------------------------------------------------------------
_SECRET     = b"test-secret-key-for-hmac-signing"    # matches conftest ENV default
_SENSOR_ID  = "TEST-SENSOR-001"                      # matches conftest ENV default
_PAYLOAD    = b"parquet-payload-bytes-for-testing"
_SEQ        = 42
_TS         = 1_717_600_000

def _reference(
    secret: bytes,
    payload: bytes,
    sequence: int,
    sensor_id: str,
    timestamp: int,
) -> str:
    """Independent Python implementation of the Rust formula."""
    mac = hmac_stdlib.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestHMACFormula:
    """Each test patches NEXUS_INTEGRITY_SECRET / NEXUS_SENSOR_ID to known values
    so results are deterministic regardless of the container environment."""

    def setup_method(self):
        self._p_secret = mock.patch.object(reader, "NEXUS_INTEGRITY_SECRET", _SECRET)
        self._p_sensor = mock.patch.object(reader, "NEXUS_SENSOR_ID", _SENSOR_ID)
        self._p_secret.start()
        self._p_sensor.start()

    def teardown_method(self):
        self._p_secret.stop()
        self._p_sensor.stop()

    def test_matches_reference_implementation(self):
        expected = _reference(_SECRET, _PAYLOAD, _SEQ, _SENSOR_ID, _TS)
        assert reader._compute_hmac(_PAYLOAD, _SEQ, _TS) == expected

    def test_output_is_64_lowercase_hex_chars(self):
        result = reader._compute_hmac(_PAYLOAD, _SEQ, _TS)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_payload_changes_hmac(self):
        h1 = reader._compute_hmac(b"payload-a", _SEQ, _TS)
        h2 = reader._compute_hmac(b"payload-b", _SEQ, _TS)
        assert h1 != h2

    def test_different_sequence_changes_hmac(self):
        h1 = reader._compute_hmac(_PAYLOAD, 1, _TS)
        h2 = reader._compute_hmac(_PAYLOAD, 2, _TS)
        assert h1 != h2

    def test_different_timestamp_changes_hmac(self):
        h1 = reader._compute_hmac(_PAYLOAD, _SEQ, 1_000_000)
        h2 = reader._compute_hmac(_PAYLOAD, _SEQ, 2_000_000)
        assert h1 != h2

    def test_different_sensor_id_changes_hmac(self):
        with mock.patch.object(reader, "NEXUS_SENSOR_ID", "SENSOR-A"):
            h1 = reader._compute_hmac(_PAYLOAD, _SEQ, _TS)
        with mock.patch.object(reader, "NEXUS_SENSOR_ID", "SENSOR-B"):
            h2 = reader._compute_hmac(_PAYLOAD, _SEQ, _TS)
        assert h1 != h2

    def test_sequence_uses_big_endian_not_little_endian(self):
        """Sequence 1 big-endian = 0x0000000000000001.
        If little-endian were used the HMAC would differ — we assert it matches BE."""
        seq = 1
        be = hmac_stdlib.new(_SECRET, digestmod=hashlib.sha256)
        be.update(b"x")
        be.update(struct.pack(">Q", seq))   # big-endian
        be.update(_SENSOR_ID.encode())
        be.update(struct.pack(">Q", _TS))

        le = hmac_stdlib.new(_SECRET, digestmod=hashlib.sha256)
        le.update(b"x")
        le.update(struct.pack("<Q", seq))   # little-endian
        le.update(_SENSOR_ID.encode())
        le.update(struct.pack(">Q", _TS))

        result = reader._compute_hmac(b"x", seq, _TS)
        assert result == be.hexdigest()
        assert result != le.hexdigest()

    def test_timestamp_uses_big_endian_not_little_endian(self):
        ts = 0x0102030405060708
        be = hmac_stdlib.new(_SECRET, digestmod=hashlib.sha256)
        be.update(_PAYLOAD)
        be.update(struct.pack(">Q", _SEQ))
        be.update(_SENSOR_ID.encode())
        be.update(struct.pack(">Q", ts))

        le = hmac_stdlib.new(_SECRET, digestmod=hashlib.sha256)
        le.update(_PAYLOAD)
        le.update(struct.pack(">Q", _SEQ))
        le.update(_SENSOR_ID.encode())
        le.update(struct.pack("<Q", ts))

        result = reader._compute_hmac(_PAYLOAD, _SEQ, ts)
        assert result == be.hexdigest()
        assert result != le.hexdigest()

    def test_update_order_payload_seq_sensor_ts(self):
        """Wrong update order produces a different digest — assert the correct order."""
        # Correct: payload, seq, sensor_id, ts
        correct = _reference(_SECRET, _PAYLOAD, _SEQ, _SENSOR_ID, _TS)

        # Wrong: sensor_id first
        wrong = hmac_stdlib.new(_SECRET, digestmod=hashlib.sha256)
        wrong.update(_SENSOR_ID.encode())
        wrong.update(_PAYLOAD)
        wrong.update(struct.pack(">Q", _SEQ))
        wrong.update(struct.pack(">Q", _TS))

        result = reader._compute_hmac(_PAYLOAD, _SEQ, _TS)
        assert result == correct
        assert result != wrong.hexdigest()

    def test_sensor_id_encoded_as_utf8(self):
        """Non-ASCII sensor_id must be encoded as UTF-8 (not latin-1 or utf-16)."""
        sensor = "SENSOR-ñoño-001"
        with mock.patch.object(reader, "NEXUS_SENSOR_ID", sensor):
            result = reader._compute_hmac(_PAYLOAD, _SEQ, _TS)
        expected = _reference(_SECRET, _PAYLOAD, _SEQ, sensor, _TS)
        assert result == expected

    def test_zero_sequence_produces_eight_zero_bytes(self):
        """Sequence=0 should contribute 8 zero bytes to the HMAC."""
        r_zero = _reference(_SECRET, _PAYLOAD, 0, _SENSOR_ID, _TS)
        assert reader._compute_hmac(_PAYLOAD, 0, _TS) == r_zero

    def test_max_uint64_sequence_handled(self):
        max_seq = (1 << 64) - 1
        r_max = _reference(_SECRET, _PAYLOAD, max_seq, _SENSOR_ID, _TS)
        assert reader._compute_hmac(_PAYLOAD, max_seq, _TS) == r_max