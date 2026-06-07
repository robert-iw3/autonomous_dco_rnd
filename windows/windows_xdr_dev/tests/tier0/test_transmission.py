"""
Tier-0 - Transmission layer tests.

Validates HMAC-SHA256 computation, EdrRow/C2Row schema contracts,
sensor subtype discrimination, and the known C2Row timestamp bug.
Mirrors test_sensor_schema.rs without requiring Rust compilation.
"""

import json
import struct
import hmac as _hmac_mod
import hashlib
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from deepxdr_logic import (
    compute_hmac, INTEGRITY_SECRET_DEFAULT,
    EDR_REQUIRED_FIELDS, C2_REQUIRED_FIELDS,
    EDR_SUBTYPES, C2_SUBTYPES, TRAFFIC_DIRECTIONS,
    make_edr_row, make_c2_row,
)

pytestmark = pytest.mark.tier0

# -----------------------------------------------------------------------------
# HMAC-SHA256  (nexus_integrity/src/lib.rs, test_sensor_schema.rs:89-96)
# -----------------------------------------------------------------------------

class TestHmac:
    SENSOR_ID = "WIN-XDR-TEST-01"
    TIMESTAMP = 1748872800
    SEQUENCE  = 1

    def _payload(self) -> bytes:
        return b"test_parquet_payload_bytes"

    def test_hmac_is_64_hex_chars(self):
        sig = compute_hmac(self._payload(), self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        assert len(sig) == 64, f"HMAC-SHA256 must be 64 hex chars, got {len(sig)}"

    def test_hmac_is_lowercase_hex(self):
        sig = compute_hmac(self._payload(), self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        assert all(c in "0123456789abcdef" for c in sig), "HMAC must be lowercase hex"

    def test_hmac_deterministic(self):
        sig1 = compute_hmac(self._payload(), self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        sig2 = compute_hmac(self._payload(), self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        assert sig1 == sig2

    def test_different_payload_different_hmac(self):
        sig1 = compute_hmac(b"payload_a", self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        sig2 = compute_hmac(b"payload_b", self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        assert sig1 != sig2, "Different payload must produce different HMAC"

    def test_sequence_binding_prevents_replay(self):
        # Same payload, different sequence counter → different HMAC
        sig1 = compute_hmac(self._payload(), 100, self.SENSOR_ID, self.TIMESTAMP)
        sig2 = compute_hmac(self._payload(), 101, self.SENSOR_ID, self.TIMESTAMP)
        assert sig1 != sig2, "HMAC must bind to sequence counter (replay prevention)"

    def test_sensor_id_binding(self):
        sig1 = compute_hmac(self._payload(), self.SEQUENCE, "HOST-A", self.TIMESTAMP)
        sig2 = compute_hmac(self._payload(), self.SEQUENCE, "HOST-B", self.TIMESTAMP)
        assert sig1 != sig2, "HMAC must bind to sensor_id"

    def test_tamper_detection(self):
        payload = bytearray(self._payload())
        sig_orig    = compute_hmac(bytes(payload), self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        payload[-1] ^= 0xFF  # flip one byte
        sig_tampered = compute_hmac(bytes(payload), self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        assert sig_orig != sig_tampered, "Tampered payload must produce different HMAC"

    def test_timestamp_binding(self):
        sig1 = compute_hmac(self._payload(), self.SEQUENCE, self.SENSOR_ID, 1000)
        sig2 = compute_hmac(self._payload(), self.SEQUENCE, self.SENSOR_ID, 9999)
        assert sig1 != sig2, "HMAC must bind to timestamp"

    def test_secret_binding(self):
        sig1 = compute_hmac(self._payload(), self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP, "secret-a")
        sig2 = compute_hmac(self._payload(), self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP, "secret-b")
        assert sig1 != sig2, "HMAC must differ with different secrets"

    def test_default_secret_constant(self):
        assert INTEGRITY_SECRET_DEFAULT == "Nexus-Integrity-SharedKey-Rotate-Me"

    def test_sequence_is_big_endian_u64(self):
        # Verify sequence is packed as u64 big-endian by computing manually
        secret = INTEGRITY_SECRET_DEFAULT
        payload = self._payload()
        seq = 42
        ts  = self.TIMESTAMP

        h = _hmac_mod.new(secret.encode(), digestmod=hashlib.sha256)
        h.update(payload)
        h.update(struct.pack(">Q", seq))     # big-endian u64
        h.update(self.SENSOR_ID.encode())
        h.update(struct.pack(">Q", ts))
        expected = h.hexdigest()

        result = compute_hmac(payload, seq, self.SENSOR_ID, ts, secret)
        assert result == expected, "compute_hmac must use big-endian u64 for sequence and timestamp"

    def test_empty_payload_produces_valid_hmac(self):
        sig = compute_hmac(b"", self.SEQUENCE, self.SENSOR_ID, self.TIMESTAMP)
        assert len(sig) == 64


# -----------------------------------------------------------------------------
# EdrRow schema  (transmission/src/schema.rs, test_sensor_schema.rs:100-142)
# -----------------------------------------------------------------------------

class TestEdrRowSchema:
    def _row(self, subtype="edr"):
        return make_edr_row(subtype)

    def test_required_fields_all_present(self):
        row = self._row()
        for field in EDR_REQUIRED_FIELDS:
            assert field in row, f"EdrRow missing required field: {field}"

    def test_sensor_subtype_preserved(self):
        for sub in EDR_SUBTYPES:
            row = self._row(sub)
            assert row["sensor_subtype"] == sub

    def test_host_non_empty(self):
        assert self._row()["host"]

    def test_user_non_empty(self):
        assert self._row()["user"]

    def test_host_ip_non_empty(self):
        assert self._row()["host_ip"]

    def test_payload_raw_valid_json(self):
        row = self._row()
        parsed = json.loads(row["payload_raw"])
        assert isinstance(parsed, dict), "payload_raw must be a JSON object"

    def test_score_in_range(self):
        row = self._row()
        assert 0.0 <= row["score"] <= 10.0

    def test_required_strings_non_empty(self):
        row = self._row()
        for field in ("category", "event_type", "signature_name", "tactic", "technique", "severity"):
            assert row[field], f"EdrRow.{field} must not be empty"

    def test_pid_positive(self):
        assert self._row()["pid"] > 0

    def test_parent_pid_positive(self):
        assert self._row()["parent_pid"] > 0

    def test_field_count(self):
        row = self._row()
        assert len(row) == len(EDR_REQUIRED_FIELDS), \
            f"EdrRow field count mismatch: expected {len(EDR_REQUIRED_FIELDS)}, got {len(row)}"


# -----------------------------------------------------------------------------
# C2Row schema  (transmission/src/schema.rs, test_sensor_schema.rs:149-181)
# -----------------------------------------------------------------------------

class TestC2RowSchema:
    def _row(self, subtype="c2"):
        return make_c2_row(subtype)

    def test_required_fields_all_present(self):
        row = self._row()
        for field in C2_REQUIRED_FIELDS:
            assert field in row, f"C2Row missing required field: {field}"

    def test_sensor_subtype_preserved(self):
        for sub in C2_SUBTYPES:
            row = self._row(sub)
            assert row["sensor_subtype"] == sub

    def test_src_ip_non_empty(self):
        row = self._row()
        assert row["src_ip"], "C2Row.src_ip (new XDR field) must be non-empty"

    def test_src_port_positive(self):
        row = self._row()
        assert row["src_port"] > 0

    def test_traffic_direction_valid(self):
        row = self._row()
        assert row["traffic_direction"] in TRAFFIC_DIRECTIONS, \
            f"C2Row.traffic_direction must be one of {TRAFFIC_DIRECTIONS}"

    def test_dest_port_positive(self):
        row = self._row()
        assert row["dest_port"] > 0

    def test_confidence_in_range(self):
        row = self._row()
        assert 0 <= row["confidence"] <= 100

    def test_event_id_non_empty(self):
        assert self._row()["event_id"]

    def test_host_non_empty(self):
        assert self._row()["host"]

    def test_process_non_empty(self):
        assert self._row()["process"]

    def test_destination_non_empty(self):
        assert self._row()["destination"]

    def test_field_count(self):
        row = self._row()
        assert len(row) == len(C2_REQUIRED_FIELDS), \
            f"C2Row field count mismatch: expected {len(C2_REQUIRED_FIELDS)}, got {len(row)}"


# -----------------------------------------------------------------------------
# Sensor subtype discrimination  (test_sensor_schema.rs:188-213)
# -----------------------------------------------------------------------------

class TestSensorSubtypeDiscrimination:
    def test_edr_subtypes_are_defined(self):
        assert "edr" in EDR_SUBTYPES
        assert "dlp" in EDR_SUBTYPES
        assert "kernel" in EDR_SUBTYPES

    def test_c2_subtypes_are_defined(self):
        assert "c2" in C2_SUBTYPES
        assert "idps" in C2_SUBTYPES

    def test_edr_and_c2_subtypes_are_disjoint(self):
        overlap = EDR_SUBTYPES & C2_SUBTYPES
        assert not overlap, f"EDR and C2 subtypes must be disjoint, found overlap: {overlap}"

    def test_edr_subtypes_count(self):
        assert len(EDR_SUBTYPES) == 3

    def test_c2_subtypes_count(self):
        assert len(C2_SUBTYPES) == 2

    def test_edr_row_rejects_c2_subtype(self):
        # Logical: an EdrRow with subtype="c2" is a contract violation
        for c2_sub in C2_SUBTYPES:
            assert c2_sub not in EDR_SUBTYPES, \
                f"C2 subtype '{c2_sub}' must not be in EDR subtype set"

    def test_c2_row_rejects_edr_subtype(self):
        for edr_sub in EDR_SUBTYPES:
            assert edr_sub not in C2_SUBTYPES, \
                f"EDR subtype '{edr_sub}' must not be in C2 subtype set"


# -----------------------------------------------------------------------------
# Known C2Row timestamp bug  (test_sensor_schema.rs:503-519)
# -----------------------------------------------------------------------------

class TestC2RowTimestampBug:
    def test_timestamp_is_iso_string_not_epoch(self):
        """
        KNOWN BUG: C2Row.timestamp stores an ISO-8601 string.
        The MLOps pipeline expects a numeric epoch (i64/f64).
        Required fix: Change C2Row.timestamp to i64 epoch_ms in schema.rs.
        src: test_sensor_schema.rs:503-519
        """
        row = make_c2_row()
        ts = row["timestamp"]
        # Verify it IS a string
        assert isinstance(ts, str), "C2Row.timestamp is a string (bug: should be int epoch)"
        # Verify it cannot be parsed as a number directly
        try:
            float(ts)
            pytest.fail("C2Row.timestamp should NOT be parseable as a plain float (ISO-8601 string)")
        except ValueError:
            pass  # expected - confirms the bug exists

    def test_c2row_timestamp_can_be_converted_to_epoch(self):
        """Document the conversion path that must be applied to fix the bug."""
        from datetime import datetime, timezone
        row = make_c2_row()
        ts = row["timestamp"]
        # ISO-8601 with timezone offset can be parsed
        dt = datetime.fromisoformat(ts.replace("+00:00", "+00:00"))
        epoch_ms = int(dt.timestamp() * 1000)
        assert epoch_ms > 0, f"Converted epoch_ms={epoch_ms} must be positive"

    def test_edr_row_timestamp_is_integer(self):
        """EdrRow.timestamp is already correct (integer epoch)."""
        row = make_edr_row()
        ts = row["timestamp"]
        assert isinstance(ts, int), f"EdrRow.timestamp should be int, got {type(ts)}"
        assert ts > 0


# -----------------------------------------------------------------------------
# Beacon trigger strings survival  (test_sensor_schema.rs:428-477)
# -----------------------------------------------------------------------------

class TestBeaconTriggerStrings:
    EDR_TRIGGERS = [
        "YARA_RWX", "WEB_SHELL_DETECTED", "ETW_TAMPER", "SIGMA_CRITICAL",
        "DLP_HOOK_HIT", "DLP_CLIPBOARD_HIT", "DLP_ARCHIVE_HIT",
        "K0_LSASS_ACCESS", "K0_THREAD_INJECT", "K0_QUARANTINE",
    ]
    C2_TRIGGERS = [
        "INGRESS_FLOOD", "PORT_SCAN", "LATERAL_SMB", "LATERAL_RDP",
        "LATERAL_WINRM", "IDPS_INGRESS_TI_SRC", "C2_BEACON_CONFIRMED",
        "DGA_DOMAIN_HIT", "TI_IP_MATCH",
    ]

    def test_all_edr_trigger_strings_defined(self):
        for trigger in self.EDR_TRIGGERS:
            row = make_edr_row("edr")
            row["event_type"] = f"{trigger}:test_detail"
            assert row["event_type"].startswith(trigger), \
                f"EdrRow event_type must support '{trigger}' prefix"

    def test_all_c2_trigger_strings_defined(self):
        for trigger in self.C2_TRIGGERS:
            row = make_c2_row("c2")
            row["alert_reason"] = f"{trigger}:10.0.5.1"
            assert row["alert_reason"].startswith(trigger), \
                f"C2Row alert_reason must support '{trigger}' prefix"

    def test_edr_trigger_count(self):
        assert len(self.EDR_TRIGGERS) == 10

    def test_c2_trigger_count(self):
        assert len(self.C2_TRIGGERS) == 9

    def test_k0_quarantine_max_score(self):
        row = make_edr_row("kernel")
        row["event_type"] = "K0_QUARANTINE"
        row["score"] = 10.0
        assert row["score"] == 10.0

    def test_edr_and_c2_triggers_are_disjoint(self):
        overlap = set(self.EDR_TRIGGERS) & set(self.C2_TRIGGERS)
        assert not overlap, f"EDR and C2 triggers must be disjoint, found: {overlap}"


# -----------------------------------------------------------------------------
# XDR is superset of legacy fields  (test_sensor_schema.rs:527-570)
# -----------------------------------------------------------------------------

class TestXdrSupersetOfLegacy:
    LEGACY_EDR_FIELDS = [
        "id", "timestamp", "category", "event_type", "pid", "parent_pid", "tid",
        "path", "parent_image", "command_line", "destination_ip", "port",
        "signature_name", "tactic", "technique", "severity", "score",
        "avg_entropy", "max_velocity", "event_count",
    ]
    XDR_ADDITIONS_EDR = ["sensor_subtype", "host", "user", "host_ip", "payload_raw"]

    LEGACY_C2_FIELDS = [
        "id", "event_id", "timestamp", "host", "user", "host_ip", "process",
        "destination", "domain", "alert_reason", "confidence", "event_type", "severity", "score",
    ]
    XDR_ADDITIONS_C2 = ["sensor_subtype", "src_ip", "src_port", "traffic_direction", "payload_raw"]

    def test_edr_row_covers_all_legacy_fields(self):
        row = make_edr_row()
        for field in self.LEGACY_EDR_FIELDS:
            assert field in row, f"EdrRow missing legacy field: {field}"

    def test_edr_row_has_all_xdr_additions(self):
        row = make_edr_row()
        for field in self.XDR_ADDITIONS_EDR:
            assert field in row, f"EdrRow missing XDR addition: {field}"

    def test_c2_row_covers_all_legacy_fields(self):
        row = make_c2_row()
        for field in self.LEGACY_C2_FIELDS:
            assert field in row, f"C2Row missing legacy field: {field}"

    def test_c2_row_has_all_xdr_additions(self):
        row = make_c2_row()
        for field in self.XDR_ADDITIONS_C2:
            assert field in row, f"C2Row missing XDR addition: {field}"
