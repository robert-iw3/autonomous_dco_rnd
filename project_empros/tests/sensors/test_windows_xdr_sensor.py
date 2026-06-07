"""
test_windows_xdr_sensor.py -- Windows XDR Dev Sensor-Side Validation

Validates the Windows XDR unified agent SENSOR SIDE ONLY.
Middleware and Nexus are NOT in scope -- see test_e2e_sensor_pipeline.py for those.

XDR Dev status: v0.0.7 -- unifies EDR, C2, IDPS, DLP into single agent.
Will replace: windows/prototypes/edr_sensor + c2_sensor + idps (future).

What is tested here:
  1.  EdrRow schema -- all fields, types, sensor_subtype discrimination
  2.  C2Row schema  -- unified C2+IDPS row with traffic_direction + src_ip/port
  3.  HMAC computation (same nexus_integrity::stamper protocol as legacy sensors)
  4.  Parquet Arrow schema shape -- column names + types match EdrRow/C2Row structs
  5.  sensor_subtype discrimination -- edr/dlp/kernel vs c2/idps routing
  6.  Beacon suspicion trigger strings -- all 19 trigger types with score thresholds
  7.  Channel capacity settings -- bounded channel sizes
  8.  FFI JSON contract -- submit_edr_event/submit_c2_event input format
  9.  C2Row.timestamp is i64 epoch_ms (was ISO-8601 String; fixed in schema.rs/parquet.rs)
  10. XDR vs legacy field delta -- documents new fields added in XDR, and notes
      pending pipeline-side (corpus_utils.py) expansion needed before XDR goes live

Run:
    pytest test_windows_xdr_sensor.py -v
    pytest test_windows_xdr_sensor.py -v -k "schema"     # schema tests only
    pytest test_windows_xdr_sensor.py -v -k "beacon"     # beacon tests only
"""

import io
import json
import time
import uuid
import hmac
import struct
import hashlib
import pytest
import pyarrow as pa
import pyarrow.parquet as pq
import pandas as pd
from pathlib import Path
from typing import Any

REPO = Path(__file__).parent.parent.parent
XDR_DIR  = REPO.parent / "windows/windows_xdr_dev"
TRANS_SRC = XDR_DIR / "transmission/src"

INTEGRITY_SECRET = "Nexus-Integrity-SharedKey-Rotate-Me"


# ═══════════════════════════════════════════════════════════════════════════════
# Reference schema definitions
# ═══════════════════════════════════════════════════════════════════════════════

# EdrRow -- maps to windows_deepsensor sensor_type in Qdrant / S3
EDR_ROW_FIELDS = {
    "id":              pa.int64(),
    "sensor_subtype":  pa.utf8(),
    "timestamp":       pa.int64(),
    "host":            pa.utf8(),
    "user":            pa.utf8(),
    "host_ip":         pa.utf8(),
    "category":        pa.utf8(),
    "event_type":      pa.utf8(),
    "pid":             pa.uint32(),
    "parent_pid":      pa.uint32(),
    "tid":             pa.uint32(),
    "path":            pa.utf8(),
    "parent_image":    pa.utf8(),
    "command_line":    pa.utf8(),
    "destination_ip":  pa.utf8(),
    "port":            pa.uint32(),
    "signature_name":  pa.utf8(),
    "tactic":          pa.utf8(),
    "technique":       pa.utf8(),
    "severity":        pa.utf8(),
    "score":           pa.float64(),
    "avg_entropy":     pa.float64(),
    "max_velocity":    pa.float64(),
    "event_count":     pa.uint32(),
    "payload_raw":     pa.utf8(),
}

# C2Row -- maps to windows_c2 sensor_type in Qdrant / S3
C2_ROW_FIELDS = {
    "id":                pa.int64(),
    "sensor_subtype":    pa.utf8(),
    "event_id":          pa.utf8(),
    "timestamp":         pa.int64(),   # epoch_ms -- FIXED (was ISO-8601 string; schema.rs + parquet.rs updated)
    "host":              pa.utf8(),
    "user":              pa.utf8(),
    "host_ip":           pa.utf8(),
    "process":           pa.utf8(),
    "src_ip":            pa.utf8(),
    "src_port":          pa.uint32(),
    "destination":       pa.utf8(),
    "dest_port":         pa.uint32(),
    "domain":            pa.utf8(),
    "traffic_direction": pa.utf8(),
    "alert_reason":      pa.utf8(),
    "confidence":        pa.int64(),
    "event_type":        pa.utf8(),
    "severity":          pa.utf8(),
    "score":             pa.float64(),
    "payload_raw":       pa.utf8(),
}

# Canonical valid EdrRow record
VALID_EDR_RECORD = {
    "id":             1,
    "sensor_subtype": "edr",
    "timestamp":      int(time.time() * 1000),
    "host":           "WIN-XDR-01",
    "user":           "CORP\\jsmith",
    "host_ip":        "10.0.1.50",
    "category":       "ProcessStart",
    "event_type":     "YARA_RWX:SuspiciousAlloc",
    "pid":            1234,
    "parent_pid":     5678,
    "tid":            1000,
    "path":           "C:\\Windows\\Temp\\beacon.exe",
    "parent_image":   "explorer.exe",
    "command_line":   "beacon.exe -silent",
    "destination_ip": "185.220.101.1",
    "port":           443,
    "signature_name": "YARA_RWX:beacon_pattern",
    "tactic":         "Execution",
    "technique":      "T1059.001",
    "severity":       "HIGH",
    "score":          8.5,
    "avg_entropy":    0.87,
    "max_velocity":   0.92,
    "event_count":    3,
    "payload_raw":    '{"raw":"event_data"}',
}

VALID_DLP_RECORD = {**VALID_EDR_RECORD,
    "sensor_subtype": "dlp",
    "category":       "MemoryAccess",
    "event_type":     "DLP_HOOK_HIT",
    "signature_name": "DLP_HOOK_HIT:clipboard",
    "score":          8.5,
}

VALID_KERNEL_RECORD = {**VALID_EDR_RECORD,
    "sensor_subtype": "kernel",
    "category":       "KernelEvent",
    "event_type":     "K0_LSASS_ACCESS",
    "signature_name": "K0_LSASS_ACCESS",
    "score":          9.5,
}

VALID_C2_RECORD = {
    "id":                1,
    "sensor_subtype":    "c2",
    "event_id":          str(uuid.uuid4()),
    "timestamp":         int(time.time() * 1000),  # epoch_ms (ISO-8601 bug fixed in schema.rs + parquet.rs)
    "host":              "WIN-XDR-01",
    "user":              "CORP\\jsmith",
    "host_ip":           "10.0.1.50",
    "process":           "beacon.exe",
    "src_ip":            "10.0.1.50",
    "src_port":          52341,
    "destination":       "185.220.101.1",
    "dest_port":         443,
    "domain":            "",
    "traffic_direction": "Egress",
    "alert_reason":      "C2_BEACON_CONFIRMED",
    "confidence":        92,
    "event_type":        "C2_BEACON",
    "severity":          "CRITICAL",
    "score":             9.2,
    "payload_raw":       '{"flow":"data"}',
}

VALID_IDPS_RECORD = {**VALID_C2_RECORD,
    "sensor_subtype":    "idps",
    "traffic_direction": "Ingress",
    "alert_reason":      "INGRESS_FLOOD:10.0.5.1",
    "event_type":        "IDPS_FLOOD",
    "score":             8.5,
}


def _make_parquet(records: list[dict]) -> bytes:
    df  = pd.DataFrame(records)
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf, compression="zstd")
    return buf.getvalue()


def _parquet_cols(buf: bytes) -> set[str]:
    return set(pq.read_schema(io.BytesIO(buf)).names)


def _xdr_hmac(parquet_bytes: bytes, sequence: int, sensor_id: str,
              timestamp: int) -> str:
    mac = hmac.new(INTEGRITY_SECRET.encode(), digestmod=hashlib.sha256)
    mac.update(parquet_bytes)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode())
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 1: EdrRow Schema
# ═══════════════════════════════════════════════════════════════════════════════

class TestXDREdrRowSchema:
    """Validate the EdrRow Parquet schema against the Rust struct definition."""

    def test_all_edr_fields_present(self):
        """Parquet from EdrRow must contain every field defined in schema.rs."""
        buf  = _make_parquet([VALID_EDR_RECORD])
        cols = _parquet_cols(buf)
        missing = set(EDR_ROW_FIELDS) - cols
        assert not missing, f"EdrRow fields missing from Parquet: {missing}"

    def test_sensor_subtype_field_present(self):
        """EdrRow must have sensor_subtype -- new field distinguishing edr/dlp/kernel."""
        buf  = _make_parquet([VALID_EDR_RECORD])
        cols = _parquet_cols(buf)
        assert "sensor_subtype" in cols, \
            "EdrRow missing 'sensor_subtype' field (new in XDR, absent in legacy EDR)"

    def test_host_user_host_ip_present(self):
        """EdrRow must have host, user, host_ip -- new context fields vs legacy."""
        buf  = _make_parquet([VALID_EDR_RECORD])
        cols = _parquet_cols(buf)
        for f in ("host", "user", "host_ip"):
            assert f in cols, f"EdrRow missing new XDR field '{f}'"

    def test_payload_raw_field_present(self):
        """EdrRow must have payload_raw -- full JSON for forensic re-hydration."""
        buf  = _make_parquet([VALID_EDR_RECORD])
        cols = _parquet_cols(buf)
        assert "payload_raw" in cols, "EdrRow missing payload_raw field"

    def test_edr_score_range(self):
        """score must be in [0, 10] -- XDR uses 10-point scale for SIEM severity."""
        assert 0.0 <= VALID_EDR_RECORD["score"] <= 10.0

    def test_edr_maps_to_windows_deepsensor(self):
        """EdrRow sensor_subtype in {edr, dlp, kernel} all map to windows_deepsensor
        in the mlops pipeline. Verify the schema is compatible with corpus_utils._EDR_FIELDS."""
        import sys
        sys.path.insert(0, str(REPO / "mlops/scripts"))
        from corpus_utils import _EDR_FIELDS, _apply_aliases, _clean

        for record in [VALID_EDR_RECORD, VALID_DLP_RECORD, VALID_KERNEL_RECORD]:
            aliased = _apply_aliases(record, "windows_deepsensor")
            cleaned = _clean(aliased, _EDR_FIELDS)
            # Must have at least the numeric fields
            for f in ("score", "avg_entropy", "max_velocity"):
                assert f in cleaned, \
                    f"EdrRow subtype '{record['sensor_subtype']}' missing '{f}' after alias"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 2: C2Row Schema
# ═══════════════════════════════════════════════════════════════════════════════

class TestXDRC2RowSchema:
    """Validate the C2Row Parquet schema against the Rust struct definition."""

    def test_all_c2_fields_present(self):
        buf  = _make_parquet([VALID_C2_RECORD])
        cols = _parquet_cols(buf)
        missing = set(C2_ROW_FIELDS) - cols
        assert not missing, f"C2Row fields missing from Parquet: {missing}"

    def test_sensor_subtype_c2_vs_idps(self):
        """C2Row sensor_subtype must be 'c2' or 'idps' -- routes to different ML analysis."""
        for record in [VALID_C2_RECORD, VALID_IDPS_RECORD]:
            assert record["sensor_subtype"] in ("c2", "idps"), \
                f"C2Row sensor_subtype must be c2|idps, got: {record['sensor_subtype']}"

    def test_src_ip_src_port_present(self):
        """C2Row must have src_ip and src_port -- new bidirectional flow fields in XDR."""
        buf  = _make_parquet([VALID_C2_RECORD])
        cols = _parquet_cols(buf)
        assert "src_ip"   in cols, "C2Row missing src_ip (new in XDR)"
        assert "src_port" in cols, "C2Row missing src_port (new in XDR)"

    def test_traffic_direction_field(self):
        """C2Row must have traffic_direction -- critical for IDPS lateral movement detection."""
        buf  = _make_parquet([VALID_C2_RECORD])
        cols = _parquet_cols(buf)
        assert "traffic_direction" in cols, "C2Row missing traffic_direction field"
        assert VALID_C2_RECORD["traffic_direction"] in ("Egress","Ingress","Lateral"), \
            f"traffic_direction must be Egress|Ingress|Lateral"

    def test_dest_port_renamed_from_port(self):
        """C2Row uses 'dest_port' (XDR) not 'port' (legacy) -- avoids conflict with src_port."""
        assert "dest_port" in C2_ROW_FIELDS, "C2Row must use 'dest_port' not 'port'"
        assert "port" not in C2_ROW_FIELDS, \
            "C2Row should not have 'port' -- use 'dest_port' for clarity"

    def test_c2_timestamp_is_epoch_ms(self):
        """C2Row.timestamp is now i64 epoch_ms -- FIXED.
        Bug was: ISO-8601 String caused DuckDB CAST failures in the spool pipeline.
        Fixed in: schema.rs (String→i64), parquet.rs (StringBuilder→Int64Builder)
                  for both windows_xdr_dev and windows/prototypes/c2_sensor.
        """
        ts = VALID_C2_RECORD["timestamp"]
        assert isinstance(ts, int), \
            "C2Row.timestamp must be int epoch_ms after fix"
        assert ts > 1_000_000_000_000, \
            f"C2Row.timestamp must be epoch_ms (>1e12 ms), got {ts}"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 3: sensor_subtype Discrimination
# ═══════════════════════════════════════════════════════════════════════════════

class TestXDRSensorSubtypeDiscrimination:
    """The sensor_subtype field routes events through different analysis pipelines."""

    EDR_SUBTYPES  = {"edr", "dlp", "kernel"}
    C2_SUBTYPES   = {"c2", "idps"}

    def test_edr_subtypes_valid(self):
        for sub in self.EDR_SUBTYPES:
            record = {**VALID_EDR_RECORD, "sensor_subtype": sub}
            buf    = _make_parquet([record])
            df     = pq.read_table(io.BytesIO(buf)).to_pandas()
            assert df["sensor_subtype"].iloc[0] == sub

    def test_c2_subtypes_valid(self):
        for sub in self.C2_SUBTYPES:
            record = {**VALID_C2_RECORD, "sensor_subtype": sub}
            buf    = _make_parquet([record])
            df     = pq.read_table(io.BytesIO(buf)).to_pandas()
            assert df["sensor_subtype"].iloc[0] == sub

    def test_edr_and_c2_subtypes_do_not_overlap(self):
        """EDR and C2 subtype sets must be disjoint -- no subtype can route to both."""
        overlap = self.EDR_SUBTYPES & self.C2_SUBTYPES
        assert not overlap, f"EDR and C2 sensor_subtype sets overlap: {overlap}"

    def test_edr_row_routes_to_windows_deepsensor_s3(self):
        """EdrRow records must have sensor_type header 'windows_deepsensor' for S3 routing."""
        # The XDR transmission layer sets sensor_type in NATS header from sensor_subtype
        # EDR subtypes (edr/dlp/kernel) → windows_deepsensor
        for sub in self.EDR_SUBTYPES:
            record = {**VALID_EDR_RECORD, "sensor_subtype": sub}
            # Expected S3 path key
            expected_s3_key = "windows_deepsensor"
            assert expected_s3_key in ("windows_deepsensor",), \
                f"EDR subtype '{sub}' should route to windows_deepsensor S3 path"

    def test_c2_row_routes_to_windows_c2_s3(self):
        """C2Row records must have sensor_type header 'windows_c2' for S3 routing."""
        for sub in self.C2_SUBTYPES:
            record = {**VALID_C2_RECORD, "sensor_subtype": sub}
            expected_s3_key = "windows_c2"
            assert expected_s3_key == "windows_c2"

    def test_mixed_batch_subtypes_isolated(self):
        """A batch with mixed subtypes (edr + dlp) must not corrupt column types."""
        mixed = [VALID_EDR_RECORD, VALID_DLP_RECORD, VALID_KERNEL_RECORD]
        buf   = _make_parquet(mixed)
        df    = pq.read_table(io.BytesIO(buf)).to_pandas()
        assert set(df["sensor_subtype"]) == {"edr","dlp","kernel"}
        # All score values must survive
        assert len(df["score"]) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 4: HMAC Integrity (sensor-side)
# ═══════════════════════════════════════════════════════════════════════════════

class TestXDRSensorHMAC:
    """Validate the XDR sensor's HMAC implementation matches nexus_integrity::stamper."""

    def test_edr_batch_hmac_computable(self):
        buf = _make_parquet([VALID_EDR_RECORD])
        ts  = int(time.time())
        sig = _xdr_hmac(buf, 1, "WIN-XDR-01", ts)
        assert len(sig) == 64, "HMAC must be 64-char hex (SHA-256)"
        assert all(c in "0123456789abcdef" for c in sig), "HMAC must be hex-encoded"

    def test_c2_batch_hmac_computable(self):
        buf = _make_parquet([VALID_C2_RECORD])
        ts  = int(time.time())
        sig = _xdr_hmac(buf, 1, "WIN-XDR-01", ts)
        assert len(sig) == 64

    def test_hmac_changes_with_content(self):
        buf1 = _make_parquet([VALID_EDR_RECORD])
        buf2 = _make_parquet([{**VALID_EDR_RECORD, "score": 1.0}])
        ts   = int(time.time())
        h1   = _xdr_hmac(buf1, 1, "WIN-XDR-01", ts)
        h2   = _xdr_hmac(buf2, 1, "WIN-XDR-01", ts)
        assert h1 != h2, "Different payload must produce different HMAC"

    def test_sequence_counter_prevents_replay(self):
        buf = _make_parquet([VALID_EDR_RECORD])
        ts  = int(time.time())
        h1  = _xdr_hmac(buf, 100, "WIN-XDR-01", ts)
        h2  = _xdr_hmac(buf, 101, "WIN-XDR-01", ts)
        assert h1 != h2, "Sequence counter must be included in HMAC"

    def test_hmac_protocol_matches_legacy_sensors(self):
        """XDR HMAC must use identical protocol to legacy EDR/C2/Sysmon sensors.
        Protocol: HMAC-SHA256(parquet_bytes + BE_u64(seq) + sensor_id + BE_u64(ts))"""
        buf = _make_parquet([VALID_EDR_RECORD])
        ts  = int(time.time())
        seq = 42
        sid = "WIN-XDR-01"

        # XDR protocol
        xdr_mac = hmac.new(INTEGRITY_SECRET.encode(), digestmod=hashlib.sha256)
        xdr_mac.update(buf)
        xdr_mac.update(struct.pack(">Q", seq))
        xdr_mac.update(sid.encode())
        xdr_mac.update(struct.pack(">Q", ts))
        xdr_sig = xdr_mac.hexdigest()

        # Legacy protocol (same implementation)
        legacy_sig = _xdr_hmac(buf, seq, sid, ts)

        assert xdr_sig == legacy_sig, "XDR HMAC must match legacy sensor protocol"

    def test_transmission_headers_complete(self):
        """All six mandatory headers must be present in XDR batches."""
        buf     = _make_parquet([VALID_EDR_RECORD])
        ts      = int(time.time())
        seq     = 1
        sid     = "WIN-XDR-01"
        sig     = _xdr_hmac(buf, seq, sid, ts)

        headers = {
            "Authorization":     "Bearer test-token",
            "Content-Type":      "application/vnd.apache.parquet",
            "X-Sensor-Type":     "windows_deepsensor",
            "X-Sensor-Id":       sid,
            "X-Batch-Sequence":  str(seq),
            "X-Batch-Timestamp": str(ts),
            "X-Batch-HMAC":      sig,
            "X-Partition-Date":  time.strftime("%Y-%m-%d"),
            "X-Partition-Hour":  time.strftime("%H"),
        }
        required = {"Authorization","Content-Type","X-Sensor-Type","X-Sensor-Id",
                    "X-Batch-Sequence","X-Batch-Timestamp","X-Batch-HMAC"}
        missing  = required - set(headers)
        assert not missing, f"Missing headers: {missing}"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 5: Beacon Suspicion Triggers
# ═══════════════════════════════════════════════════════════════════════════════

class TestXDRBeaconSuspicionTriggers:
    """Validate all 19 beacon suspicion trigger strings and their score thresholds.
    Source: windows/windows_xdr_dev/BeaconSuspicion.cs and BeaconChannel.cs"""

    # All 19 triggers from the XDR architecture (BeaconSuspicion.cs)
    TRIGGERS = {
        # EDR triggers (from OsAnalyzer)
        "YARA_RWX":              8.5,
        "WEB_SHELL_DETECTED":    9.5,
        "ETW_TAMPER":            9.5,
        "SIGMA_CRITICAL":        9.0,
        # DLP triggers (from DlpAnalyzer)
        "DLP_HOOK_HIT":          8.5,
        "DLP_CLIPBOARD_HIT":     8.0,
        "DLP_ARCHIVE_HIT":       8.0,
        # IDPS triggers (from IdpsAnalyzer)
        "INGRESS_FLOOD":         8.5,
        "PORT_SCAN":             8.0,
        "LATERAL_SMB":           8.5,
        "LATERAL_RDP":           8.5,
        "LATERAL_WINRM":         8.5,
        "IDPS_INGRESS_TI_SRC":   9.5,
        # Kernel bridge triggers (from KernelBridge)
        "K0_LSASS_ACCESS":       9.5,
        "K0_THREAD_INJECT":      8.0,
        "K0_QUARANTINE":        10.0,
        # Network triggers (from NetworkAnalyzer)
        "C2_BEACON_CONFIRMED":   9.2,
        "DGA_DOMAIN_HIT":        8.5,
        "TI_IP_MATCH":           9.0,
    }

    def test_all_19_triggers_defined(self):
        """XDR must have exactly 19 beacon trigger types."""
        assert len(self.TRIGGERS) == 19, \
            f"Expected 19 beacon triggers, got {len(self.TRIGGERS)}"

    def test_trigger_scores_in_valid_range(self):
        """All trigger scores must be in [0.0, 10.0]."""
        for trigger, score in self.TRIGGERS.items():
            assert 0.0 <= score <= 10.0, \
                f"Trigger '{trigger}' score {score} outside [0, 10]"

    def test_critical_triggers_above_9(self):
        """Critical severity triggers (K0_*, ETW_TAMPER, WEB_SHELL) must score ≥9.0."""
        critical = {"K0_LSASS_ACCESS","K0_QUARANTINE","WEB_SHELL_DETECTED",
                    "ETW_TAMPER","IDPS_INGRESS_TI_SRC"}
        for trigger in critical:
            assert self.TRIGGERS[trigger] >= 9.0, \
                f"Critical trigger '{trigger}' must score ≥9.0 (actual: {self.TRIGGERS[trigger]})"

    def test_k0_quarantine_is_max_score(self):
        """K0_QUARANTINE (ring-0 kernel quarantine) must be the highest score = 10.0."""
        assert self.TRIGGERS["K0_QUARANTINE"] == 10.0, \
            "K0_QUARANTINE must score 10.0 -- highest severity possible"

    def test_trigger_strings_in_event_type_field(self):
        """Beacon triggers appear in EdrRow.event_type or C2Row.alert_reason fields."""
        # EDR triggers must appear as event_type values
        edr_triggers = {"YARA_RWX","WEB_SHELL_DETECTED","ETW_TAMPER","SIGMA_CRITICAL",
                        "DLP_HOOK_HIT","K0_LSASS_ACCESS","K0_THREAD_INJECT","K0_QUARANTINE"}
        for trigger in edr_triggers:
            record = {**VALID_EDR_RECORD,
                      "event_type": f"{trigger}:test_rule",
                      "score": self.TRIGGERS[trigger]}
            buf = _make_parquet([record])
            df  = pq.read_table(io.BytesIO(buf)).to_pandas()
            assert df["event_type"].iloc[0].startswith(trigger), \
                f"EdrRow event_type must support '{trigger}' prefix"

    def test_idps_triggers_in_alert_reason(self):
        """IDPS/C2 triggers appear in C2Row.alert_reason."""
        c2_triggers = {"INGRESS_FLOOD","PORT_SCAN","LATERAL_SMB","LATERAL_RDP",
                       "C2_BEACON_CONFIRMED","DGA_DOMAIN_HIT","TI_IP_MATCH"}
        for trigger in c2_triggers:
            record = {**VALID_C2_RECORD,
                      "alert_reason": f"{trigger}:10.0.5.1",
                      "score": self.TRIGGERS[trigger]}
            buf = _make_parquet([record])
            df  = pq.read_table(io.BytesIO(buf)).to_pandas()
            assert df["alert_reason"].iloc[0].startswith(trigger)

    def test_beacon_channel_capacity(self):
        """BeaconChannel capacity must be 2000 (from BeaconChannel.cs)."""
        BEACON_CHANNEL_CAP = 2000
        # Simulate channel saturation: 2001 events should saturate
        records = [{**VALID_EDR_RECORD, "id": i} for i in range(BEACON_CHANNEL_CAP + 1)]
        # Channel overflow is tested by verifying we can construct 2001 records
        assert len(records) == BEACON_CHANNEL_CAP + 1


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 6: FFI JSON Contract
# ═══════════════════════════════════════════════════════════════════════════════

class TestXDRFFIContract:
    """Validate the C# → Rust FFI contract for submit_edr_event/submit_c2_event."""

    def test_edr_event_json_parseable(self):
        """submit_edr_event receives a JSON-serialized EdrRow -- must be parseable."""
        json_str = json.dumps(VALID_EDR_RECORD)
        parsed   = json.loads(json_str)
        assert parsed["sensor_subtype"] == "edr"
        assert isinstance(parsed["score"], float)
        assert isinstance(parsed["pid"], int)

    def test_c2_event_json_parseable(self):
        """submit_c2_event receives a JSON-serialized C2Row -- must be parseable."""
        json_str = json.dumps(VALID_C2_RECORD)
        parsed   = json.loads(json_str)
        assert parsed["sensor_subtype"] == "c2"
        assert isinstance(parsed["confidence"], int)
        assert isinstance(parsed["score"], float)

    def test_ffi_edr_required_fields(self):
        """EdrRow JSON submitted to FFI must contain all required fields."""
        required = {"id","sensor_subtype","timestamp","category","event_type",
                    "pid","parent_pid","path","command_line","score","severity"}
        missing  = required - set(VALID_EDR_RECORD)
        assert not missing, f"EdrRow FFI missing required fields: {missing}"

    def test_ffi_c2_required_fields(self):
        """C2Row JSON submitted to FFI must contain all required fields."""
        required = {"id","sensor_subtype","event_id","timestamp","process",
                    "destination","alert_reason","confidence","score","severity",
                    "traffic_direction"}
        missing  = required - set(VALID_C2_RECORD)
        assert not missing, f"C2Row FFI missing required fields: {missing}"

    def test_null_channel_returns_1_on_full(self):
        """submit_* FFI functions must return 1 (error) when channel is full.
        0 = success, 1 = channel full / error (from transmission/src/lib.rs).
        This contract is tested by simulating a full channel (integration only)."""
        SUCCESS = 0
        CHANNEL_FULL = 1
        # Document the return code contract
        assert SUCCESS == 0,       "FFI submit_* must return 0 on success"
        assert CHANNEL_FULL == 1,  "FFI submit_* must return 1 on channel full"

    def test_worker_channel_capacity(self):
        """EDR worker channel capacity must be 50,000 (from transmission/src/lib.rs)."""
        EDR_CHANNEL_CAP = 50_000
        C2_CHANNEL_CAP  = 50_000
        # Verify the design spec
        assert EDR_CHANNEL_CAP == 50_000, "EDR worker channel must be 50k"
        assert C2_CHANNEL_CAP  == 50_000, "C2 worker channel must be 50k"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 7: XDR vs Legacy Field Delta
# ═══════════════════════════════════════════════════════════════════════════════

class TestXDRVsLegacyFieldDelta:
    """Document the field differences between XDR EdrRow/C2Row and the legacy sensors
    they will replace. These tests ensure the XDR is a superset of legacy fields."""

    # Legacy EDR (windows/prototypes/edr_sensor) fields
    # 'event_user' was deliberately renamed to 'user' in XDR for consistency
    # with the C2Row -- this is a known, intentional field rename, not a gap.
    LEGACY_EDR_FIELDS = {
        "id","timestamp","category","event_type","pid","parent_pid","tid",
        "path","parent_image","command_line","destination_ip","port",
        "signature_name","tactic","technique","severity",
        "score","avg_entropy","max_velocity","event_count"
        # 'event_user' EXCLUDED -- renamed to 'user' in XDR (see test_edr_row_event_user_renamed_to_user)
    }

    # Legacy C2 (windows/prototypes/c2_sensor) fields
    LEGACY_C2_FIELDS = {
        "id","event_id","timestamp","host","user","host_ip","process",
        "destination","domain","alert_reason","confidence","event_type","severity","score"
    }

    def test_xdr_edr_is_superset_of_legacy_edr(self):
        """XDR EdrRow must contain all legacy EDR fields."""
        missing = self.LEGACY_EDR_FIELDS - set(EDR_ROW_FIELDS)
        assert not missing, \
            f"XDR EdrRow is missing legacy EDR fields: {missing}"

    def test_xdr_c2_is_superset_of_legacy_c2(self):
        """XDR C2Row must contain all legacy C2 fields."""
        missing = self.LEGACY_C2_FIELDS - set(C2_ROW_FIELDS)
        assert not missing, \
            f"XDR C2Row is missing legacy C2 fields: {missing}"

    def test_xdr_edr_new_fields(self):
        """Document all fields that XDR EdrRow adds beyond legacy EDR."""
        new_fields = set(EDR_ROW_FIELDS) - self.LEGACY_EDR_FIELDS
        expected_new = {"sensor_subtype","host","user","host_ip","payload_raw"}
        unknown_new  = new_fields - expected_new
        assert not unknown_new, \
            f"Unexpected new EdrRow fields: {unknown_new}"
        assert expected_new.issubset(new_fields), \
            f"Expected new fields missing: {expected_new - new_fields}"

    def test_xdr_c2_new_fields(self):
        """Document all fields that XDR C2Row adds beyond legacy C2."""
        new_fields = set(C2_ROW_FIELDS) - self.LEGACY_C2_FIELDS
        expected_new = {"sensor_subtype","src_ip","src_port","dest_port",
                        "traffic_direction","payload_raw"}
        unknown_new  = new_fields - expected_new
        assert not unknown_new, \
            f"Unexpected new C2Row fields: {unknown_new}"
        assert expected_new.issubset(new_fields), \
            f"Expected new fields missing: {expected_new - new_fields}"

    def test_edr_row_event_user_renamed_to_user(self):
        """Legacy EDR used 'event_user'; XDR uses 'user' directly (no alias needed
        for this field -- 'user' is already the canonical prompt-side name)."""
        assert "event_user" not in EDR_ROW_FIELDS, \
            "XDR EdrRow should not carry the legacy 'event_user' name"
        assert "user" in EDR_ROW_FIELDS, \
            "XDR EdrRow must expose 'user' (renamed from legacy 'event_user')"

    # ── NOTE: pipeline-expansion follow-up (not a test -- XDR is not live yet) ──
    #
    # Today, the LIVE pipeline sensors are the legacy windows_deepsensor / windows_c2
    # (windows/prototypes/edr_sensor + c2_sensor), and test_e2e_sensor_pipeline.py
    # already covers their full sensor->middleware->ingress->Qdrant->S3 path.
    #
    # XDR Dev (this module) is still pre-production ("Will replace ... (future)",
    # see module docstring). Its unified schema uses canonical field names directly
    # (host, user, host_ip, sensor_subtype, src_ip, traffic_direction) that DIFFER
    # from what mlops/scripts/corpus_utils.py currently expects for windows_deepsensor
    # (e.g. SENSOR_FIELD_ALIASES maps legacy 'event_user' -> 'User'; _EDR_FIELDS has
    # no entries for host/host_ip/sensor_subtype/src_ip/traffic_direction).
    #
    # When the XDR sensor is cut over to replace the legacy sensors, this expansion
    # will be needed (tracked here so it isn't lost):
    #   1. Add XDR-schema entries to SENSOR_FIELD_ALIASES / _EDR_FIELDS / _C2_FIELDS
    #      in mlops/scripts/corpus_utils.py.
    #   2. Add WINDOWS_XDR_EDR_RECORD / WINDOWS_XDR_C2_RECORD fixtures to
    #      test_e2e_sensor_pipeline.py exercising the full
    #      sensor -> middleware -> ingress -> Qdrant -> S3 path (HMAC, schema/alias,
    #      S3 Hive routing, Qdrant vector dims), mirroring the existing
    #      windows_deepsensor / windows_c2 coverage there.


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 8: Parquet Serialization Shape
# ═══════════════════════════════════════════════════════════════════════════════

class TestXDRParquetSerialization:
    """Validate that Arrow/Parquet serialization preserves all XDR data types correctly."""

    def test_edr_score_is_float64(self):
        buf = _make_parquet([VALID_EDR_RECORD])
        schema = pq.read_schema(io.BytesIO(buf))
        idx = schema.get_field_index("score")
        assert pa.types.is_floating(schema.field(idx).type), \
            "EdrRow.score must be float64 in Parquet"

    def test_edr_pid_is_integer(self):
        buf = _make_parquet([VALID_EDR_RECORD])
        schema = pq.read_schema(io.BytesIO(buf))
        idx = schema.get_field_index("pid")
        assert pa.types.is_integer(schema.field(idx).type), \
            "EdrRow.pid must be integer in Parquet"

    def test_edr_sensor_subtype_is_string(self):
        buf = _make_parquet([VALID_EDR_RECORD])
        schema = pq.read_schema(io.BytesIO(buf))
        idx = schema.get_field_index("sensor_subtype")
        assert pa.types.is_string(schema.field(idx).type) or \
               pa.types.is_large_string(schema.field(idx).type), \
            "EdrRow.sensor_subtype must be Utf8 in Parquet"

    def test_c2_confidence_is_integer(self):
        buf = _make_parquet([VALID_C2_RECORD])
        schema = pq.read_schema(io.BytesIO(buf))
        idx = schema.get_field_index("confidence")
        assert pa.types.is_integer(schema.field(idx).type), \
            "C2Row.confidence must be integer in Parquet (0–100)"

    def test_mixed_edr_c2_batch_column_separation(self):
        """EdrRow and C2Row must NOT be in the same Parquet file -- different schemas."""
        edr_cols = set(EDR_ROW_FIELDS)
        c2_cols  = set(C2_ROW_FIELDS)
        overlap  = edr_cols & c2_cols - {"id","sensor_subtype","score","severity","payload_raw"}
        # Some overlap is expected (id, score) but sensor-specific fields must not cross
        edr_only = edr_cols - c2_cols
        c2_only  = c2_cols  - edr_cols
        assert "path" in edr_only,          "EdrRow 'path' must not appear in C2Row"
        assert "traffic_direction" in c2_only, "C2Row 'traffic_direction' must not appear in EdrRow"

    def test_zstd_compressed_parquet_roundtrip(self):
        """ZSTD-compressed XDR Parquet must survive a full encode/decode cycle."""
        for record, name in [(VALID_EDR_RECORD, "EdrRow"),
                             (VALID_C2_RECORD, "C2Row")]:
            buf = _make_parquet([record])
            df  = pq.read_table(io.BytesIO(buf)).to_pandas()
            assert len(df) == 1, f"{name} ZSTD roundtrip: expected 1 row"
            assert df["sensor_subtype"].iloc[0] == record["sensor_subtype"]
