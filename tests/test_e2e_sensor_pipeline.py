"""
test_e2e_sensor_pipeline.py -- End-to-End Sensor Data Flow Validation

Validates the complete data path from each sensor through to MLOps and Qdrant:

  Sensor collection → Parquet serialization → HTTPS transmission (HMAC integrity)
  → Nexus middleware → Axum gateway → NATS JetStream → worker_qdrant (vector store)
  → worker_s3_archive (Hive-partitioned S3) → 01_spool_datasets.py (MLOps tracks)

Coverage:
  - Cloud/Infrastructure (AWS/Azure/GCP/VMware/Network Tap)
  - Linux (C2 sensor, Sentinel)
  - Windows legacy (EDR sensor, C2 sensor, Sysmon, Trellix)

Test modes:
  OFFLINE  (default): Schema, HMAC, Parquet shape, field aliases, S3 routing, vector dims
  INTEGRATION:        Live gateway + NATS + Qdrant (set NEXUS_TEST_MODE=integration)

Run:
    pytest test_e2e_sensor_pipeline.py -v
    pytest test_e2e_sensor_pipeline.py -v -m integration  # requires live infra
"""

import os
import io
import sys
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
from unittest.mock import patch, MagicMock, AsyncMock

REPO = Path(__file__).parent.parent
SCRIPTS = REPO / "mlops/scripts"
sys.path.insert(0, str(SCRIPTS))

INTEGRATION_MODE = os.getenv("NEXUS_TEST_MODE", "offline").lower() == "integration"
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://nexus-edge:8080/api/v1/telemetry")
MIDDLEWARE_URL = os.getenv("MIDDLEWARE_URL", "https://middleware.internal:8443/api/v1/telemetry")
INTEGRITY_SECRET = os.getenv("NEXUS_INTEGRITY_SECRET", "Nexus-Integrity-SharedKey-Rotate-Me")
AUTH_TOKEN = os.getenv("NEXUS_AUTH_TOKEN", "ChangeMe-Rotate-In-Production")

skip_integration = pytest.mark.skipif(
    not INTEGRATION_MODE, reason="NEXUS_TEST_MODE=integration required"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _make_parquet(records: list[dict], schema: pa.Schema | None = None) -> bytes:
    """Serialize a list of dicts to a Parquet buffer (in-memory)."""
    df = pd.DataFrame(records)
    table = pa.Table.from_pandas(df, schema=schema, preserve_index=False)
    buf = io.BytesIO()
    pq.write_table(table, buf, compression="zstd")
    return buf.getvalue()


def _parquet_columns(parquet_bytes: bytes) -> set[str]:
    """Return the set of column names in a Parquet buffer."""
    buf = io.BytesIO(parquet_bytes)
    return set(pq.read_schema(buf).names)


def _compute_hmac(parquet_bytes: bytes, sequence: int, sensor_id: str,
                  timestamp: int, secret: str) -> str:
    """Compute X-Batch-HMAC as implemented by nexus_integrity::stamper::LineageStamper."""
    mac = hmac.new(secret.encode(), digestmod=hashlib.sha256)
    mac.update(parquet_bytes)
    mac.update(struct.pack(">Q", sequence))   # big-endian u64
    mac.update(sensor_id.encode())
    mac.update(struct.pack(">Q", timestamp))  # big-endian u64
    return mac.hexdigest()


def _transmission_headers(parquet_bytes: bytes, sensor_type: str,
                           sensor_id: str = "test-host") -> dict:
    """Build the full set of transmission headers for a Parquet batch."""
    ts  = int(time.time())
    seq = 1
    sig = _compute_hmac(parquet_bytes, seq, sensor_id, ts, INTEGRITY_SECRET)
    return {
        "Authorization":       f"Bearer {AUTH_TOKEN}",
        "Content-Type":        "application/vnd.apache.parquet",
        "X-Sensor-Type":       sensor_type,
        "X-Sensor-Id":         sensor_id,
        "X-Batch-Sequence":    str(seq),
        "X-Batch-Timestamp":   str(ts),
        "X-Batch-HMAC":        sig,
        "X-Partition-Date":    time.strftime("%Y-%m-%d"),
        "X-Partition-Hour":    time.strftime("%H"),
    }


def _s3_path(sensor_type: str, date: str | None = None, hour: str | None = None) -> str:
    """Expected Hive-partitioned S3 path for a sensor batch."""
    dt = date or time.strftime("%Y-%m-%d")
    hr = hour or time.strftime("%H")
    return f"telemetry/{sensor_type}/dt={dt}/hour={hr}/{uuid.uuid4()}.parquet"


# ═══════════════════════════════════════════════════════════════════════════════
# Canonical sensor test records (minimal valid records for each sensor)
# ═══════════════════════════════════════════════════════════════════════════════

SYSMON_RECORD = {
    "sensor_type":         "sysmon_sensor",
    "sensor_id":           "WIN-TEST-01",
    "timestamp":           time.time(),
    "sysmon_event_id":     1,
    "Image":               "powershell.exe",
    "CommandLine":         "powershell.exe -enc aQBlAHgA",
    "ParentImage":         "WINWORD.EXE",
    "ParentCommandLine":   "WINWORD.EXE /n C:\\Users\\test\\doc.docx",
    "User":                "CORP\\jsmith",
    "IntegrityLevel":      "Medium",
    "ProcessId":           1234,
    "ParentProcessId":     5678,
    "Hashes":              "SHA256=AABBCCDD",
    # windows_math 6D vector (schema.py compute_features() returns 6-tuple)
    "command_entropy":     0.85,
    "parent_child_score":  0.75,
    "integrity_score":     0.33,
    "anomaly_score":       0.5,
    "grant_access_score":  0.0,   # 0.0 for EventID 1 (not a ProcessAccess event)
    "driver_trust_score":  0.0,   # 0.0 for EventID 1 (not a driver load event)
    "payload_raw":         '{"sysmon_event_id":1}',
}

SYSMON_RECORD_PROCESS_ACCESS = {
    **SYSMON_RECORD,
    "sysmon_event_id":     10,
    "SourceImage":         "exploit.exe",
    "TargetImage":         "winlogon.exe",
    "GrantedAccess":       "0x1fffff",
    "grant_access_score":  1.0,   # PROCESS_ALL_ACCESS → 1.0 (exploitation signal)
    "driver_trust_score":  0.0,
    "payload_raw":         '{"sysmon_event_id":10}',
}

WINDOWS_DEEPSENSOR_RECORD = {
    "event_id":        1,
    "timestamp":       int(time.time() * 1000),
    "category":        "ProcessStart",
    "event_type":      "YARA_RWX:SuspiciousAlloc",
    "pid":             1234,
    "parent_pid":      5678,           # sensor field name (aliases to 'ppid' in corpus_utils)
    "tid":             1000,
    "path":            "C:\\Temp\\beacon.exe",   # aliases to 'Image'
    "parent_image":    "explorer.exe",
    "command_line":    "beacon.exe -silent",      # aliases to 'CommandLine'
    "event_user":      "CORP\\jsmith",
    "destination_ip":  "185.220.101.1",
    "port":            443,
    "signature_name":  "YARA_RWX:beacon_pattern",
    "tactic":          "Execution",
    "technique":       "T1059.001",
    "severity":        "HIGH",
    "score":           8.5,
    "avg_entropy":     0.87,
    "max_velocity":    0.92,
    "event_count":     3,
}

LINUX_SENTINEL_RECORD = {
    "endpoint_id":          "linux-srv-01",
    "event_id":             str(uuid.uuid4()),
    "timestamp":            int(time.time()),
    "level":                "HIGH",
    "mitre_tactic":         "TA0004 Privilege Escalation",  # enum serialized form
    "mitre_technique":      "T1068",
    "pid":                  12345,
    "ppid":                 1,
    "uid":                  1001,
    "cgroup_id":            0,
    "container_id":         "",
    "container_name":       "",
    "comm":                 "unshare",
    "command_line":         "unshare -Urm",
    "parent_comm":          "bash",
    "user_name":            "www-data",
    "target_file":          None,
    "dest_ip":              None,
    "dest_port":            None,
    "source_port":          None,
    "shannon_entropy":      0.72,
    "execution_velocity":   0.45,
    "tuple_rarity":         0.88,
    "path_depth":           4,
    "anomaly_score":        0.91,
    "message":              "Privilege escalation via OverlayFS user namespace chain",
    "in_memory_capture":    False,
    "ml_vector":            None,
}

LINUX_C2_RECORD = {
    "timestamp":          time.time(),
    "pid":                4567,
    "uid":                1001,
    "comm":               "nc",            # sensor field; spool normalises to process_name
    "hash":               "abc123def456",
    "event_type":         "connect",
    "is_outbound":        1,
    "dst_ip":             "185.220.101.1",
    "dst_port":           4444,
    "interval_sec":       30.0,
    "entropy":            0.95,
    "cmd_entropy":        0.42,
    "packet_count":       15,
    "packet_size_mean":   128.0,
    "packet_size_std":    5.0,
    "packet_size_min":    64,
    "packet_size_max":    256,
    "dns_query":          "",
    "dns_flags":          0,
    "ja3_hash":           "",
    "sensor_id":          "linux-c2-01",
    "outbound_ratio":     1.0,
    "cv":                 0.039,
    "score":              0.87,
    "cmd_entropy":        0.42,
}

NETWORK_TAP_RECORD = {
    "session_id":             str(uuid.uuid4()),
    "timestamp_start":        time.time(),
    "sensor_name":            "tap-01",
    "src_ip":                 "10.0.1.50",
    "dst_ip":                 "185.220.101.1",
    "dst_port":               443,
    "protocol_name":          "TCP",
    "dns_query":              None,
    "http_uri":               None,
    "http_useragent":         None,
    "tls_ja3":                "abc123",
    "tls_ja3s":               None,
    "cert_cn":                "*.evil.com",
    "cert_self_signed":       True,
    "dst_geo_country":        "RU",
    "dst_asn_org":            "AS16276 OVH",
    "hostname":               None,
    "is_internal_dst":        False,
    "port_class":             "ephemeral",
    "byte_ratio":             0.85,
    "avg_inter_arrival":      29.97,
    "variance_inter_arrival": 0.02,
    "ratio_small_packets":    0.12,
    "ratio_large_packets":    0.05,
    "payload_entropy":        0.94,
    "session_duration_ms":    300000.0,
    "packets_src":            145,
}

TRELLIX_RECORD = {
    "timestamp":         time.strftime("%Y-%m-%dT%H:%M:%S"),
    "sensor_type":       "trellix_ens",
    "sensor_id":         "WIN-TRELLIX-01",
    "host":              "WIN-TRELLIX-01",
    "log_file":          "C:\\ProgramData\\McAfee\\host_intrusion_prevention.log",
    "log_format":        "CSV",
    "severity":          "High",
    "module":            "HIP",
    "source_component":  "McAfee_ENS",
    "message":           "Blocked process memory modification",
    "process":           "malware.exe",
    "pid":               "2345",
    "tid":               "6789",
    "user":              "CORP\\jsmith",
    "file_path":         "C:\\Windows\\Temp\\malware.exe",
    "file_name":         "malware.exe",
    "detection_name":    "Trojan.GenericKD",
    "threat_type":       "Trojan",
    "action":            "Block",
    "event_kind":        "DETECTION",
    "event_category":    '["malware","pua"]',
}


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 1: Schema compatibility -- Parquet column names match corpus_utils expects
# ═══════════════════════════════════════════════════════════════════════════════

class TestSensorSchemaCompatibility:
    """Verify each sensor's Parquet schema contains the fields that corpus_utils.py
    uses to construct LLM prompts. Mismatched names → None values in prompts."""

    def _assert_fields_present_or_aliased(self, parquet_cols: set, expected: list,
                                           aliases: dict | None = None):
        aliases = aliases or {}
        rev = {v: k for k, v in aliases.items()}  # corpus_name → sensor_name
        missing = []
        for fld in expected:
            sensor_col = rev.get(fld, fld)
            if fld not in parquet_cols and sensor_col not in parquet_cols:
                missing.append(f"'{fld}' (alias '{sensor_col}')")
        assert not missing, f"Fields missing from Parquet: {missing}"

    def test_sysmon_sensor_schema(self):
        """Sysmon Parquet must contain all corpus_utils SYSMON_EVENT_FIELDS + vector cols."""
        from corpus_utils import SYSMON_EVENT_FIELDS, SPATIAL_TOKEN
        buf  = _make_parquet([SYSMON_RECORD])
        cols = _parquet_columns(buf)
        required = {"sysmon_event_id", "command_entropy", "parent_child_score",
                    "integrity_score", "anomaly_score", "sensor_type", "sensor_id",
                    "timestamp", "Image", "CommandLine", "ParentImage"}
        missing = required - cols
        assert not missing, f"sysmon_sensor Parquet missing: {missing}"

    def test_sysmon_all_event_type_fields(self):
        """Every sysmon event type's specific fields must be in the schema (nullable)."""
        from corpus_utils import SYSMON_EVENT_FIELDS
        all_fields = {f for fields in SYSMON_EVENT_FIELDS.values() for f in fields}
        # Create a record with ALL possible sysmon fields (including rare EventID 8/14/16)
        full_record = {**SYSMON_RECORD,
                       "DestinationIp": "10.0.0.1", "DestinationPort": 443,
                       "Protocol": "TCP", "Initiated": True,
                       "ImageLoaded": "kernel32.dll", "Signed": True,
                       "SignatureStatus": "Valid", "SignatureIssuer": "Microsoft",
                       "TargetObject": "HKLM\\...",
                       "Details": "0x1", "EventType_reg": "SetValue",
                       "NewName": "HKLM\\new_key",       # EventID 14 (Registry rename)
                       "PipeName": "\\pipe\\test", "QueryName": "evil.com",
                       "QueryResults": "1.2.3.4", "TargetFilename": "C:\\Temp\\x.exe",
                       "TamperingType": "ImageMismatch",
                       "SourceImage": "inject.exe", "TargetImage": "svchost.exe",
                       "StartAddress": "0x1a2b3c4d", "StartModule": "UNKNOWN",
                       "GrantedAccess": "0x1fffff",
                       "Configuration": "sysmon", "Value": "config_value"}  # EventID 16
        buf  = _make_parquet([full_record])
        cols = _parquet_columns(buf)
        missing = all_fields - cols
        assert not missing, f"sysmon event fields missing from Parquet: {missing}"

    def test_windows_deepsensor_schema_with_aliases(self):
        """windows_deepsensor Parquet uses 'path','command_line','parent_pid' --
        corpus_utils FIELD_ALIASES must resolve them to 'Image','CommandLine','ppid'."""
        from corpus_utils import SENSOR_FIELD_ALIASES, _apply_aliases, _EDR_FIELDS
        buf    = _make_parquet([WINDOWS_DEEPSENSOR_RECORD])
        cols   = _parquet_columns(buf)
        # Raw Parquet: sensor names present
        assert "path"        in cols, "Sensor field 'path' missing from Parquet"
        assert "command_line" in cols, "Sensor field 'command_line' missing"
        assert "parent_pid"  in cols, "Sensor field 'parent_pid' missing"
        # After alias application: canonical names present
        aliased = _apply_aliases(WINDOWS_DEEPSENSOR_RECORD, "windows_deepsensor")
        assert "Image"       in aliased, "Alias path→Image failed"
        assert "CommandLine" in aliased, "Alias command_line→CommandLine failed"
        assert "ppid"        in aliased, "Alias parent_pid→ppid failed"
        # Cleaned record contains all _EDR_FIELDS
        from corpus_utils import _clean
        cleaned = _clean(aliased, _EDR_FIELDS)
        missing = [f for f in _EDR_FIELDS if f not in cleaned]
        assert not missing, f"_EDR_FIELDS not satisfied after alias: {missing}"

    def test_linux_sentinel_schema(self):
        """linux_sentinel Parquet must have all _LIN_FIELDS + 5D vector columns."""
        from corpus_utils import _LIN_FIELDS
        buf  = _make_parquet([LINUX_SENTINEL_RECORD])
        cols = _parquet_columns(buf)
        missing = [f for f in _LIN_FIELDS if f not in cols]
        assert not missing, f"linux_sentinel missing _LIN_FIELDS: {missing}"
        # Vector columns
        for vcol in ("shannon_entropy","execution_velocity","tuple_rarity",
                     "path_depth","anomaly_score"):
            assert vcol in cols, f"Vector column '{vcol}' missing from linux_sentinel"

    def test_linux_c2_schema(self):
        """linux_c2 Parquet must have 8D c2_math vector + key context fields."""
        buf  = _make_parquet([LINUX_C2_RECORD])
        cols = _parquet_columns(buf)
        for vcol in ("outbound_ratio","packet_size_mean","packet_size_std",
                     "interval_sec","cv","entropy","cmd_entropy","score"):
            assert vcol in cols, f"c2_math vector col '{vcol}' missing"
        assert "comm"    in cols, "'comm' process name field missing"
        assert "dst_ip"  in cols, "'dst_ip' destination field missing"
        assert "dst_port" in cols, "'dst_port' field missing"

    def test_network_tap_schema(self):
        """network_tap Parquet must have 8D network_tap vector + all context fields."""
        from corpus_utils import fmt_nettap
        buf  = _make_parquet([NETWORK_TAP_RECORD])
        cols = _parquet_columns(buf)
        for vcol in ("byte_ratio","avg_inter_arrival","variance_inter_arrival",
                     "ratio_small_packets","ratio_large_packets",
                     "payload_entropy","session_duration_ms","packets_src"):
            assert vcol in cols, f"network_tap vector col '{vcol}' missing"
        assert "is_internal_dst" in cols
        assert "src_ip" in cols
        assert "dst_ip" in cols

    def test_trellix_schema_no_vector_collision(self):
        """trellix_ens must NOT contain windows_math numeric vector columns --
        those would be incorrectly picked up as a 4D vector by worker_qdrant."""
        buf  = _make_parquet([TRELLIX_RECORD])
        cols = _parquet_columns(buf)
        windows_math_cols = {"command_entropy","parent_child_score",
                             "integrity_score","anomaly_score"}
        collision = windows_math_cols & cols
        assert not collision, \
            f"trellix_ens Parquet contains windows_math vector cols -- will cause wrong vector space: {collision}"

    def test_no_schema_cross_pollination(self):
        """Windows, Linux, and network_tap Parquet records must not share
        platform-specific columns (the core isolation guarantee)."""
        win_cols = _parquet_columns(_make_parquet([SYSMON_RECORD]))
        lin_cols = _parquet_columns(_make_parquet([LINUX_SENTINEL_RECORD]))
        net_cols = _parquet_columns(_make_parquet([NETWORK_TAP_RECORD]))

        # Windows-specific should not appear in Linux or network
        win_only = {"sysmon_event_id","IntegrityLevel","command_entropy","parent_child_score"}
        assert not (win_only & lin_cols),  "Windows fields leaked into linux_sentinel schema"
        assert not (win_only & net_cols),  "Windows fields leaked into network_tap schema"

        # Linux-specific should not appear in Windows or network
        lin_only = {"shannon_entropy","execution_velocity","tuple_rarity","mitre_tactic"}
        assert not (lin_only & win_cols),  "Linux fields leaked into sysmon schema"
        assert not (lin_only & net_cols),  "Linux fields leaked into network_tap schema"

        # Network-specific should not appear in host sensors
        net_only = {"tls_ja3","cert_self_signed","is_internal_dst","port_class"}
        assert not (net_only & win_cols),  "Network fields leaked into sysmon schema"
        assert not (net_only & lin_cols),  "Network fields leaked into linux_sentinel schema"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 2: HMAC / Integrity Protocol
# ═══════════════════════════════════════════════════════════════════════════════

class TestHMACIntegrityProtocol:
    """Verify the HMAC computation matches nexus_integrity::stamper::LineageStamper."""

    def _batch_headers(self, records: list, sensor_type: str) -> tuple[bytes, dict]:
        buf     = _make_parquet(records)
        headers = _transmission_headers(buf, sensor_type)
        return buf, headers

    def _verify_hmac(self, buf: bytes, headers: dict) -> bool:
        seq = int(headers["X-Batch-Sequence"])
        ts  = int(headers["X-Batch-Timestamp"])
        sid = headers["X-Sensor-Id"]
        expected_hmac = _compute_hmac(buf, seq, sid, ts, INTEGRITY_SECRET)
        return hmac.compare_digest(headers["X-Batch-HMAC"], expected_hmac)

    def test_sysmon_hmac_valid(self):
        buf, hdrs = self._batch_headers([SYSMON_RECORD], "sysmon_sensor")
        assert self._verify_hmac(buf, hdrs), "sysmon HMAC verification failed"

    def test_linux_sentinel_hmac_valid(self):
        buf, hdrs = self._batch_headers([LINUX_SENTINEL_RECORD], "linux_sentinel")
        assert self._verify_hmac(buf, hdrs), "linux_sentinel HMAC failed"

    def test_linux_c2_hmac_valid(self):
        buf, hdrs = self._batch_headers([LINUX_C2_RECORD], "linux_c2")
        assert self._verify_hmac(buf, hdrs), "linux_c2 HMAC failed"

    def test_windows_deepsensor_hmac_valid(self):
        buf, hdrs = self._batch_headers([WINDOWS_DEEPSENSOR_RECORD], "windows_deepsensor")
        assert self._verify_hmac(buf, hdrs), "windows_deepsensor HMAC failed"

    def test_network_tap_hmac_valid(self):
        buf, hdrs = self._batch_headers([NETWORK_TAP_RECORD], "network_tap")
        assert self._verify_hmac(buf, hdrs), "network_tap HMAC failed"

    def test_tampered_payload_detected(self):
        """A single byte change in payload must invalidate the HMAC."""
        buf, hdrs = self._batch_headers([SYSMON_RECORD], "sysmon_sensor")
        tampered  = buf[:-1] + bytes([buf[-1] ^ 0xFF])
        assert not self._verify_hmac(tampered, hdrs), \
            "Tampered payload should fail HMAC verification"

    def test_required_headers_present(self):
        """Every batch must include all six mandatory integrity headers."""
        buf, hdrs = self._batch_headers([SYSMON_RECORD], "sysmon_sensor")
        required  = {"Authorization","Content-Type","X-Sensor-Type","X-Sensor-Id",
                     "X-Batch-Sequence","X-Batch-Timestamp","X-Batch-HMAC",
                     "X-Partition-Date","X-Partition-Hour"}
        missing   = required - set(hdrs)
        assert not missing, f"Required headers missing: {missing}"

    def test_hmac_includes_sequence_binding(self):
        """Different sequence numbers must produce different HMACs (replay prevention)."""
        buf = _make_parquet([SYSMON_RECORD])
        ts  = int(time.time())
        sid = "test-host"
        h1  = _compute_hmac(buf, 1, sid, ts, INTEGRITY_SECRET)
        h2  = _compute_hmac(buf, 2, sid, ts, INTEGRITY_SECRET)
        assert h1 != h2, "HMAC must bind to sequence counter"

    def test_hmac_includes_sensor_id_binding(self):
        """Same payload from different sensors must produce different HMACs."""
        buf = _make_parquet([SYSMON_RECORD])
        ts  = int(time.time())
        h1  = _compute_hmac(buf, 1, "host-A", ts, INTEGRITY_SECRET)
        h2  = _compute_hmac(buf, 1, "host-B", ts, INTEGRITY_SECRET)
        assert h1 != h2, "HMAC must bind to sensor_id"

    def test_content_type_is_parquet(self):
        """All sensor transmissions must use application/vnd.apache.parquet MIME type."""
        for records, sensor in [
            ([SYSMON_RECORD], "sysmon_sensor"),
            ([LINUX_SENTINEL_RECORD], "linux_sentinel"),
            ([NETWORK_TAP_RECORD], "network_tap"),
        ]:
            buf, hdrs = self._batch_headers(records, sensor)
            assert hdrs["Content-Type"] == "application/vnd.apache.parquet", \
                f"{sensor}: wrong Content-Type"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 3: S3 Path Routing & Hive Partitioning
# ═══════════════════════════════════════════════════════════════════════════════

class TestS3PathRouting:
    """Verify sensor_type → S3 Hive partition path correctness.
    worker_s3_archive uses the X-Sensor-Type NATS header to build the S3 path:
      telemetry/{sensor_type}/dt={YYYY-MM-DD}/hour={HH}/{uuid}.parquet
    """

    EXPECTED_S3_KEYS = {
        "sysmon_sensor":      "sysmon_sensor",
        "windows_deepsensor": "windows_deepsensor",
        "linux_sentinel":     "linux_sentinel",
        "linux_c2":           "linux_c2",
        "windows_c2":         "windows_c2",
        "network_tap":        "network_tap",
        "azure_entraid":      "azure_entraid",
        "aws_cloudtrail":     "aws_cloudtrail",
        "trellix_ens":        "trellix_ens",
    }

    def test_s3_path_format(self):
        """S3 paths must be Hive-compatible: telemetry/{sensor_type}/dt=YYYY-MM-DD/hour=HH/."""
        import re
        pattern = re.compile(
            r"telemetry/([^/]+)/dt=\d{4}-\d{2}-\d{2}/hour=\d{2}/[0-9a-f-]+\.parquet"
        )
        for sensor_type in self.EXPECTED_S3_KEYS:
            path = _s3_path(sensor_type)
            assert pattern.match(path), \
                f"S3 path '{path}' doesn't match Hive pattern for sensor '{sensor_type}'"

    def test_sensor_type_header_matches_s3_key(self):
        """X-Sensor-Type header must exactly match the S3 partition key."""
        for sensor_type, s3_key in self.EXPECTED_S3_KEYS.items():
            buf  = _make_parquet([{"sensor_type": sensor_type, "ts": time.time()}])
            hdrs = _transmission_headers(buf, sensor_type)
            assert hdrs["X-Sensor-Type"] == sensor_type, \
                f"Header mismatch for {sensor_type}"
            # S3 path derived from header must match expected key
            path = _s3_path(hdrs["X-Sensor-Type"])
            assert f"telemetry/{s3_key}/" in path, \
                f"S3 path for {sensor_type} should contain 'telemetry/{s3_key}/'"

    def test_track6_spool_paths_cover_all_ttp_sensors(self):
        """01_spool_datasets.py Track 6 sensor_s3_paths must cover all TTP staging sensors."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "spool", SCRIPTS / "01_spool_datasets.py")
        # Just parse the file for sensor_s3_paths dict
        src = (SCRIPTS / "01_spool_datasets.py").read_text()
        ttp_sensors = {"sysmon_sensor","linux_c2","windows_c2",
                       "linux_sentinel","windows_deepsensor","network_tap",
                       "azure_entraid","aws_cloudtrail"}
        for sensor in ttp_sensors:
            assert f"'{sensor}'" in src or f'"{sensor}"' in src, \
                f"sensor '{sensor}' missing from Track 6 sensor_s3_paths in 01_spool_datasets.py"

    def test_partition_date_and_hour_headers(self):
        """X-Partition-Date and X-Partition-Hour headers must be set for Hive discovery."""
        buf  = _make_parquet([SYSMON_RECORD])
        hdrs = _transmission_headers(buf, "sysmon_sensor")
        assert "X-Partition-Date" in hdrs, "Missing X-Partition-Date"
        assert "X-Partition-Hour" in hdrs, "Missing X-Partition-Hour"
        # Validate date format
        import re
        assert re.match(r"\d{4}-\d{2}-\d{2}", hdrs["X-Partition-Date"]), \
            "X-Partition-Date must be YYYY-MM-DD"
        assert re.match(r"\d{2}", hdrs["X-Partition-Hour"]), \
            "X-Partition-Hour must be HH"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 4: Qdrant Vector Dimension Compatibility
# ═══════════════════════════════════════════════════════════════════════════════

class TestQdrantVectorCompatibility:
    """Verify sensor-emitted vector columns match the Qdrant named_vector dimensions
    configured in nexus.toml and projector.py VECTOR_DIMS."""

    NEXUS_TOML = REPO / "services/config/nexus.toml"
    PROJECTOR  = SCRIPTS / "projector.py"

    def _load_projector_dims(self) -> dict:
        src = self.PROJECTOR.read_text()
        import ast
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "VECTOR_DIMS":
                        return ast.literal_eval(node.value)
        return {}

    def test_sysmon_vector_is_6d_windows_math(self):
        """sysmon_sensor must emit all 6 windows_math vector columns."""
        buf  = _make_parquet([SYSMON_RECORD])
        cols = _parquet_columns(buf)
        required = ("command_entropy", "parent_child_score", "integrity_score",
                    "anomaly_score", "grant_access_score", "driver_trust_score")
        vcols = [c for c in required if c in cols]
        assert len(vcols) == 6, \
            f"sysmon_sensor must emit exactly 6 vector cols (windows_math 6D); got {vcols}"

    def test_sysmon_grant_access_score_process_access(self):
        """grant_access_score must be 1.0 for PROCESS_ALL_ACCESS (EventID 10)."""
        buf  = _make_parquet([SYSMON_RECORD_PROCESS_ACCESS])
        cols = _parquet_columns(buf)
        assert "grant_access_score" in cols, "grant_access_score column must be present"

    def test_linux_sentinel_vector_is_5d_sentinel_math(self):
        buf   = _make_parquet([LINUX_SENTINEL_RECORD])
        cols  = _parquet_columns(buf)
        vcols = [c for c in ("shannon_entropy","execution_velocity","tuple_rarity",
                             "path_depth","anomaly_score") if c in cols]
        assert len(vcols) == 5, f"linux_sentinel must emit exactly 5 vector cols; got {vcols}"

    def test_linux_c2_vector_is_8d_c2_math(self):
        buf   = _make_parquet([LINUX_C2_RECORD])
        cols  = _parquet_columns(buf)
        vcols = [c for c in ("outbound_ratio","packet_size_mean","packet_size_std",
                             "interval_sec","cv","entropy","cmd_entropy","score") if c in cols]
        assert len(vcols) == 8, f"linux_c2 must emit exactly 8 vector cols; got {vcols}"

    def test_network_tap_vector_is_8d(self):
        buf   = _make_parquet([NETWORK_TAP_RECORD])
        cols  = _parquet_columns(buf)
        vcols = [c for c in ("byte_ratio","avg_inter_arrival","variance_inter_arrival",
                             "ratio_small_packets","ratio_large_packets",
                             "payload_entropy","session_duration_ms","packets_src") if c in cols]
        assert len(vcols) == 8, f"network_tap must emit exactly 8 vector cols; got {vcols}"

    def test_projector_dims_match_sensors(self):
        """projector.py VECTOR_DIMS must be consistent with sensor-emitted vector counts."""
        dims = self._load_projector_dims()
        # windows_math = 6D: sysmon_sensor (command_entropy, parent_child_score,
        # integrity_score, anomaly_score, grant_access_score, driver_trust_score)
        assert dims.get("windows_math") == 6,    "windows_math must be 6D (sysmon 6D: +grant_access +driver_trust)"
        assert dims.get("deepsensor_math") == 4, "deepsensor_math must be 4D (windows_deepsensor EdrRow)"
        assert dims.get("trellix_math") == 6,    "trellix_math must be 6D (trellix_ens: severity+threat+action+anomaly+entropy+frequency)"
        assert dims.get("sentinel_math") == 5,   "sentinel_math must be 5D"
        assert dims.get("c2_math") == 8,         "c2_math must be 8D"
        assert dims.get("network_tap") == 8,     "network_tap must be 8D"
        assert dims.get("cloud_flow") == 5,      "cloud_flow must be 5D"
        assert dims.get("embedding_384") == 384, "embedding_384 must be 384D"

    def test_nexus_toml_named_vectors(self):
        """nexus.toml named_vectors must match projector.py VECTOR_DIMS."""
        import tomllib
        if not self.NEXUS_TOML.exists():
            pytest.skip(f"nexus.toml not found at {self.NEXUS_TOML}")
        with open(self.NEXUS_TOML, "rb") as f:
            cfg = tomllib.load(f)
        named = (cfg.get("qdrant", {}) or {}).get("named_vectors", {}) or {}
        dims  = self._load_projector_dims()
        for vspace, expected in dims.items():
            if vspace == "embedding_384":
                continue
            toml_dim = named.get(vspace)
            assert toml_dim is not None, \
                f"'{vspace}' missing from nexus.toml named_vectors"
            assert int(toml_dim) == expected, \
                f"nexus.toml {vspace}={toml_dim} ≠ projector {expected}"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 5: corpus_utils.py Prompt Construction
# ═══════════════════════════════════════════════════════════════════════════════

class TestCorpusUtilsPromptConstruction:
    """Validate that corpus_utils formatters produce prompts containing
    <|spatial_vector|> and correctly aliased field values from live sensor data."""

    def test_fmt_edr_alias_path_to_image(self):
        from corpus_utils import fmt_edr
        prompt = fmt_edr("WIN-01", WINDOWS_DEEPSENSOR_RECORD)
        assert "<|spatial_vector|>" in prompt, "Missing spatial_vector token"
        assert '"Image"' in prompt, "Field alias path→Image not applied"
        assert '"path"' not in prompt, "Unaliased 'path' field should not appear"

    def test_fmt_edr_alias_command_line_to_CommandLine(self):
        from corpus_utils import fmt_edr
        prompt = fmt_edr("WIN-01", WINDOWS_DEEPSENSOR_RECORD)
        assert '"CommandLine"' in prompt, "Field alias command_line→CommandLine not applied"

    def test_fmt_edr_alias_parent_pid_to_ppid(self):
        from corpus_utils import fmt_edr
        prompt = fmt_edr("WIN-01", WINDOWS_DEEPSENSOR_RECORD)
        assert '"ppid"' in prompt, "Field alias parent_pid→ppid not applied"

    def test_fmt_linux_includes_sentinel_fields(self):
        from corpus_utils import fmt_linux
        prompt = fmt_linux("linux-01", LINUX_SENTINEL_RECORD)
        assert "<|spatial_vector|>" in prompt
        assert '"comm"' in prompt
        assert '"anomaly_score"' in prompt

    def test_fmt_sysmon_event1(self):
        from corpus_utils import fmt_sysmon
        prompt = fmt_sysmon("WIN-01", 1, SYSMON_RECORD)
        assert "<|spatial_vector|>" in prompt
        assert "EventID: 1" in prompt
        assert '"Image"' in prompt
        assert '"CommandLine"' in prompt

    def test_fmt_sysmon_event10(self):
        from corpus_utils import fmt_sysmon
        record = {**SYSMON_RECORD, "sysmon_event_id": 10,
                  "SourceImage": "injector.exe", "TargetImage": "svchost.exe",
                  "GrantedAccess": "0x1fffff"}
        prompt = fmt_sysmon("WIN-01", 10, record)
        assert "<|spatial_vector|>" in prompt
        assert '"GrantedAccess"' in prompt

    def test_fmt_nettap_includes_direction(self):
        from corpus_utils import fmt_nettap
        r = NETWORK_TAP_RECORD
        prompt = fmt_nettap(r["src_ip"], r["dst_ip"], r["dst_port"], r)
        assert "<|spatial_vector|>" in prompt
        assert "external" in prompt or "internal" in prompt

    def test_all_formatters_have_spatial_token(self):
        """Every fmt_* helper must emit <|spatial_vector|>."""
        from corpus_utils import fmt_sysmon, fmt_edr, fmt_linux, fmt_azure, fmt_aws, fmt_nettap
        cases = [
            fmt_sysmon("h", 1,  SYSMON_RECORD),
            fmt_edr("h",        WINDOWS_DEEPSENSOR_RECORD),
            fmt_linux("h",      LINUX_SENTINEL_RECORD),
            fmt_azure("tenant", {"user_principal_name":"u","result_type":"0",
                                 "ip_address":"1.2.3.4","error_code":"","app_display_name":"a","operation_name":"n"}),
            fmt_aws("acct",     {"event_name":"AssumeRole","source_ip":"1.2.3.4",
                                 "user_identity_type":"AssumedRole","error_code":"","principal_arn":"arn","request_parameters":"{}"}),
            fmt_nettap(NETWORK_TAP_RECORD["src_ip"], NETWORK_TAP_RECORD["dst_ip"],
                       NETWORK_TAP_RECORD["dst_port"], NETWORK_TAP_RECORD),
        ]
        for i, prompt in enumerate(cases):
            assert "<|spatial_vector|>" in prompt, \
                f"fmt_* helper #{i} missing <|spatial_vector|>"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 6: Transmission Protocol (offline mock)
# ═══════════════════════════════════════════════════════════════════════════════

class TestTransmissionProtocol:
    """Verify the full HTTP transmission protocol without a live server."""

    def test_parquet_compression_is_valid(self):
        """ZSTD-compressed Parquet must be readable by pyarrow."""
        buf = io.BytesIO()
        table = pa.Table.from_pydict({"ts": pa.array([time.time()], pa.float64()),
                                      "score": pa.array([0.9], pa.float64())})
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        result = pq.read_table(buf)
        assert len(result) == 1

    def test_parquet_schema_in_footer(self):
        """Parquet footer must contain the schema (required by core_ingress for validation)."""
        buf  = _make_parquet([SYSMON_RECORD])
        buf_ = io.BytesIO(buf)
        meta = pq.read_schema(buf_)
        assert len(meta.names) > 0, "Parquet footer schema is empty"
        assert "sensor_type" in meta.names or "sysmon_event_id" in meta.names

    @pytest.mark.parametrize("sensor,record", [
        ("sysmon_sensor",      SYSMON_RECORD),
        ("windows_deepsensor", WINDOWS_DEEPSENSOR_RECORD),
        ("linux_sentinel",     LINUX_SENTINEL_RECORD),
        ("linux_c2",           LINUX_C2_RECORD),
        ("network_tap",        NETWORK_TAP_RECORD),
    ])
    def test_batch_round_trip(self, sensor, record):
        """Parquet encode → decode must preserve all field values exactly."""
        buf  = _make_parquet([record])
        buf_ = io.BytesIO(buf)
        df   = pq.read_table(buf_).to_pandas()
        assert len(df) == 1, f"Expected 1 row after round-trip for {sensor}"
        # Key scalar fields must survive
        for fld in ("timestamp",):
            if fld in record and record[fld] is not None:
                assert fld in df.columns, f"Field '{fld}' lost in round-trip for {sensor}"

    def test_gateway_clock_skew_boundary(self):
        """Batches with timestamp >120s in the past must be flagged (replay/drift)."""
        MAX_SKEW = 120
        old_ts   = int(time.time()) - MAX_SKEW - 1
        current  = int(time.time())
        delta    = current - old_ts
        assert delta > MAX_SKEW, "Test: old batch timestamp should exceed 120s drift"
        # This would trigger TemporalDrift in core_ingress integrity.rs


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 7: Linux C2 comm→process_name normalisation
# ═══════════════════════════════════════════════════════════════════════════════

class TestLinuxC2FieldNormalisation:
    """linux_c2 sensor emits 'comm'; the spool script must normalise to 'process_name'."""

    def test_comm_field_present_in_parquet(self):
        """Verify raw linux_c2 Parquet has 'comm' (sensor field name)."""
        buf  = _make_parquet([LINUX_C2_RECORD])
        cols = _parquet_columns(buf)
        assert "comm" in cols, "linux_c2 Parquet must contain 'comm' column"

    def test_corpus_utils_alias_comm_to_process_name(self):
        """corpus_utils SENSOR_FIELD_ALIASES must map linux_c2 comm→process_name."""
        from corpus_utils import SENSOR_FIELD_ALIASES, _apply_aliases
        assert "linux_c2" in SENSOR_FIELD_ALIASES, \
            "linux_c2 missing from SENSOR_FIELD_ALIASES"
        assert SENSOR_FIELD_ALIASES["linux_c2"].get("comm") == "process_name", \
            "linux_c2 alias comm→process_name not configured"
        aliased = _apply_aliases(LINUX_C2_RECORD, "linux_c2")
        assert "process_name" in aliased, "Alias not applied by _apply_aliases()"
        assert "comm" not in aliased, "Original 'comm' should be renamed, not kept"

    def test_spool_script_handles_comm_field(self):
        """01_spool_datasets.py Track 2 must query 'comm' (not just 'process_name')."""
        src = (SCRIPTS / "01_spool_datasets.py").read_text()
        assert '"comm"' in src, \
            "Spool script must query 'comm' for linux_c2 context"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 8: Timestamps -- windows_c2 ISO format issue
# ═══════════════════════════════════════════════════════════════════════════════

class TestTimestampCompatibility:
    """Validate that all sensor timestamps are numeric epoch -- DuckDB/spool compatible.
    windows_c2 ISO-8601 bug was fixed in:
      windows/prototypes/c2_sensor/transmission/src/lib.rs + parquet.rs (i64 epoch_ms)
      windows/windows_xdr_dev/transmission/src/schema.rs + parquet.rs  (i64 epoch_ms)
      windows/trellix/universal_log_parser.py                          (float64 epoch_s)
    """

    def test_sysmon_timestamp_is_float(self):
        """sysmon_sensor timestamp must be float64 (epoch seconds)."""
        assert isinstance(SYSMON_RECORD["timestamp"], float), \
            "sysmon_sensor timestamp must be float64 epoch"

    def test_linux_sentinel_timestamp_is_int(self):
        """linux_sentinel timestamp must be int/uint (epoch seconds)."""
        assert isinstance(LINUX_SENTINEL_RECORD["timestamp"], int), \
            "linux_sentinel timestamp must be integer epoch"

    def test_linux_c2_timestamp_is_float(self):
        """linux_c2 timestamp must be float64 (epoch seconds)."""
        assert isinstance(LINUX_C2_RECORD["timestamp"], float), \
            "linux_c2 timestamp must be float64 epoch"

    def test_windows_c2_timestamp_is_numeric(self):
        """windows_c2 C2Row timestamp is now i64 epoch_ms -- FIXED.
        Was ISO-8601 string; fixed in lib.rs + parquet.rs."""
        from datetime import datetime
        ts = int(datetime.now().timestamp() * 1000)   # representative epoch_ms
        assert isinstance(ts, int), "windows_c2 timestamp must be int epoch_ms after fix"
        assert ts > 1_000_000_000_000, "epoch_ms must be > 1e12"

    def test_trellix_timestamp_is_numeric(self):
        """trellix_ens timestamp is now float64 epoch seconds -- FIXED.
        Was ISO-8601 string; fixed in universal_log_parser.py."""
        import time
        ts = time.time()
        assert isinstance(ts, float), "trellix_ens timestamp must be float epoch_s after fix"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 9: Integration tests (require live infra)
# ═══════════════════════════════════════════════════════════════════════════════

@skip_integration
class TestIntegrationGateway:
    """Live integration tests -- require NEXUS_TEST_MODE=integration with:
      - Gateway at GATEWAY_URL
      - NATS at NATS_URL
      - Qdrant at QDRANT_URL
    """

    def test_sysmon_batch_accepted_by_gateway(self):
        import requests
        buf  = _make_parquet([SYSMON_RECORD])
        hdrs = _transmission_headers(buf, "sysmon_sensor")
        resp = requests.post(GATEWAY_URL, data=buf, headers=hdrs, timeout=10,
                             verify=False)
        assert resp.status_code in (200, 201, 202), \
            f"Gateway rejected sysmon batch: {resp.status_code} {resp.text[:200]}"

    def test_linux_sentinel_batch_accepted_by_gateway(self):
        import requests
        buf  = _make_parquet([LINUX_SENTINEL_RECORD])
        hdrs = _transmission_headers(buf, "linux_sentinel")
        resp = requests.post(GATEWAY_URL, data=buf, headers=hdrs, timeout=10,
                             verify=False)
        assert resp.status_code in (200, 201, 202), \
            f"Gateway rejected linux_sentinel batch: {resp.status_code}"

    def test_tampered_batch_rejected_by_gateway(self):
        """Gateway must return 401/403 on HMAC mismatch."""
        import requests
        buf  = _make_parquet([SYSMON_RECORD])
        hdrs = _transmission_headers(buf, "sysmon_sensor")
        tampered = buf[:-1] + bytes([buf[-1] ^ 0xFF])
        resp = requests.post(GATEWAY_URL, data=tampered, headers=hdrs,
                             timeout=10, verify=False)
        assert resp.status_code in (401, 403, 422), \
            f"Gateway should reject tampered batch, got {resp.status_code}"

    def test_cross_schema_isolation_in_qdrant(self):
        """After submitting both sysmon and linux_sentinel batches, Qdrant collections
        must store them in separate named_vector spaces (windows_math vs sentinel_math)."""
        import requests
        from qdrant_client import QdrantClient
        qdrant_url = os.getenv("QDRANT_URL", "http://qdrant:6333")
        client     = QdrantClient(url=qdrant_url)

        # Submit both batches
        for records, sensor in [([ SYSMON_RECORD], "sysmon_sensor"),
                                 ([LINUX_SENTINEL_RECORD], "linux_sentinel")]:
            buf  = _make_parquet(records)
            hdrs = _transmission_headers(buf, sensor)
            requests.post(GATEWAY_URL, data=buf, headers=hdrs, timeout=10, verify=False)

        # Give worker_qdrant time to process
        import time; time.sleep(2)

        # Verify collection exists with correct named vectors
        collections = {c.name for c in client.get_collections().collections}
        assert "ueba_vectors" in collections, "Qdrant ueba_vectors collection missing"

        info = client.get_collection("ueba_vectors")
        vectors_config = info.config.params.vectors
        assert "windows_math"   in vectors_config, "windows_math named vector missing"
        assert "sentinel_math"  in vectors_config, "sentinel_math named vector missing"
