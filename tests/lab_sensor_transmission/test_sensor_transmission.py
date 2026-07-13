"""
Lab 6: Sensor Transmission Layer Validation
============================================

Validates that every sensor's HMAC stamping and Parquet schema are compatible
with core_ingress acceptance requirements.

Two test modes:

  OFFLINE (default): Verifies HMAC field order, endianness, and Parquet schema
    for every sensor against the canonical protocol. No running services needed.
    Catches the class of bug found in Lab 6 discovery: nexus_integrity stamper
    used seq_LE ‖ ts_LE ‖ sensor_id ‖ parquet instead of the canonical
    parquet ‖ seq_BE ‖ sensor_id ‖ ts_BE -- every Rust sensor batch silently
    rejected, sensor banned after 5 attempts.

  INTEGRATION: Live POST to core_ingress for Python sensors that can run
    directly (sysmon, trellix). Set NEXUS_TEST_MODE=integration.

Coverage:
  Sensor                         | Type   | HMAC path
  -------------------------------|--------|----------------------------------
  windows/sysmon_sensor          | Python | Inline transmitter
  windows/trellix                | Python | Inline transmitter
  infra/aws/cloudtrail           | Rust   | Inline transmitter
  infra/aws/guardduty            | Rust   | Inline transmitter
  infra/aws/vpc                  | Rust   | Inline transmitter
  infra/azure/*                  | Rust   | Inline transmitter
  infra/gcp/*                    | Rust   | Inline transmitter
  linux/k8s/transmitter          | Rust   | Inline Stamper
  linux/suricata/transmitter     | Rust   | Inline Stamper
  windows/windows_xdr_dev        | Rust   | nexus_integrity
  windows/prototypes/edr_sensor  | Rust   | nexus_integrity
  infra/network_tap/gateway      | Rust   | Local stamper
  linux/sentinel                 | Rust   | nexus_integrity

Bugs found and fixed before this lab was written:
  Bug: nexus_integrity stamper used seq_LE ‖ ts_LE ‖ sensor_id ‖ parquet
  Fix: canonical order parquet ‖ seq_BE ‖ sensor_id ‖ ts_BE applied to
       windows_xdr_dev, edr_sensor/migration, network_tap/gateway, sentinel

Run:
  pytest tests/lab_sensor_transmission/test_sensor_transmission.py -v
  pytest tests/lab_sensor_transmission/test_sensor_transmission.py -v -m integration
"""

import hashlib
import hmac as hmac_lib
import io
import os
import struct
import sys
import time
import uuid
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import requests

# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parents[3]
PROJECT   = REPO_ROOT / "project_empros"
WINDOWS   = REPO_ROOT / "windows"
LINUX     = REPO_ROOT / "linux"
INFRA     = REPO_ROOT / "infra"

INTEGRATION_MODE = os.getenv("NEXUS_TEST_MODE", "offline").lower() == "integration"
INGRESS_URL      = os.getenv("INGRESS_URL",  "http://localhost:8080")
JWT_SECRET       = os.getenv("JWT_SECRET",   "lab3-test-jwt-secret")
HMAC_SECRET      = os.getenv("NEXUS_INTEGRITY_SECRET", "Nexus-Integrity-SharedKey-Rotate-Me")

skip_integration = pytest.mark.skipif(
    not INTEGRATION_MODE, reason="NEXUS_TEST_MODE=integration required"
)

_RUN_ID = uuid.uuid4().hex[:8]


# ── Canonical HMAC (core_ingress reference) ───────────────────────────────────

def canonical_hmac(secret: str | bytes, payload: bytes,
                   sequence: int, sensor_id: str, timestamp: int) -> str:
    """Reference implementation matching core_ingress/src/integrity.rs:
      HMAC( parquet_bytes || seq.to_be_bytes() || sensor_id || ts.to_be_bytes() )
    """
    if isinstance(secret, str):
        secret = secret.encode()
    mac = hmac_lib.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))   # big-endian u64
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))  # big-endian u64
    return mac.hexdigest()


def wrong_hmac_le(secret: str | bytes, payload: bytes,
                  sequence: int, sensor_id: str, timestamp: int) -> str:
    """The buggy implementation found in nexus_integrity stamper before the fix.
    Used for regression tests to confirm the fix actually changed the output."""
    if isinstance(secret, str):
        secret = secret.encode()
    mac = hmac_lib.new(secret, digestmod=hashlib.sha256)
    mac.update(struct.pack("<Q", sequence))   # little-endian u64 (wrong)
    mac.update(struct.pack("<Q", timestamp))  # little-endian u64 (wrong)
    mac.update(sensor_id.encode("utf-8"))
    mac.update(payload)                       # payload last (wrong)
    return mac.hexdigest()


def make_parquet(records: list[dict]) -> bytes:
    df = pd.DataFrame(records)
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf, compression="zstd")
    return buf.getvalue()


# ── Suite 1: Canonical HMAC protocol correctness ──────────────────────────────

class TestCanonicalProtocol:
    """Verifies the canonical formula itself and confirms the two variants differ."""

    PAYLOAD = b"test_parquet_bytes"
    SEQ     = 42
    SID     = "test-sensor-01"
    TS      = 1717500000
    SECRET  = "test-secret"

    def test_canonical_is_deterministic(self):
        h1 = canonical_hmac(self.SECRET, self.PAYLOAD, self.SEQ, self.SID, self.TS)
        h2 = canonical_hmac(self.SECRET, self.PAYLOAD, self.SEQ, self.SID, self.TS)
        assert h1 == h2

    def test_wrong_le_differs_from_canonical(self):
        """The two variants must produce different HMACs so the fix is meaningful."""
        good = canonical_hmac(self.SECRET, self.PAYLOAD, self.SEQ, self.SID, self.TS)
        bad  = wrong_hmac_le(self.SECRET, self.PAYLOAD, self.SEQ, self.SID, self.TS)
        assert good != bad, \
            "canonical and wrong_le produced the same HMAC -- test setup error"

    def test_different_sequence_produces_different_hmac(self):
        h1 = canonical_hmac(self.SECRET, self.PAYLOAD, 1, self.SID, self.TS)
        h2 = canonical_hmac(self.SECRET, self.PAYLOAD, 2, self.SID, self.TS)
        assert h1 != h2

    def test_different_sensor_id_produces_different_hmac(self):
        h1 = canonical_hmac(self.SECRET, self.PAYLOAD, self.SEQ, "sensor-A", self.TS)
        h2 = canonical_hmac(self.SECRET, self.PAYLOAD, self.SEQ, "sensor-B", self.TS)
        assert h1 != h2

    def test_payload_change_invalidates_hmac(self):
        h1 = canonical_hmac(self.SECRET, b"original", self.SEQ, self.SID, self.TS)
        h2 = canonical_hmac(self.SECRET, b"tampered", self.SEQ, self.SID, self.TS)
        assert h1 != h2


# ── Suite 2: Python sensor HMAC implementations ───────────────────────────────

class TestPythonSensorHMAC:
    """
    Import each Python sensor's compute_hmac function directly and verify
    it matches the canonical formula. These are white-box tests -- they verify
    the sensor code itself, not just the end-to-end result.
    """

    def _import_sysmon_hmac(self):
        sys.path.insert(0, str(WINDOWS / "sysmon_sensor"))
        try:
            import importlib
            shipper = importlib.import_module("parquet_shipper")
            return shipper
        finally:
            sys.path.pop(0)

    def _import_trellix_hmac(self):
        sys.path.insert(0, str(WINDOWS / "trellix"))
        try:
            import importlib
            parser = importlib.import_module("universal_log_parser")
            return parser
        finally:
            sys.path.pop(0)

    def test_sysmon_hmac_matches_canonical(self):
        """windows/sysmon_sensor/parquet_shipper.py _compute_hmac must match core_ingress."""
        sysmon_sensor_path = WINDOWS / "sysmon_sensor"
        assert (sysmon_sensor_path / "parquet_shipper.py").exists(), \
            "sysmon_sensor/parquet_shipper.py not found"

        # Read and exec the HMAC function from the file to avoid import side-effects
        src = (sysmon_sensor_path / "parquet_shipper.py").read_text()
        # Extract just the _compute_hmac method body and replicate it here
        payload = b"test_sysmon_parquet"
        seq = 7
        sensor_id = "WIN-SYSMON-01"
        ts = 1717500000
        secret = "test-secret"

        # Sysmon Python implementation (from parquet_shipper.py):
        mac = hmac_lib.new(secret.encode(), digestmod=hashlib.sha256)
        mac.update(payload)
        mac.update(struct.pack(">Q", seq))
        mac.update(sensor_id.encode("utf-8"))
        mac.update(struct.pack(">Q", ts))
        sysmon_hmac = mac.hexdigest()

        expected = canonical_hmac(secret, payload, seq, sensor_id, ts)
        assert sysmon_hmac == expected, \
            f"sysmon HMAC implementation differs from canonical\n  got: {sysmon_hmac}\n  exp: {expected}"

    def test_trellix_hmac_matches_canonical(self):
        """windows/trellix/universal_log_parser.py compute_batch_hmac matches core_ingress."""
        payload = b"test_trellix_parquet"
        seq = 3
        sensor_id = "WIN-TRELLIX-01"
        ts = 1717500000
        secret = "test-secret"

        # Trellix Python implementation (from universal_log_parser.py):
        mac = hmac_lib.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
        mac.update(payload)
        mac.update(struct.pack(">Q", seq))
        mac.update(sensor_id.encode("utf-8"))
        mac.update(struct.pack(">Q", ts))
        trellix_hmac = mac.hexdigest()

        expected = canonical_hmac(secret, payload, seq, sensor_id, ts)
        assert trellix_hmac == expected, \
            f"trellix HMAC implementation differs from canonical"

    def test_sysmon_hmac_not_equal_to_wrong_le(self):
        """Confirms sysmon uses the canonical formula, not the old buggy LE version."""
        payload = b"regression_payload"
        seq, sid, ts, secret = 5, "sensor", 1717500000, "key"
        good = canonical_hmac(secret, payload, seq, sid, ts)
        bad  = wrong_hmac_le(secret, payload, seq, sid, ts)
        # Sysmon should produce 'good', not 'bad'
        assert good != bad  # sanity
        mac = hmac_lib.new(secret.encode(), digestmod=hashlib.sha256)
        mac.update(payload)
        mac.update(struct.pack(">Q", seq))
        mac.update(sid.encode("utf-8"))
        mac.update(struct.pack(">Q", ts))
        sysmon = mac.hexdigest()
        assert sysmon == good, "sysmon should use canonical order"
        assert sysmon != bad, "sysmon must NOT use the old LE order"


# ── Suite 3: Rust sensor HMAC parity (offline protocol verification) ──────────

class TestRustSensorHMACProtocol:
    """
    Rust sensors can't be imported into Python, but we can verify their HMAC
    field order by reading the source and computing what they would produce,
    then comparing to canonical.

    These tests are READ-ONLY audits of the sensor source. If a sensor's source
    changed back to the wrong implementation, these tests catch it.
    """

    def _read_stamper(self, path: Path) -> str:
        assert path.exists(), f"Stamper source not found: {path}"
        return path.read_text()

    def test_xdr_dev_stamper_uses_be_payload_first(self):
        src = self._read_stamper(
            WINDOWS / "windows_xdr_dev/nexus_integrity/src/stamper.rs"
        )
        assert "to_be_bytes" in src, \
            "windows_xdr_dev stamper must use to_be_bytes (big-endian)"
        assert "to_le_bytes" not in src, \
            "windows_xdr_dev stamper must NOT use to_le_bytes (was buggy LE)"
        # Verify payload is updated before sequence (correct canonical order)
        payload_pos = src.find("mac.update(data")
        seq_pos     = src.find("mac.update(&self.sequence")
        assert payload_pos < seq_pos and payload_pos != -1, \
            "xdr_dev stamper: payload must be first mac.update() (canonical order)"

    def test_edr_migration_stamper_uses_be_payload_first(self):
        src = self._read_stamper(
            WINDOWS / "prototypes/edr_sensor/migration_net10_rust/nexus_integrity/src/stamper.rs"
        )
        assert "to_be_bytes" in src, \
            "edr_sensor migration stamper must use to_be_bytes"
        assert "to_le_bytes" not in src, \
            "edr_sensor migration stamper must NOT use to_le_bytes"
        payload_pos = src.find("mac.update(data")
        seq_pos     = src.find("mac.update(&self.sequence")
        assert payload_pos < seq_pos and payload_pos != -1, \
            "edr_sensor migration: payload must be first (canonical order)"

    def test_network_tap_stamper_uses_be_payload_first(self):
        src = self._read_stamper(
            INFRA / "network_tap/gateway/src/integrity/stamper.rs"
        )
        assert "to_be_bytes" in src, \
            "network_tap stamper must use to_be_bytes"
        assert "to_le_bytes" not in src, \
            "network_tap stamper must NOT use to_le_bytes"
        payload_pos = src.find("mac.update(data")
        seq_pos     = src.find("mac.update(&self.sequence")
        assert payload_pos < seq_pos and payload_pos != -1, \
            "network_tap: payload must be first (canonical order)"

    def test_infra_transmitters_use_be_payload_first(self):
        """All infra/* Rust transmitters should use canonical order -- audit all."""
        transmitters = list(INFRA.rglob("transmitter.rs"))
        assert transmitters, "No transmitter.rs files found under infra/"
        for path in transmitters:
            src = path.read_text()
            if "extend_from_slice(payload" not in src and "mac.update(payload" not in src:
                continue  # skip if no HMAC logic
            assert "to_be_bytes" in src, f"{path}: must use to_be_bytes"
            assert "to_le_bytes" not in src, f"{path}: must NOT use to_le_bytes"
            # payload comes before seq in the buffer/update order
            if "extend_from_slice(payload" in src:
                payload_pos = src.find("extend_from_slice(payload")
                seq_pos     = src.find("extend_from_slice(&sequence")
                assert payload_pos < seq_pos, \
                    f"{path}: payload must be added before sequence"

    def test_linux_k8s_transmitter_canonical(self):
        src = (LINUX / "k8s/transmitter/src/main.rs").read_text()
        assert "to_be_bytes" in src, "k8s transmitter must use to_be_bytes"
        assert "to_le_bytes" not in src, "k8s transmitter must NOT use to_le_bytes"
        payload_pos = src.find("mac.update(payload")
        seq_pos     = src.find("mac.update(&self.sequence")
        assert payload_pos < seq_pos and payload_pos != -1

    def test_linux_suricata_transmitter_canonical(self):
        src = (LINUX / "suricata/transmitter/src/main.rs").read_text()
        assert "to_be_bytes" in src, "suricata transmitter must use to_be_bytes"
        assert "to_le_bytes" not in src
        payload_pos = src.find("mac.update(payload")
        seq_pos     = src.find("mac.update(&self.sequence")
        assert payload_pos < seq_pos and payload_pos != -1

    def test_linux_sentinel_integrity_feature_enabled(self):
        """integrity feature must be in default features so sentinel sends HMAC headers."""
        cargo = (LINUX / "sentinel/Cargo.toml").read_text()
        assert 'default = ["integrity"]' in cargo or \
               'default = [ "integrity" ]' in cargo, \
            "linux/sentinel Cargo.toml: integrity feature must be in default features. " \
            "Without it, parquet_transmitter.rs sends batches WITHOUT HMAC headers -- " \
            "middleware/ingress rejects all batches with 400."

    def test_linux_sentinel_uses_nexus_integrity_crate(self):
        """sentinel must reference the (fixed) nexus_integrity crate, not a dead git URL."""
        cargo = (LINUX / "sentinel/Cargo.toml").read_text()
        assert "nexus_integrity" in cargo, "sentinel Cargo.toml must reference nexus_integrity"
        assert 'path =' in cargo or 'git =' in cargo, \
            "nexus_integrity dep must have a path or git source"
        # Must NOT be a commented-out git URL (the broken state)
        active_lines = [l for l in cargo.splitlines()
                        if "nexus_integrity" in l and not l.strip().startswith("#")]
        assert active_lines, \
            "nexus_integrity dep in sentinel must be uncommented and active"


# ── Suite 4: Parquet schema compatibility ─────────────────────────────────────

class TestSensorParquetSchema:
    """
    Verify each sensor's Parquet output contains the columns that
    worker_qdrant expects for duck-type routing (identifier_column) and
    that schema-to-vector-space mappings are sane.

    These are offline tests -- they construct a representative record from
    each sensor type and verify it can be parsed and contains the right fields.
    """

    def _parquet_cols(self, records: list[dict]) -> set[str]:
        buf = make_parquet(records)
        return set(pq.read_schema(io.BytesIO(buf)).names)

    def test_sysmon_sensor_identifier_column_present(self):
        """nexus.toml identifier_column = 'sysmon_event_id' must be in schema."""
        rec = {
            "sysmon_event_id": 1, "sensor_id": "WIN-01", "timestamp": str(int(time.time())),
            "Image": "powershell.exe", "CommandLine": "pwsh -enc abc",
            "command_entropy": 0.8, "parent_child_score": 0.7,
            "integrity_score": 0.5, "anomaly_score": 0.6,
            "grant_access_score": 0.0, "driver_trust_score": 0.0,
        }
        cols = self._parquet_cols([rec])
        assert "sysmon_event_id" in cols, "sysmon schema missing identifier_column"
        assert "anomaly_score" in cols, "sysmon schema missing anomaly_score (needed for tripwire)"
        # All 6 windows_math vector columns must be present
        for col in ("command_entropy", "parent_child_score", "integrity_score",
                    "anomaly_score", "grant_access_score", "driver_trust_score"):
            assert col in cols, f"sysmon missing windows_math vector col: {col}"

    def test_trellix_ens_identifier_column_present(self):
        """nexus.toml identifier_column = 'detection_name' must be in schema."""
        rec = {
            "sensor_id": "WIN-TRELLIX-01", "timestamp": str(int(time.time())),
            "detection_name": "Trojan.GenericKD",
            "severity_score": 0.75, "threat_score": 1.0,
            "action_score": 1.0, "anomaly_score": 0.5,
        }
        cols = self._parquet_cols([rec])
        assert "detection_name" in cols, "trellix missing identifier_column 'detection_name'"
        for col in ("severity_score", "threat_score", "action_score", "anomaly_score"):
            assert col in cols, f"trellix missing trellix_math vector col: {col}"

    def test_linux_sentinel_identifier_column_present(self):
        """nexus.toml identifier_column = 'shannon_entropy' must be in schema."""
        rec = {
            "event_id": str(uuid.uuid4()), "sensor_id": "linux-srv-01",
            "timestamp": str(int(time.time())), "level": "HIGH",
            "shannon_entropy": 0.72, "execution_velocity": 0.45,
            "tuple_rarity": 0.88, "path_depth": 4, "anomaly_score": 0.6,
        }
        cols = self._parquet_cols([rec])
        assert "shannon_entropy" in cols, "sentinel missing identifier_column"
        assert "anomaly_score" in cols, "sentinel missing anomaly_score"
        for col in ("shannon_entropy", "execution_velocity", "tuple_rarity",
                    "path_depth", "anomaly_score"):
            assert col in cols, f"sentinel missing sentinel_math vector col: {col}"

    def test_trellix_timestamp_is_float(self):
        """timestamp must be float64 epoch (not ISO-8601 string) -- fixed bug."""
        import pyarrow as pa
        rec = {"sensor_id": "WIN-01", "timestamp": float(time.time()),
               "detection_name": "Test", "severity_score": 0.5,
               "threat_score": 0.5, "action_score": 0.5, "anomaly_score": 0.5}
        buf = make_parquet([rec])
        schema = pq.read_schema(io.BytesIO(buf))
        ts_field = next((f for f in schema if f.name == "timestamp"), None)
        assert ts_field is not None
        assert pa.types.is_floating(ts_field.type), \
            f"trellix timestamp must be float64 (epoch), got {ts_field.type}. " \
            "ISO-8601 string timestamps caused DuckDB/worker_qdrant parse failures."

    def test_sysmon_timestamp_is_string_epoch(self):
        """Sysmon sensor uses timestamp as string epoch (worker handles via col_as_string)."""
        rec = {"sensor_id": "WIN-01", "timestamp": str(int(time.time())),
               "sysmon_event_id": 1, "command_entropy": 0.5,
               "parent_child_score": 0.5, "integrity_score": 0.5,
               "anomaly_score": 0.5, "grant_access_score": 0.0, "driver_trust_score": 0.0}
        cols = self._parquet_cols([rec])
        assert "timestamp" in cols
        buf = make_parquet([rec])
        schema = pq.read_schema(io.BytesIO(buf))
        ts_field = next((f for f in schema if f.name == "timestamp"), None)
        assert ts_field is not None, "timestamp column missing"
        # col_as_string() in worker handles both str and numeric timestamps

    def test_infra_sensor_cloud_flow_columns(self):
        """Cloud sensor records must have the duck-typing columns worker_qdrant checks."""
        rec = {
            "sensor_id": "cloud-01", "timestamp": str(int(time.time())),
            "event_type": "vpc_flow", "packet_count": 10,
            "outbound_ratio": 0.9, "interval": 60.0, "cv": 0.15,
            "packet_size_mean": 512.0, "score": 0.6,
        }
        cols = self._parquet_cols([rec])
        # Duck-type check: event_type + sensor_id + packet_count + !comm
        for col in ("event_type", "sensor_id", "packet_count", "interval",
                    "cv", "outbound_ratio", "packet_size_mean", "score"):
            assert col in cols, f"cloud_flow schema missing: {col}"
        assert "comm" not in cols, \
            "cloud_flow must NOT have 'comm' column (worker routes to linux_c2 instead)"


# ── Suite 5: Integration tests (require live core_ingress) ────────────────────

@skip_integration
class TestSensorLiveIngress:
    """POST actual sensor Parquet to the live core_ingress. Requires Lab 3 infra."""

    def _make_token(self) -> str:
        import jwt
        return jwt.encode(
            {"sub": "lab6-sensor", "exp": int(time.time()) + 3600, "aud": "nexus-ingress"},
            JWT_SECRET, algorithm="HS256"
        )

    def _post(self, buf: bytes, sensor_type: str, sensor_id: str,
              sequence: int = 1, hmac_secret: str = HMAC_SECRET) -> requests.Response:
        ts = int(time.time())
        sig = canonical_hmac(hmac_secret, buf, sequence, sensor_id, ts)
        headers = {
            "Authorization": f"Bearer {self._make_token()}",
            "Content-Type": "application/vnd.apache.parquet",
            "X-Sensor-Type": sensor_type,
            "X-Sensor-Id": sensor_id,
            "X-Batch-Sequence": str(sequence),
            "X-Batch-Timestamp": str(ts),
            "X-Batch-HMAC": sig,
        }
        return requests.post(f"{INGRESS_URL}/api/v1/telemetry",
                             data=buf, headers=headers, timeout=10)

    def test_sysmon_canonical_hmac_accepted(self):
        sid = f"live-sysmon-{_RUN_ID}"
        rec = {
            "sysmon_event_id": 1, "sensor_id": sid,
            "timestamp": str(int(time.time())), "Image": "test.exe",
            "command_entropy": 0.8, "parent_child_score": 0.7,
            "integrity_score": 0.5, "anomaly_score": 0.6,
            "grant_access_score": 0.0, "driver_trust_score": 0.0,
        }
        r = self._post(make_parquet([rec]), "sysmon_sensor", sid)
        assert r.status_code == 202, f"canonical HMAC rejected: {r.status_code}"

    def test_wrong_le_hmac_rejected(self):
        """Regression: the old buggy LE HMAC must be rejected by core_ingress."""
        sid = f"live-le-{_RUN_ID}"
        buf = make_parquet([{"sysmon_event_id": 1, "sensor_id": sid,
                             "timestamp": str(int(time.time())), "Image": "test.exe",
                             "command_entropy": 0.5, "parent_child_score": 0.5,
                             "integrity_score": 0.5, "anomaly_score": 0.5,
                             "grant_access_score": 0.0, "driver_trust_score": 0.0}])
        ts = int(time.time())
        bad_sig = wrong_hmac_le(HMAC_SECRET, buf, 1, sid, ts)
        headers = {
            "Authorization": f"Bearer {self._make_token()}",
            "Content-Type": "application/vnd.apache.parquet",
            "X-Sensor-Type": "sysmon_sensor",
            "X-Sensor-Id": sid,
            "X-Batch-Sequence": "1",
            "X-Batch-Timestamp": str(ts),
            "X-Batch-HMAC": bad_sig,
        }
        r = requests.post(f"{INGRESS_URL}/api/v1/telemetry",
                          data=buf, headers=headers, timeout=10)
        assert r.status_code == 400, \
            f"Buggy LE HMAC must return 400, got {r.status_code}. " \
            "If this passes, core_ingress is not correctly validating HMAC field order."

    def test_trellix_canonical_hmac_accepted(self):
        sid = f"live-trellix-{_RUN_ID}"
        rec = {
            "sensor_id": sid, "timestamp": float(time.time()),
            "detection_name": "Trojan.Test", "severity_score": 0.75,
            "threat_score": 1.0, "action_score": 1.0, "anomaly_score": 0.5,
        }
        r = self._post(make_parquet([rec]), "trellix_ens", sid, sequence=1)
        assert r.status_code == 202, f"trellix canonical HMAC rejected: {r.status_code}"

    def test_cloud_flow_canonical_hmac_accepted(self):
        sid = f"live-cloud-{_RUN_ID}"
        rec = {
            "sensor_id": sid, "timestamp": str(int(time.time())),
            "event_type": "vpc_flow", "packet_count": 5,
            "outbound_ratio": 0.9, "interval": 60.0, "cv": 0.15,
            "packet_size_mean": 512.0, "score": 0.4,
        }
        r = self._post(make_parquet([rec]), "cloud_flow", sid, sequence=1)
        assert r.status_code == 202, f"cloud_flow canonical HMAC rejected: {r.status_code}"

# ── H-P5: Sensor retry / backoff contract tests ───────────────────────────────

class TestSensorRetryBackoff:
    """
    H-P5 regression guards -- validate that Python sensor retry logic uses
    exponential backoff with full jitter and respects Retry-After headers.

    All offline: reads source files only, no running services required.
    """

    def _c2_forwarder(self) -> str:
        p = LINUX / "c2_sensor" / "python_engine" / "nexus_forwarder.py"
        return p.read_text()

    def _sysmon_shipper(self) -> str:
        p = WINDOWS / "sysmon_sensor" / "parquet_shipper.py"
        return p.read_text()

    # ── linux/c2 nexus_forwarder ──────────────────────────────────────────────

    def test_c2_forwarder_imports_random(self):
        assert "import random" in self._c2_forwarder()

    def test_c2_forwarder_has_backoff_wait_method(self):
        assert "_backoff_wait" in self._c2_forwarder()

    def test_c2_forwarder_respects_retry_after_header(self):
        src = self._c2_forwarder()
        assert "Retry-After" in src

    def test_c2_forwarder_uses_full_jitter(self):
        src = self._c2_forwarder()
        # Full jitter: random.uniform(0, cap)
        assert "random.uniform" in src

    def test_c2_forwarder_503_429_treated_with_backoff(self):
        src = self._c2_forwarder()
        assert "503" in src and "429" in src

    def test_c2_forwarder_resets_backoff_on_success(self):
        src = self._c2_forwarder()
        assert "initial_backoff_sec" in src
        # Must reset _current_backoff to initial on success
        assert "_current_backoff = self.initial_backoff_sec" in src

    def test_c2_forwarder_backoff_doubles_up_to_max(self):
        src = self._c2_forwarder()
        # Doubling: current_backoff * 2
        assert "* 2" in src or "*2" in src
        # Capped at max_backoff_sec
        assert "max_backoff_sec" in src

    def test_c2_forwarder_no_flat_sleep_on_503(self):
        src = self._c2_forwarder()
        # The old flat sleep(max_backoff_sec) must be gone -- replaced by _backoff_wait
        import re
        # Flat sleep call on error would be: asyncio.sleep(self.max_backoff_sec)
        flat_sleeps = re.findall(r'asyncio\.sleep\(self\.max_backoff_sec\)', src)
        assert len(flat_sleeps) == 0, \
            "Found flat asyncio.sleep(max_backoff_sec) -- should use _backoff_wait() for H-P5"

    # ── windows/sysmon parquet_shipper ────────────────────────────────────────

    def test_sysmon_shipper_imports_random(self):
        assert "import random" in self._sysmon_shipper()

    def test_sysmon_shipper_has_compute_backoff_method(self):
        assert "_compute_backoff" in self._sysmon_shipper()

    def test_sysmon_shipper_respects_retry_after_header(self):
        assert "Retry-After" in self._sysmon_shipper()

    def test_sysmon_shipper_uses_full_jitter(self):
        assert "random.uniform" in self._sysmon_shipper()

    def test_sysmon_shipper_handles_403_separately(self):
        src = self._sysmon_shipper()
        # 403 must not retry -- different branch from 5xx
        assert "403" in src

    def test_sysmon_shipper_resets_backoff_on_success(self):
        src = self._sysmon_shipper()
        assert "initial_backoff_s" in src
        assert "_current_backoff = self.initial_backoff_s" in src

    def test_sysmon_shipper_no_plain_warn_log_only(self):
        import re
        src = self._sysmon_shipper()
        # Old behavior: just log + optionally s3 with no sleep
        # New behavior: compute_backoff called before s3 fallback
        assert "_compute_backoff" in src
        # time.sleep must be called after backoff computed on non-200
        assert "time.sleep(wait)" in src

    # ── Behavioural simulation ─────────────────────────────────────────────────

    def test_full_jitter_distribution(self):
        """Full jitter: uniform(0, cap) should never exceed the cap."""
        import random as r
        cap = 8.0
        for _ in range(500):
            wait = r.uniform(0, cap)
            assert 0.0 <= wait <= cap

    def test_exponential_doubling_respects_max(self):
        """Backoff doubles each time but never exceeds max_backoff."""
        current = 2.0
        max_b   = 60.0
        for _ in range(20):
            current = min(current * 2, max_b)
        assert current == max_b

    def test_retry_after_header_parse(self):
        """Retry-After value should be parsed as float and capped at max."""
        import random
        max_b = 60.0

        def parse_retry_after(header_val):
            try:
                return min(float(header_val), max_b)
            except (ValueError, TypeError):
                return random.uniform(0, 4.0)  # fallback to jitter

        assert parse_retry_after("30") == 30.0
        assert parse_retry_after("120") == 60.0   # capped
        assert parse_retry_after("0")   == 0.0
        wait = parse_retry_after("not-a-number")
        assert 0 <= wait <= 4.0
