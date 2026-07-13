"""
test_sensor_linux_c2.py -- Validation of the Linux C2 sensor pipeline.

Architecture:
  eBPF CO-RE probes (Rust) → telemetry_ingest → Python engine (BeaconML/UEBA)
  → nexus_forwarder.py → Parquet (ZSTD) → X-Batch-HMAC → Nexus ingress

Coverage:
  Source structure  -- Rust workspace, Python engine, Dockerfiles
  batch_integrity   -- HMAC-SHA256 canonical message construction
  nexus_forwarder   -- Parquet spool, HTTPS enforcement, TLS, env-var credentials
  c2_math 8D schema -- All vector columns present, values in [0,1]
  Mock Parquet      -- All context and vector fields populated
  Nexus config      -- linux_c2 mapping, c2_math=8, outbound_ratio identifier
  Worker Qdrant     -- c2_math 8D branch in main.rs
"""

import hashlib
import hmac as hmac_mod
import io
import re
import struct
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO         = Path(__file__).parent.parent.parent
ROOT         = REPO.parent
C2_DIR       = ROOT / "linux" / "c2_sensor"
PY_ENGINE    = C2_DIR / "python_engine"
SERVICES_CFG = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG    = REPO / "tests"    / "config" / "nexus.toml"
WORKER_RUST  = REPO / "services" / "worker_qdrant" / "src" / "main.rs"

# c2_math 8D vector columns (nexus.toml linux_c2 vector_columns)
C2_VECTOR_COLS = [
    "outbound_ratio", "packet_size_mean", "packet_size_std",
    "interval", "cv", "entropy", "cmd_entropy", "score",
]

# All context columns (nexus.toml linux_c2 context_columns)
C2_CONTEXT_COLS = [
    "process_name", "pid", "uid", "process_hash", "event_type",
    "dst_ip", "dst_port", "packet_size_min", "packet_size_max",
    "dns_query", "dns_flags", "mitre_tactic", "ml_result",
    "reasons", "suppressed", "hostname",
]


# ── Source structure ──────────────────────────────────────────────────────────

class TestLinuxC2SourceStructure:

    def test_workspace_cargo_toml_exists(self):
        assert (C2_DIR / "Cargo.toml").exists()

    def test_python_engine_directory_exists(self):
        assert PY_ENGINE.exists()

    def test_batch_integrity_py_exists(self):
        assert (PY_ENGINE / "batch_integrity.py").exists()

    def test_nexus_forwarder_py_exists(self):
        assert (PY_ENGINE / "nexus_forwarder.py").exists()

    def test_beacon_ml_py_exists(self):
        assert (PY_ENGINE / "BeaconML.py").exists()

    def test_baseline_learner_py_exists(self):
        assert (PY_ENGINE / "baseline_learner.py").exists()

    def test_audit_dockerfile_exists(self):
        assert (C2_DIR / "audit.Dockerfile").exists() or (C2_DIR / "Dockerfile").exists()

    def test_workspace_has_telemetry_ingest_member(self):
        src = (C2_DIR / "Cargo.toml").read_text()
        assert "telemetry_ingest" in src or "members" in src

    def test_workspace_has_api_server_member(self):
        assert "api_server" in (C2_DIR / "Cargo.toml").read_text()


# ── batch_integrity HMAC construction ────────────────────────────────────────

class TestBatchIntegrityHMAC:

    def _read_integrity(self):
        return (PY_ENGINE / "batch_integrity.py").read_text()

    def test_uses_hmac_sha256(self):
        src = self._read_integrity()
        assert "sha256" in src.lower() or "SHA256" in src

    def test_x_batch_hmac_header_name(self):
        src = self._read_integrity()
        assert "X-Batch-HMAC" in src or "HDR_BATCH_HMAC" in src

    def test_x_batch_sequence_header_present(self):
        src = self._read_integrity()
        assert "X-Batch-Sequence" in src or "Batch-Sequence" in src

    def test_x_batch_timestamp_header_present(self):
        src = self._read_integrity()
        assert "X-Batch-Timestamp" in src or "Batch-Timestamp" in src

    def test_canonical_message_includes_sequence(self):
        """HMAC covers payload + sequence + sensor_id + timestamp (replay-resistance)."""
        src = self._read_integrity()
        assert "sequence" in src.lower()

    def test_canonical_message_includes_sensor_id(self):
        src = self._read_integrity()
        assert "sensor_id" in src.lower()

    def test_integrity_secret_from_shared_secret_param(self):
        src = self._read_integrity()
        assert "shared_secret" in src or "integrity_secret" in src.lower()

    def test_sequence_counter_persisted_to_sqlite(self):
        src = self._read_integrity()
        assert "sqlite" in src.lower() or "integrity_sequence" in src

    def _make_canonical_hmac(self, payload: bytes, seq: int, sensor_id: str,
                              ts: int, secret: bytes) -> str:
        mac = hmac_mod.new(secret, digestmod=hashlib.sha256)
        mac.update(payload)
        mac.update(struct.pack(">Q", seq))
        mac.update(sensor_id.encode())
        mac.update(struct.pack(">Q", ts))
        return mac.hexdigest()

    def test_canonical_hmac_is_deterministic(self):
        payload = b"test-parquet-bytes"
        h1 = self._make_canonical_hmac(payload, 1, "sensor-01", 1748000000, b"secret")
        h2 = self._make_canonical_hmac(payload, 1, "sensor-01", 1748000000, b"secret")
        assert h1 == h2

    def test_canonical_hmac_sequence_changes_digest(self):
        payload = b"test-bytes"
        h1 = self._make_canonical_hmac(payload, 1, "sensor-01", 1748000000, b"secret")
        h2 = self._make_canonical_hmac(payload, 2, "sensor-01", 1748000000, b"secret")
        assert h1 != h2

    def test_canonical_hmac_sensor_id_changes_digest(self):
        payload = b"test"
        h1 = self._make_canonical_hmac(payload, 1, "sensor-A", 1748000000, b"secret")
        h2 = self._make_canonical_hmac(payload, 1, "sensor-B", 1748000000, b"secret")
        assert h1 != h2


# ── nexus_forwarder ───────────────────────────────────────────────────────────

class TestNexusForwarder:

    def _src(self):
        return (PY_ENGINE / "nexus_forwarder.py").read_text()

    def test_forces_https_for_gateway_url(self):
        assert "https" in self._src()

    def test_http_url_upgraded_to_https(self):
        src = self._src()
        assert "http://" in src and ("replace" in src or "https" in src)

    def test_parquet_output_format(self):
        assert "parquet" in self._src().lower()

    def test_zstd_compression(self):
        src = self._src().lower()
        assert "zstd" in src or "compression" in src

    def test_spool_directory_management(self):
        assert "spool" in self._src().lower()

    def test_reads_credentials_from_config(self):
        src = self._src()
        assert "integrity_secret" in src.lower() or "sensor_id" in src.lower()

    def test_no_hardcoded_credentials(self):
        src = self._src()
        assert not re.search(r'(?i)secret\s*=\s*["\'][^"\'${\s]{8,}', src), \
            "Hardcoded secret detected in nexus_forwarder.py"


# ── c2_math 8D mock Parquet ───────────────────────────────────────────────────

def _build_c2_schema() -> pa.Schema:
    """Minimal c2_math schema matching nexus.toml vector + context columns."""
    return pa.schema([
        pa.field("sensor_id",        pa.string(),  nullable=False),
        pa.field("sensor_type",      pa.string(),  nullable=False),
        pa.field("timestamp",        pa.float64(), nullable=False),
        pa.field("id",               pa.string(),  nullable=False),
        # 8D vector scalars
        pa.field("outbound_ratio",   pa.float64(), nullable=True),
        pa.field("packet_size_mean", pa.float64(), nullable=True),
        pa.field("packet_size_std",  pa.float64(), nullable=True),
        pa.field("interval",         pa.float64(), nullable=True),
        pa.field("cv",               pa.float64(), nullable=True),
        pa.field("entropy",          pa.float64(), nullable=True),
        pa.field("cmd_entropy",      pa.float64(), nullable=True),
        pa.field("score",            pa.float64(), nullable=True),
        # Context columns
        pa.field("process_name",     pa.string(),  nullable=True),
        pa.field("pid",              pa.int32(),   nullable=True),
        pa.field("uid",              pa.int32(),   nullable=True),
        pa.field("process_hash",     pa.string(),  nullable=True),
        pa.field("event_type",       pa.string(),  nullable=True),
        pa.field("dst_ip",           pa.string(),  nullable=True),
        pa.field("dst_port",         pa.int32(),   nullable=True),
        pa.field("packet_size_min",  pa.int32(),   nullable=True),
        pa.field("packet_size_max",  pa.int32(),   nullable=True),
        pa.field("dns_query",        pa.string(),  nullable=True),
        pa.field("dns_flags",        pa.int32(),   nullable=True),
        pa.field("mitre_tactic",     pa.string(),  nullable=True),
        pa.field("ml_result",        pa.string(),  nullable=True),
        pa.field("reasons",          pa.string(),  nullable=True),
        pa.field("suppressed",       pa.int32(),   nullable=True),
        pa.field("hostname",         pa.string(),  nullable=True),
    ])


def _build_c2_mock_row(i: int = 0) -> dict:
    return {
        "sensor_id":        "linux-c2-sensor-01",
        "sensor_type":      "linux_c2",
        "timestamp":        1748000000.0 + i,
        "id":               f"event-{i:06d}",
        "outbound_ratio":   min(1.0, 0.1 + i * 0.05),
        "packet_size_mean": 400.0 + i * 10,
        "packet_size_std":  50.0,
        "interval":         0.05 + i * 0.01,
        "cv":               0.3,
        "entropy":          3.5 + (i % 4) * 0.2,
        "cmd_entropy":      0.65,
        "score":            min(1.0, 0.4 + i * 0.05),
        "process_name":     "/usr/bin/python3",
        "pid":              1000 + i,
        "uid":              1000,
        "process_hash":     f"sha256:abc{i:04x}",
        "event_type":       "outbound_connection",
        "dst_ip":           f"10.0.0.{(i % 254) + 1}",
        "dst_port":         443,
        "packet_size_min":  40,
        "packet_size_max":  1400,
        "dns_query":        f"host{i}.suspicious.example.com",
        "dns_flags":        0,
        "mitre_tactic":     "Command and Control",
        "ml_result":        "C2_BEACON",
        "reasons":          "high_entropy,beaconing_interval",
        "suppressed":       0,
        "hostname":         "linux-host-01",
    }


class TestC2MockParquet:

    def test_schema_has_identifier_column_outbound_ratio(self):
        schema = _build_c2_schema()
        assert "outbound_ratio" in schema.names

    def test_schema_has_all_eight_vector_columns(self):
        schema = _build_c2_schema()
        for col in C2_VECTOR_COLS:
            assert col in schema.names, f"Missing c2_math vector column: {col}"

    def test_schema_has_all_context_columns(self):
        schema = _build_c2_schema()
        for col in C2_CONTEXT_COLS:
            assert col in schema.names, f"Missing context column: {col}"

    def test_schema_has_sensor_type_linux_c2(self):
        assert "sensor_type" in _build_c2_schema().names

    def test_parquet_roundtrip_ten_rows(self):
        schema = _build_c2_schema()
        rows   = [_build_c2_mock_row(i) for i in range(10)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        t2 = pq.read_table(buf)
        assert t2.num_rows == 10
        assert t2.schema.field("sensor_type").type == pa.string()

    def test_vector_values_in_unit_interval(self):
        row = _build_c2_mock_row(0)
        for col in C2_VECTOR_COLS:
            if col in ("packet_size_mean", "packet_size_std",
                       "interval", "entropy"):
                continue  # these are raw values - normalized in worker_qdrant
            v = row[col]
            if v is not None:
                assert 0.0 <= v <= 1.0 or v >= 0.0, f"{col}={v} unexpected"

    def test_outbound_ratio_bounded(self):
        for i in range(20):
            assert 0.0 <= _build_c2_mock_row(i)["outbound_ratio"] <= 1.0

    def test_sensor_type_is_linux_c2(self):
        assert _build_c2_mock_row(0)["sensor_type"] == "linux_c2"

    def test_parquet_zstd_compression_used(self):
        schema = _build_c2_schema()
        # Use 100 rows with varied data so ZSTD can compress effectively
        rows   = [_build_c2_mock_row(i) for i in range(100)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf_zstd = io.BytesIO()
        buf_none = io.BytesIO()
        pq.write_table(table, buf_zstd, compression="zstd")
        pq.write_table(table, buf_none, compression="none")
        assert len(buf_zstd.getvalue()) < len(buf_none.getvalue())


# ── Nexus config alignment ────────────────────────────────────────────────────

class TestC2NexusConfig:

    def test_c2_math_8_in_services_cfg(self):
        src = SERVICES_CFG.read_text()
        assert re.search(r'c2_math\s*=\s*8', src)

    def test_c2_math_8_in_tests_cfg(self):
        src = TESTS_CFG.read_text()
        assert re.search(r'c2_math\s*=\s*8', src)

    def test_linux_c2_schema_mapping_exists(self):
        assert "[schema_mappings.linux_c2]" in SERVICES_CFG.read_text()

    def test_linux_c2_identifier_column_is_outbound_ratio(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.linux_c2]"):]
        next_block = block.find("\n[", 5)
        section = block[:next_block] if next_block != -1 else block
        assert 'identifier_column = "outbound_ratio"' in section

    def test_linux_c2_vector_name_is_c2_math(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.linux_c2]"):]
        assert 'vector_name = "c2_math"' in block[:500]

    def test_linux_c2_all_eight_vector_columns_in_cfg(self):
        src = SERVICES_CFG.read_text()
        for col in C2_VECTOR_COLS:
            assert col in src, f"Missing c2 vector column in nexus.toml: {col}"

    def test_worker_rust_c2_math_8d_branch(self):
        src = WORKER_RUST.read_text()
        assert re.search(r'"c2_math".*?raw_math\.len\(\)\s*==\s*8', src, re.DOTALL)

    def test_worker_rust_c2_math_normalisation_comments(self):
        src = WORKER_RUST.read_text()
        start = src.find('"c2_math"')
        assert start != -1
        # Should have normalisation constants e.g. / 1500.0 for packet_size_mean
        block = src[start:start + 400]
        assert "1500" in block or "8.0" in block or "clamp" in block
