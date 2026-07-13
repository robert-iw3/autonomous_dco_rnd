"""
test_sensor_macos.py -- Validation of the macOS sensor pipeline.

Architecture:
  macOS endpoint → macos_sensor → Parquet (ZSTD) →
  X-Batch-HMAC → Nexus ingress

Sensor type: macos_sensor
Vector: windows_math 6D (shared vector space with sysmon_sensor)
  [command_entropy, parent_child_score, integrity_score, anomaly_score,
   grant_access_score, driver_trust_score]
Identifier: plist_path

Key invariants:
  - Shares windows_math vector with sysmon_sensor
  - Identifier column: plist_path (macOS-specific, analogous to sysmon_event_id)
  - X-Batch-HMAC header (standard batch integrity pattern)

Coverage:
  Source structure   -- macos_sensor directory, Cargo.toml or requirements.txt
  nexus.toml         -- macos_sensor mapping, windows_math=6, plist_path identifier
  Mock Parquet       -- 6D vector + macOS-specific context fields, roundtrip
  Worker Qdrant      -- macos_sensor handled via windows_math 6D branch
"""

import io
import re
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO         = Path(__file__).parent.parent.parent
ROOT         = REPO.parent
MACOS_DIR    = ROOT / "macos" / "macos_sensor"
SERVICES_CFG = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG    = REPO / "tests"    / "config" / "nexus.toml"
WORKER_RUST  = REPO / "services" / "worker_qdrant" / "src" / "main.rs"

MACOS_VECTOR_COLS = [
    "command_entropy", "parent_child_score", "integrity_score",
    "anomaly_score", "grant_access_score", "driver_trust_score",
]


# ── Source structure ──────────────────────────────────────────────────────────

class TestMacOSSensorSourceStructure:

    def test_macos_sensor_dir_exists(self):
        # macos_sensor is a planned sensor; nexus.toml mapping exists as placeholder.
        # Directory created when macOS sensor development begins.
        pytest.skip("macos/macos_sensor not yet implemented -- placeholder nexus.toml mapping exists")

    def test_cargo_or_requirements_exists(self):
        pytest.skip("macos/macos_sensor not yet implemented")

    def test_dockerfile_or_service_file(self):
        pytest.skip("macos/macos_sensor not yet implemented")


# ── Nexus config alignment ────────────────────────────────────────────────────

class TestMacOSNexusConfig:

    def test_macos_sensor_mapping_exists(self):
        assert "[schema_mappings.macos_sensor]" in SERVICES_CFG.read_text()

    def test_macos_sensor_identifier_is_plist_path(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.macos_sensor]"):][:400]
        # TOML allows extra whitespace around '='; use regex for robustness
        assert re.search(r'identifier_column\s*=\s*"plist_path"', block)

    def test_macos_sensor_vector_name_windows_math(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.macos_sensor]"):][:400]
        assert re.search(r'vector_name\s*=\s*"windows_math"', block)

    def test_windows_math_6_in_services_cfg(self):
        src = SERVICES_CFG.read_text()
        assert re.search(r'windows_math\s*=\s*6', src)

    def test_all_six_vector_columns_in_cfg(self):
        src = SERVICES_CFG.read_text()
        for col in MACOS_VECTOR_COLS:
            assert col in src, f"Missing vector column in nexus.toml: {col}"

    def test_macos_sensor_in_tests_cfg(self):
        assert "macos_sensor" in TESTS_CFG.read_text()

    def test_worker_rust_windows_math_handles_macos(self):
        src = WORKER_RUST.read_text()
        # worker_qdrant branches on active_source_type == "macos_sensor" (not "windows_math")
        assert re.search(r'"macos_sensor".*?raw_math\.len\(\)\s*==\s*6', src, re.DOTALL)


# ── Mock Parquet -- macOS sensor fields ───────────────────────────────────────

def _build_macos_schema() -> pa.Schema:
    return pa.schema([
        pa.field("sensor_id",          pa.string(),  nullable=False),
        pa.field("sensor_type",        pa.string(),  nullable=False),
        pa.field("timestamp",          pa.float64(), nullable=False),
        pa.field("plist_path",         pa.string(),  nullable=False),
        # windows_math 6D vector (shared with sysmon)
        pa.field("command_entropy",    pa.float64(), nullable=True),
        pa.field("parent_child_score", pa.float64(), nullable=True),
        pa.field("integrity_score",    pa.float64(), nullable=True),
        pa.field("anomaly_score",      pa.float64(), nullable=True),
        pa.field("grant_access_score", pa.float64(), nullable=True),
        pa.field("driver_trust_score", pa.float64(), nullable=True),
        # macOS-specific context
        pa.field("process_name",       pa.string(),  nullable=True),
        pa.field("pid",                pa.int32(),   nullable=True),
        pa.field("uid",                pa.int32(),   nullable=True),
        pa.field("bundle_id",          pa.string(),  nullable=True),
        pa.field("team_id",            pa.string(),  nullable=True),
        pa.field("signing_id",         pa.string(),  nullable=True),
        pa.field("es_event_type",      pa.string(),  nullable=True),
        pa.field("file_path",          pa.string(),  nullable=True),
        pa.field("mitre_tactic",       pa.string(),  nullable=True),
    ])


def _build_macos_row(i: int = 0) -> dict:
    return {
        "sensor_id":          "macos-sensor-01",
        "sensor_type":        "macos_sensor",
        "timestamp":          1748000000.0 + i,
        "plist_path":         f"/Library/LaunchDaemons/com.evil{i}.daemon.plist",
        "command_entropy":    min(1.0, 0.4 + i * 0.03),
        "parent_child_score": min(1.0, 0.1 + i * 0.05),
        "integrity_score":    min(1.0, 0.5 + i * 0.02),
        "anomaly_score":      min(1.0, 0.2 + i * 0.04),
        "grant_access_score": 0.0,
        "driver_trust_score": min(1.0, 0.1 * (i % 4)),
        "process_name":       f"process_{i}",
        "pid":                1000 + i,
        "uid":                501,
        "bundle_id":          f"com.example.app{i}",
        "team_id":            "ABCDE12345",
        "signing_id":         f"com.example.app{i}:ABCDE12345",
        "es_event_type":      "ES_EVENT_TYPE_NOTIFY_EXEC",
        "file_path":          f"/usr/local/bin/malware_{i}",
        "mitre_tactic":       "Persistence",
    }


class TestMacOSMockParquet:

    def test_schema_has_plist_path_identifier(self):
        assert "plist_path" in _build_macos_schema().names

    def test_schema_has_all_six_vector_columns(self):
        schema = _build_macos_schema()
        for col in MACOS_VECTOR_COLS:
            assert col in schema.names

    def test_parquet_roundtrip(self):
        schema = _build_macos_schema()
        rows   = [_build_macos_row(i) for i in range(15)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        t2 = pq.read_table(buf)
        assert t2.num_rows == 15

    def test_all_six_vector_scores_in_unit_interval(self):
        for i in range(20):
            row = _build_macos_row(i)
            for col in MACOS_VECTOR_COLS:
                v = row[col]
                assert 0.0 <= v <= 1.0, f"Row {i} {col}={v} out of [0,1]"

    def test_sensor_type_macos_sensor(self):
        assert _build_macos_row(0)["sensor_type"] == "macos_sensor"

    def test_plist_path_is_launchdaemon_format(self):
        row = _build_macos_row(0)
        assert row["plist_path"].startswith("/Library/")
