"""
test_sensor_windows_c2.py -- Validation of the windows_xdr_dev C2Row pipeline.

Architecture:
  windows_xdr_dev (Rust) → C2Row struct (sensor_type="c2sensor") →
  c2_to_parquet() → Parquet (ZSTD) → X-Batch-HMAC → Nexus ingress

Key invariants:
  - C2Row has `process` field (NOT `Image`)
  - nexus.toml windows_c2 identifier_column = "Image" (different from C2Row.process)
  - worker_qdrant checks sysmon_event_id FIRST, then Image (sysmon wins on overlap)
  - deepsensor_math 4D handled separately (EdrRow path)
  - c2_math 8D: outbound_ratio, packet_size_mean, packet_size_std,
                interval, cv, entropy, cmd_entropy, score

Coverage:
  Source structure   -- windows_xdr_dev Cargo.toml, schema.rs, parquet.rs
  C2Row schema       -- process (NOT Image), destination, alert_reason, event_id
  Worker ordering    -- sysmon_event_id checked before Image (prevents misrouting)
  c2_math alignment  -- 8D vector columns in nexus.toml windows_c2 mapping
  Mock Parquet       -- C2Row fields, roundtrip, ZSTD
"""

import io
import re
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO         = Path(__file__).parent.parent.parent
ROOT         = REPO.parent
XDR_DIR      = ROOT / "windows" / "windows_xdr_dev"
TX_DIR       = XDR_DIR / "transmission"
SCHEMA_RS    = TX_DIR / "src" / "schema.rs"
PARQUET_RS   = TX_DIR / "src" / "parquet.rs"
SERVICES_CFG = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG    = REPO / "tests"    / "config" / "nexus.toml"
WORKER_RUST  = REPO / "services" / "worker_qdrant" / "src" / "main.rs"

C2_VECTOR_COLS = [
    "outbound_ratio", "packet_size_mean", "packet_size_std",
    "interval", "cv", "entropy", "cmd_entropy", "score",
]


# ── Source structure ──────────────────────────────────────────────────────────

class TestWindowsC2SourceStructure:

    def test_xdr_cargo_toml_exists(self):
        assert (XDR_DIR / "Cargo.toml").exists()

    def test_transmission_cargo_toml_exists(self):
        assert (TX_DIR / "Cargo.toml").exists()

    def test_schema_rs_exists(self):
        assert SCHEMA_RS.exists()

    def test_parquet_rs_exists(self):
        assert PARQUET_RS.exists()

    def test_worker_rs_exists(self):
        # transmission/src uses lib.rs + worker.rs pattern (no main.rs)
        assert (TX_DIR / "src" / "worker.rs").exists() or \
               (TX_DIR / "src" / "lib.rs").exists()

    def test_deployment_artifact_exists(self):
        # DeepXDR converged into a hybrid .NET 10 + Rust agent (readme.md):
        # the .NET Windows Service project lives nested under agent/ (XdrAgent.csproj),
        # not at XDR_DIR's top level -- glob non-recursively at top level for the
        # workspace Cargo.toml (Rust ML engine) and recursively for .csproj/.sln
        # (the .NET service), since both halves are real deployment artifacts here.
        has_docker = (XDR_DIR / "docker-compose.yaml").exists() or \
                     (XDR_DIR / "docker-compose.yml").exists() or \
                     (XDR_DIR / "Dockerfile").exists()
        has_dotnet = any(XDR_DIR.rglob("*.csproj")) or any(XDR_DIR.rglob("*.sln"))
        has_cargo = (XDR_DIR / "Cargo.toml").exists()
        assert has_docker or has_dotnet or has_cargo


# ── C2Row schema -- process NOT Image ────────────────────────────────────────

class TestC2RowSchema:

    def _src(self):
        return SCHEMA_RS.read_text()

    def test_c2row_struct_exists(self):
        assert "C2Row" in self._src()

    def test_c2row_has_process_field(self):
        src = self._src()
        assert "process" in src

    def test_c2row_sensor_type_is_c2sensor(self):
        src = self._src()
        assert "c2sensor" in src

    def test_c2row_has_destination_field(self):
        assert "destination" in self._src()

    def test_c2row_has_event_id(self):
        assert "event_id" in self._src()

    def test_c2row_has_alert_reason(self):
        assert "alert_reason" in self._src()

    def test_edr_row_has_sensor_type_deepsensor(self):
        assert "deepsensor" in self._src()


# ── parquet.rs -- C2Row serialization ─────────────────────────────────────────

class TestC2ParquetSerialization:

    def _src(self):
        return PARQUET_RS.read_text()

    def test_c2_to_parquet_function_exists(self):
        src = self._src()
        assert "c2_to_parquet" in src

    def test_c2_parquet_does_not_have_image_field(self):
        src = self._src()
        start = src.find("c2_to_parquet")
        if start == -1:
            pytest.skip("c2_to_parquet not found in parquet.rs")
        end = src.find("fn edr_to_parquet", start)
        c2_block = src[start:end] if end != -1 else src[start:start+800]
        assert '"Image"' not in c2_block, \
            "C2Row parquet schema must not have Image field (C2Row uses 'process')"

    def test_c2_parquet_has_process_field(self):
        src = self._src()
        start = src.find("c2_to_parquet")
        if start == -1:
            pytest.skip("c2_to_parquet not found in parquet.rs")
        end = src.find("fn edr_to_parquet", start)
        c2_block = src[start:end] if end != -1 else src[start:start+800]
        assert "process" in c2_block

    def test_edr_to_parquet_function_exists(self):
        assert "edr_to_parquet" in self._src()

    def test_edr_parquet_has_max_velocity(self):
        src = self._src()
        assert "max_velocity" in src

    def test_edr_parquet_has_avg_entropy(self):
        assert "avg_entropy" in self._src()


# ── Worker Qdrant ordering -- sysmon_event_id before Image ────────────────────

class TestWorkerQdrantRouting:

    def _src(self):
        return WORKER_RUST.read_text()

    def test_worker_checks_sysmon_event_id_before_image(self):
        """
        sysmon records carry both sysmon_event_id AND Image.
        worker_qdrant MUST check sysmon_event_id first to avoid routing sysmon
        records through the windows_c2 branch by mistake.
        """
        src = self._src()
        pos_sysmon = src.find("sysmon_event_id")
        pos_image  = src.find('"Image"')
        assert pos_sysmon != -1, "sysmon_event_id check missing from worker_qdrant"
        assert pos_image  != -1, "Image identifier check missing from worker_qdrant"
        assert pos_sysmon < pos_image, \
            "worker_qdrant must check sysmon_event_id BEFORE Image to prevent sysmon misrouting"

    def test_worker_has_c2_math_8d_branch(self):
        assert re.search(r'"c2_math".*?raw_math\.len\(\)\s*==\s*8', self._src(), re.DOTALL)

    def test_worker_has_windows_math_6d_branch(self):
        # worker_qdrant uses active_source_type == "sysmon_sensor" (not "windows_math")
        assert re.search(r'"sysmon_sensor".*?raw_math\.len\(\)\s*==\s*6', self._src(), re.DOTALL)

    def test_worker_has_deepsensor_math_4d_branch(self):
        src = self._src()
        assert re.search(r'"deepsensor_math".*?raw_math\.len\(\)\s*==\s*4', src, re.DOTALL)


# ── c2_math alignment in nexus.toml ──────────────────────────────────────────

class TestWindowsC2NexusConfig:

    def test_windows_c2_mapping_exists(self):
        assert "[schema_mappings.windows_c2]" in SERVICES_CFG.read_text()

    def test_windows_c2_vector_name_c2_math(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.windows_c2]"):]
        assert 'vector_name = "c2_math"' in block[:400]

    def test_windows_c2_identifier_column_is_image(self):
        """nexus.toml windows_c2 mapping uses 'Image' as identifier.
        Note: C2Row.process field is serialized differently; the mapping
        targets a specific ingestion variant where Image is available."""
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.windows_c2]"):]
        assert 'identifier_column = "Image"' in block[:400]

    def test_all_eight_c2_vector_columns_in_cfg(self):
        src = SERVICES_CFG.read_text()
        for col in C2_VECTOR_COLS:
            assert col in src, f"Missing c2_math vector column: {col}"

    def test_windows_c2_mapping_in_tests_cfg(self):
        assert "windows_c2" in TESTS_CFG.read_text()


# ── Mock Parquet -- C2Row fields ───────────────────────────────────────────────

def _build_c2row_schema() -> pa.Schema:
    """C2Row as emitted by c2_to_parquet() in parquet.rs."""
    return pa.schema([
        pa.field("sensor_id",        pa.string(),  nullable=False),
        pa.field("sensor_type",      pa.string(),  nullable=False),
        pa.field("timestamp",        pa.float64(), nullable=False),
        pa.field("event_id",         pa.string(),  nullable=False),
        pa.field("process",          pa.string(),  nullable=True),
        pa.field("destination",      pa.string(),  nullable=True),
        pa.field("alert_reason",     pa.string(),  nullable=True),
        # c2_math 8D
        pa.field("outbound_ratio",   pa.float64(), nullable=True),
        pa.field("packet_size_mean", pa.float64(), nullable=True),
        pa.field("packet_size_std",  pa.float64(), nullable=True),
        pa.field("interval",         pa.float64(), nullable=True),
        pa.field("cv",               pa.float64(), nullable=True),
        pa.field("entropy",          pa.float64(), nullable=True),
        pa.field("cmd_entropy",      pa.float64(), nullable=True),
        pa.field("score",            pa.float64(), nullable=True),
    ])


def _build_c2row_mock(i: int = 0) -> dict:
    return {
        "sensor_id":        "windows-xdr-dev-01",
        "sensor_type":      "c2sensor",
        "timestamp":        1748000000.0 + i,
        "event_id":         f"c2evt-{i:06d}",
        "process":          f"malware_{i}.exe",
        "destination":      f"203.0.113.{(i % 254) + 1}:4444",
        "alert_reason":     "C2_BEACON_DETECTED",
        "outbound_ratio":   min(1.0, 0.3 + i * 0.04),
        "packet_size_mean": 256.0 + i * 5,
        "packet_size_std":  30.0,
        "interval":         30.0 + i * 0.5,
        "cv":               0.05 + i * 0.001,
        "entropy":          4.2 + (i % 4) * 0.1,
        "cmd_entropy":      0.6,
        "score":            min(1.0, 0.5 + i * 0.04),
    }


class TestWindowsC2MockParquet:

    def test_schema_has_process_not_image(self):
        schema = _build_c2row_schema()
        assert "process" in schema.names
        assert "Image" not in schema.names

    def test_schema_has_all_c2_vector_columns(self):
        schema = _build_c2row_schema()
        for col in C2_VECTOR_COLS:
            assert col in schema.names

    def test_parquet_roundtrip(self):
        schema = _build_c2row_schema()
        rows   = [_build_c2row_mock(i) for i in range(15)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        t2 = pq.read_table(buf)
        assert t2.num_rows == 15

    def test_sensor_type_c2sensor(self):
        assert _build_c2row_mock(0)["sensor_type"] == "c2sensor"

    def test_outbound_ratio_bounded(self):
        for i in range(20):
            assert 0.0 <= _build_c2row_mock(i)["outbound_ratio"] <= 1.0
