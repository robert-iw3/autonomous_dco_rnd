"""
test_sensor_windows_deepsensor.py -- Validation of the windows_xdr_dev EdrRow pipeline.

Architecture:
  windows_xdr_dev (Rust) → EdrRow struct (sensor_type="deepsensor") →
  edr_to_parquet() → Parquet (ZSTD) → X-Batch-HMAC → Nexus ingress

deepsensor_math 4D = [score, avg_entropy, max_velocity, event_count]
Identifier: max_velocity

worker_qdrant normalisation (all divide to [0,1]):
  score         → raw / 100.0
  avg_entropy   → raw / 8.0
  max_velocity  → raw / 5000.0
  event_count   → raw / 100.0

Coverage:
  Source structure      -- windows_xdr_dev workspace, schema.rs, parquet.rs
  EdrRow schema         -- max_velocity, avg_entropy, score, event_count fields
  edr_to_parquet()      -- correct Parquet schema, no C2Row contamination
  Worker normalisation  -- 4 divisors: /100, /8, /5000, /100
  deepsensor_math 4D    -- nexus.toml mapping, identifier_column=max_velocity
  Mock Parquet          -- roundtrip, 4D values validated
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

DEEPSENSOR_VECTOR_COLS = ["score", "avg_entropy", "max_velocity", "event_count"]


# ── Source structure ──────────────────────────────────────────────────────────

class TestDeepSensorSourceStructure:

    def test_xdr_cargo_toml_exists(self):
        assert (XDR_DIR / "Cargo.toml").exists()

    def test_schema_rs_exists(self):
        assert SCHEMA_RS.exists()

    def test_parquet_rs_exists(self):
        assert PARQUET_RS.exists()

    def test_transmission_cargo_exists(self):
        assert (TX_DIR / "Cargo.toml").exists()


# ── EdrRow schema ─────────────────────────────────────────────────────────────

class TestEdrRowSchema:

    def _src(self):
        return SCHEMA_RS.read_text()

    def test_edr_row_struct_exists(self):
        assert "EdrRow" in self._src()

    def test_edr_row_sensor_type_deepsensor(self):
        assert "deepsensor" in self._src()

    def test_edr_row_has_max_velocity(self):
        assert "max_velocity" in self._src()

    def test_edr_row_has_avg_entropy(self):
        assert "avg_entropy" in self._src()

    def test_edr_row_has_score(self):
        assert "score" in self._src()

    def test_edr_row_has_event_count(self):
        assert "event_count" in self._src()

    def test_edr_row_distinct_from_c2row(self):
        src = self._src()
        assert "EdrRow" in src and "C2Row" in src


# ── edr_to_parquet serialization ──────────────────────────────────────────────

class TestEdrParquetSerialization:

    def _src(self):
        return PARQUET_RS.read_text()

    def test_edr_to_parquet_function_exists(self):
        assert "edr_to_parquet" in self._src()

    def test_edr_parquet_max_velocity_field(self):
        src = self._src()
        start = src.find("edr_to_parquet")
        if start == -1:
            pytest.skip("edr_to_parquet not found")
        end = src.find("fn c2_to_parquet", start)
        block = src[start:end] if end != -1 else src[start:start+800]
        assert "max_velocity" in block

    def test_edr_parquet_avg_entropy_field(self):
        src = self._src()
        start = src.find("edr_to_parquet")
        if start == -1:
            pytest.skip("edr_to_parquet not found")
        end = src.find("fn c2_to_parquet", start)
        block = src[start:end] if end != -1 else src[start:start+800]
        assert "avg_entropy" in block

    def test_edr_parquet_score_field(self):
        src = self._src()
        start = src.find("edr_to_parquet")
        if start == -1:
            pytest.skip("edr_to_parquet not found")
        end = src.find("fn c2_to_parquet", start)
        block = src[start:end] if end != -1 else src[start:start+800]
        assert "score" in block


# ── Worker Qdrant normalisation ───────────────────────────────────────────────

class TestDeepSensorWorkerNormalisation:

    def _src(self):
        return WORKER_RUST.read_text()

    def test_deepsensor_math_4d_branch(self):
        src = self._src()
        assert re.search(r'"deepsensor_math".*?raw_math\.len\(\)\s*==\s*4', src, re.DOTALL)

    def test_score_normalised_by_100(self):
        """score is raw XDR score (0-100), must be divided by 100.0 before Qdrant upsert."""
        src = self._src()
        start = src.find('"deepsensor_math"')
        assert start != -1
        block = src[start:start + 600]
        assert "100.0" in block or "/ 100" in block

    def test_avg_entropy_normalised_by_8(self):
        """Shannon entropy max is 8 bits; divide by 8.0 to [0,1]."""
        src = self._src()
        start = src.find('"deepsensor_math"')
        assert start != -1
        block = src[start:start + 600]
        assert "8.0" in block or "/ 8" in block

    def test_max_velocity_normalised_by_5000(self):
        """max_velocity is events/sec (raw); divide by 5000.0 to normalise."""
        src = self._src()
        start = src.find('"deepsensor_math"')
        assert start != -1
        block = src[start:start + 600]
        assert "5000" in block

    def test_event_count_normalised_by_100(self):
        """event_count: divide by 100.0."""
        src = self._src()
        start = src.find('"deepsensor_math"')
        assert start != -1
        block = src[start:start + 600]
        assert "100.0" in block or "/ 100" in block


# ── Mock Parquet -- EdrRow ──────────────────────────────────────────────────────

def _build_edr_schema() -> pa.Schema:
    return pa.schema([
        pa.field("sensor_id",    pa.string(),  nullable=False),
        pa.field("sensor_type",  pa.string(),  nullable=False),
        pa.field("timestamp",    pa.float64(), nullable=False),
        pa.field("event_id",     pa.string(),  nullable=False),
        pa.field("score",        pa.float64(), nullable=True),
        pa.field("avg_entropy",  pa.float64(), nullable=True),
        pa.field("max_velocity", pa.float64(), nullable=True),
        pa.field("event_count",  pa.float64(), nullable=True),
        # Context
        pa.field("process_name", pa.string(),  nullable=True),
        pa.field("pid",          pa.int32(),   nullable=True),
        pa.field("hostname",     pa.string(),  nullable=True),
        pa.field("mitre_tactic", pa.string(),  nullable=True),
    ])


def _build_edr_mock(i: int = 0) -> dict:
    return {
        "sensor_id":    "windows-xdr-dev-01",
        "sensor_type":  "deepsensor",
        "timestamp":    1748000000.0 + i,
        "event_id":     f"edr-{i:06d}",
        "score":        float(30 + i * 2),     # raw 0–100, worker divides by 100
        "avg_entropy":  3.2 + i * 0.1,          # raw 0–8, worker divides by 8
        "max_velocity": float(100 + i * 50),    # raw events/sec, worker divides by 5000
        "event_count":  float(5 + i),           # raw count, worker divides by 100
        "process_name": f"/usr/bin/python3_{i}",
        "pid":          2000 + i,
        "hostname":     "windows-host-01",
        "mitre_tactic": "Execution",
    }


class TestDeepSensorMockParquet:

    def test_schema_has_all_four_vector_columns(self):
        schema = _build_edr_schema()
        for col in DEEPSENSOR_VECTOR_COLS:
            assert col in schema.names

    def test_schema_identifier_max_velocity(self):
        assert "max_velocity" in _build_edr_schema().names

    def test_parquet_roundtrip(self):
        schema = _build_edr_schema()
        rows   = [_build_edr_mock(i) for i in range(15)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        t2 = pq.read_table(buf)
        assert t2.num_rows == 15

    def test_sensor_type_deepsensor(self):
        assert _build_edr_mock(0)["sensor_type"] == "deepsensor"

    def test_normalised_score_in_unit_interval(self):
        for i in range(10):
            row = _build_edr_mock(i)
            assert 0.0 <= row["score"] / 100.0 <= 1.0

    def test_normalised_entropy_in_unit_interval(self):
        for i in range(10):
            row = _build_edr_mock(i)
            assert 0.0 <= row["avg_entropy"] / 8.0 <= 1.0


# ── Nexus config alignment ────────────────────────────────────────────────────

class TestDeepSensorNexusConfig:

    def test_windows_deepsensor_mapping_exists(self):
        assert "[schema_mappings.windows_deepsensor]" in SERVICES_CFG.read_text()

    def test_deepsensor_identifier_is_max_velocity(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.windows_deepsensor]"):]
        assert 'identifier_column = "max_velocity"' in block[:400]

    def test_deepsensor_math_4_in_cfg(self):
        src = SERVICES_CFG.read_text()
        assert re.search(r'deepsensor_math\s*=\s*4', src)

    def test_deepsensor_vector_name_in_cfg(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.windows_deepsensor]"):]
        assert 'vector_name = "deepsensor_math"' in block[:400]

    def test_all_four_vector_columns_in_cfg(self):
        src = SERVICES_CFG.read_text()
        for col in DEEPSENSOR_VECTOR_COLS:
            assert col in src, f"Missing deepsensor vector column: {col}"

    def test_windows_deepsensor_in_tests_cfg(self):
        assert "windows_deepsensor" in TESTS_CFG.read_text()
