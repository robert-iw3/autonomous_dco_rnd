"""
Prove _rows_to_parquet produces output that fully satisfies TRELLIX_MATH_SCHEMA.

Tests verify:
  - Output is non-empty bytes parseable by pyarrow
  - Column set exactly matches TRELLIX_MATH_SCHEMA field names
  - trellix_math column is list<float32> with exactly 6 elements
  - Scalar decomposition columns (severity_score, etc.) survive roundtrip
  - Null nullable fields survive roundtrip as None
  - Compression is ZSTD
  - auto_id and stream values are preserved
  - Vector element [0] is severity_score (6D vector layout contract)
  - Multi-row batch works without schema errors
"""

from __future__ import annotations

import datetime
import io
import math
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import reader
from schema import TRELLIX_MATH_SCHEMA, build_row

def _row(
    auto_id: int = 1,
    stream: str = "ens",
    severity_score: float = 0.6,
    threat_score: float = 1.0,
    action_score: float = 0.75,
    anomaly_score: float = 0.3,
    entropy_score: float = 0.5,
    frequency_score: float = 0.9,
    **overrides,
) -> dict:
    base = build_row(
        auto_id=auto_id,
        received_utc=datetime.datetime(2024, 1, 1, 10, 0, 0),
        agent_guid="GUID-TEST",
        source_host="TEST-HOST",
        threat_name="Test.Malware",
        threat_type="Trojan",
        threat_category="Malware",
        threat_severity=3,
        action_taken="Blocked",
        user_name="testuser",
        threat_file_name=r"C:\Users\test\Downloads\payload.exe",
        threat_source_url=None,
        process_name="explorer.exe",
        threat_event_id=1080,
        analyzer_name="VSE",
        analyzer_detection_method="Heuristic",
        anomaly_score=anomaly_score,
        entropy_score=entropy_score,
        frequency_score=frequency_score,
        batch_id="test-batch-001",
        stream=stream,
        severity_score=severity_score,
        threat_score=threat_score,
        action_score=action_score,
    )
    base.update(overrides)
    return base

class TestParquetValid:
    def test_output_is_non_empty_bytes(self):
        payload = reader._rows_to_parquet([_row()])
        assert isinstance(payload, bytes)
        assert len(payload) > 0

    def test_pyarrow_can_parse_output(self):
        payload = reader._rows_to_parquet([_row()])
        table = pq.read_table(io.BytesIO(payload))
        assert table is not None

    def test_row_count_matches_input(self):
        rows = [_row(auto_id=i) for i in range(1, 6)]
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet(rows)))
        assert len(table) == 5

class TestSchemaContract:
    def test_column_names_exactly_match_trellix_math_schema(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row()])))
        expected = {f.name for f in TRELLIX_MATH_SCHEMA}
        assert set(table.schema.names) == expected

    def test_no_extra_columns(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row()])))
        assert len(table.schema.names) == len(TRELLIX_MATH_SCHEMA)

    def test_auto_id_is_int64(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row()])))
        field = table.schema.field("auto_id")
        assert field.type == pa.int64()

    def test_trellix_math_is_list_of_float32(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row()])))
        field = table.schema.field("trellix_math")
        assert field.type == pa.list_(pa.float32())

    def test_stream_is_string(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row()])))
        assert table.schema.field("stream").type == pa.string()

class TestVectorLayout:
    def test_vector_has_exactly_six_elements(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row()])))
        vec = table.column("trellix_math").to_pylist()[0]
        assert len(vec) == 6

    def test_vector_element_zero_is_severity_score(self):
        r = _row(severity_score=0.8)
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([r])))
        vec = table.column("trellix_math").to_pylist()[0]
        assert math.isclose(vec[0], 0.8, abs_tol=1e-4)

    def test_vector_element_one_is_threat_score(self):
        r = _row(threat_score=1.0)
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([r])))
        vec = table.column("trellix_math").to_pylist()[0]
        assert math.isclose(vec[1], 1.0, abs_tol=1e-4)

    def test_vector_element_three_is_anomaly_score(self):
        r = _row(anomaly_score=0.42)
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([r])))
        vec = table.column("trellix_math").to_pylist()[0]
        assert math.isclose(vec[3], 0.42, abs_tol=1e-4)

    def test_scalar_scores_match_vector_elements(self):
        """Each scalar column must equal the corresponding vector element."""
        r = _row(
            severity_score=0.4,
            threat_score=0.95,
            action_score=0.75,
            anomaly_score=0.2,
            entropy_score=0.6,
            frequency_score=0.85,
        )
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([r])))
        vec = table.column("trellix_math").to_pylist()[0]
        for i, col in enumerate(
            ("severity_score", "threat_score", "action_score",
             "anomaly_score", "entropy_score", "frequency_score")
        ):
            scalar = table.column(col).to_pylist()[0]
            assert math.isclose(scalar, vec[i], abs_tol=1e-4), f"{col}: {scalar} != vec[{i}]={vec[i]}"

class TestColumnValues:
    def test_auto_id_round_trips(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row(auto_id=42)])))
        assert table.column("auto_id").to_pylist() == [42]

    def test_stream_column_preserved_ens(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row(stream="ens")])))
        assert table.column("stream").to_pylist() == ["ens"]

    def test_stream_column_preserved_appcontrol(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row(stream="appcontrol")])))
        assert table.column("stream").to_pylist() == ["appcontrol"]

    def test_null_threat_source_url_preserved(self):
        r = _row()
        r["threat_source_url"] = None
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([r])))
        assert table.column("threat_source_url").to_pylist() == [None]

    def test_file_name_is_basename_of_file_path(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row()])))
        assert table.column("file_name").to_pylist() == ["payload.exe"]

    def test_detection_name_maps_from_threat_name(self):
        table = pq.read_table(io.BytesIO(reader._rows_to_parquet([_row()])))
        assert table.column("detection_name").to_pylist() == ["Test.Malware"]

class TestCompression:
    def test_compression_is_zstd(self):
        meta = pq.read_metadata(io.BytesIO(reader._rows_to_parquet([_row()])))
        rg = meta.row_group(0)
        compressions = {rg.column(i).compression for i in range(rg.num_columns)}
        assert "ZSTD" in compressions