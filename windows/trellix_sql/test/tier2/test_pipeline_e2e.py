"""
Full end-to-end test of _process_stream: SQL → UEBA → Parquet → Nexus POST.

The real reader._process_stream function is called with:
  - FakeConnection (SQLite-backed, no ODBC)
  - TrellixUEBAEngine (real IsolationForest on tmp SQLite)
  - _BatchSequence (real file-backed sequence counter)
  - requests.post mocked at the module level

Tests verify every integration seam:
  - Correct row counts per stream
  - Nexus HTTP call: URL, headers, payload format
  - Parquet payload matches TRELLIX_MATH_SCHEMA
  - HMAC header is 64-char hex
  - Sequence counter increments across calls
  - Watermark advances to the last AutoID transmitted
  - Empty batch: no HTTP call, no watermark write, returns 0
"""

from __future__ import annotations

import io
import unittest.mock as mock
import pyarrow.parquet as pq
import pytest
import reader
from schema import TRELLIX_MATH_SCHEMA

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mocked_post():
    """Return a context manager that patches requests.post and returns (cm, mock_obj)."""
    m = mock.MagicMock()
    m.return_value.status_code = 200
    m.return_value.raise_for_status = mock.Mock()
    return mock.patch("requests.post", m), m

def _capture_post():
    """Context manager that captures the POST data and returns (cm, captured[])."""
    captured = {}

    def _side_effect(url, data, headers, timeout):
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = headers
        r = mock.Mock()
        r.status_code = 200
        r.raise_for_status = mock.Mock()
        return r

    cm = mock.patch("requests.post", side_effect=_side_effect)
    return cm, captured

# ---------------------------------------------------------------------------
# ENS stream
# ---------------------------------------------------------------------------

class TestProcessStreamENS:
    def test_returns_three_row_count(self, fake_con, ueba_engine, batch_sequence):
        with mock.patch("requests.post") as mp:
            mp.return_value.status_code = 200
            mp.return_value.raise_for_status = mock.Mock()
            count = reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert count == 3

    def test_posts_to_nexus_exactly_once(self, fake_con, ueba_engine, batch_sequence):
        with mock.patch("requests.post") as mp:
            mp.return_value.status_code = 200
            mp.return_value.raise_for_status = mock.Mock()
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert mp.call_count == 1

    def test_post_url_matches_nexus_ingest_url(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert captured["url"] == reader.NEXUS_INGEST_URL

    def test_payload_is_valid_parquet(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        table = pq.read_table(io.BytesIO(captured["data"]))
        assert set(table.schema.names) == {f.name for f in TRELLIX_MATH_SCHEMA}

    def test_parquet_row_count_matches_ens_batch(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        table = pq.read_table(io.BytesIO(captured["data"]))
        assert len(table) == 3

    def test_stream_column_is_ens(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        table = pq.read_table(io.BytesIO(captured["data"]))
        assert set(table.column("stream").to_pylist()) == {"ens"}

    def test_all_required_headers_present(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        required = {
            "Authorization",
            "Content-Type",
            "X-Sensor-Type",
            "X-Sensor-Id",
            "X-Batch-Sequence",
            "X-Batch-Timestamp",
            "X-Batch-HMAC",
        }
        assert required.issubset(captured["headers"].keys())

    def test_content_type_is_parquet(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert captured["headers"]["Content-Type"] == "application/vnd.apache.parquet"

    def test_authorization_header_uses_bearer_token(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert captured["headers"]["Authorization"] == f"Bearer {reader.NEXUS_AUTH_TOKEN}"

    def test_hmac_header_is_64_hex_chars(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        hmac_val = captured["headers"]["X-Batch-HMAC"]
        assert len(hmac_val) == 64
        assert all(c in "0123456789abcdef" for c in hmac_val)

    def test_sensor_type_header_is_trellix_ens(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert captured["headers"]["X-Sensor-Type"] == reader.SENSOR_TYPE

    def test_sensor_id_header_matches_nexus_sensor_id(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert captured["headers"]["X-Sensor-Id"] == reader.NEXUS_SENSOR_ID

    def test_watermark_advances_to_last_ens_auto_id(self, fake_con, ueba_engine, batch_sequence):
        with mock.patch("requests.post") as mp:
            mp.return_value.status_code = 200
            mp.return_value.raise_for_status = mock.Mock()
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert reader._get_watermark(fake_con, "ens") == 5  # last ENS row is AutoID=5

    def test_sequence_starts_at_one(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert int(captured["headers"]["X-Batch-Sequence"]) == 1

# ---------------------------------------------------------------------------
# AppControl stream
# ---------------------------------------------------------------------------

class TestProcessStreamAppControl:
    def test_returns_two_row_count(self, fake_con, ueba_engine, batch_sequence):
        with mock.patch("requests.post") as mp:
            mp.return_value.status_code = 200
            mp.return_value.raise_for_status = mock.Mock()
            count = reader._process_stream(fake_con, ueba_engine, "appcontrol", batch_sequence)
        assert count == 2

    def test_stream_column_is_appcontrol(self, fake_con, ueba_engine, batch_sequence):
        cm, captured = _capture_post()
        with cm:
            reader._process_stream(fake_con, ueba_engine, "appcontrol", batch_sequence)
        table = pq.read_table(io.BytesIO(captured["data"]))
        assert set(table.column("stream").to_pylist()) == {"appcontrol"}

    def test_watermark_advances_to_last_ac_auto_id(self, fake_con, ueba_engine, batch_sequence):
        with mock.patch("requests.post") as mp:
            mp.return_value.status_code = 200
            mp.return_value.raise_for_status = mock.Mock()
            reader._process_stream(fake_con, ueba_engine, "appcontrol", batch_sequence)
        assert reader._get_watermark(fake_con, "appcontrol") == 4  # last AC row is AutoID=4

# ---------------------------------------------------------------------------
# Sequence counter across two stream calls
# ---------------------------------------------------------------------------

class TestBatchSequenceIncrement:
    def test_sequence_increments_across_ens_then_appcontrol(
        self, fake_con, ueba_engine, batch_sequence
    ):
        seq_values: list[int] = []

        def _side(url, data, headers, timeout):
            seq_values.append(int(headers["X-Batch-Sequence"]))
            r = mock.Mock()
            r.status_code = 200
            r.raise_for_status = mock.Mock()
            return r

        with mock.patch("requests.post", side_effect=_side):
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
            reader._process_stream(fake_con, ueba_engine, "appcontrol", batch_sequence)

        assert len(seq_values) == 2
        assert seq_values[1] == seq_values[0] + 1

# ---------------------------------------------------------------------------
# Empty-batch behaviour
# ---------------------------------------------------------------------------

class TestProcessStreamEmpty:
    def test_returns_zero_for_empty_db(self, empty_con, ueba_engine, batch_sequence):
        with mock.patch("requests.post") as mp:
            count = reader._process_stream(empty_con, ueba_engine, "ens", batch_sequence)
        assert count == 0
        mp.assert_not_called()

    def test_no_post_when_no_rows(self, empty_con, ueba_engine, batch_sequence):
        with mock.patch("requests.post") as mp:
            reader._process_stream(empty_con, ueba_engine, "ens", batch_sequence)
        mp.assert_not_called()

    def test_watermark_unchanged_for_empty_batch(self, empty_con, ueba_engine, batch_sequence):
        with mock.patch("requests.post"):
            reader._process_stream(empty_con, ueba_engine, "ens", batch_sequence)
        assert reader._get_watermark(empty_con, "ens") == 0

    def test_returns_zero_after_watermark_exhausts_rows(
        self, fake_con, ueba_engine, batch_sequence
    ):
        """After processing all ENS rows, a second cycle finds nothing."""
        with mock.patch("requests.post") as mp:
            mp.return_value.status_code = 200
            mp.return_value.raise_for_status = mock.Mock()
            reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
            count2 = reader._process_stream(fake_con, ueba_engine, "ens", batch_sequence)
        assert count2 == 0