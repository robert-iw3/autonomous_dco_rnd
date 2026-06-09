"""
Prove watermark read/write correctness against the SQLite-backed FakeConnection.

_get_watermark and _update_watermark are the persistence boundary between
transmission cycles. These tests verify that:
  - Missing watermark row → returns 0 (safe default for first run)
  - After write, read returns the same value
  - Multiple writes: newest AutoID wins (ORDER BY WatermarkID DESC)
  - ENS and appcontrol streams are tracked independently
  - Written rows contain correct Status / RowsTransmitted / BatchID values
"""

import reader

class TestGetWatermark:
    def test_returns_zero_when_no_rows(self, empty_con):
        assert reader._get_watermark(empty_con, "ens") == 0

    def test_returns_zero_for_unknown_stream(self, fake_con):
        assert reader._get_watermark(fake_con, "never_written") == 0

    def test_reads_back_value_after_single_write(self, empty_con):
        reader._update_watermark(empty_con, "ens", 500, 10, "batch-001")
        assert reader._get_watermark(empty_con, "ens") == 500

    def test_returns_latest_not_oldest(self, empty_con):
        reader._update_watermark(empty_con, "ens", 100, 5, "b1")
        reader._update_watermark(empty_con, "ens", 200, 8, "b2")
        reader._update_watermark(empty_con, "ens", 300, 3, "b3")
        assert reader._get_watermark(empty_con, "ens") == 300

    def test_streams_are_independent(self, empty_con):
        reader._update_watermark(empty_con, "ens", 1000, 20, "b-ens")
        reader._update_watermark(empty_con, "appcontrol", 500, 10, "b-ac")
        assert reader._get_watermark(empty_con, "ens") == 1000
        assert reader._get_watermark(empty_con, "appcontrol") == 500

    def test_appcontrol_does_not_shadow_ens(self, empty_con):
        reader._update_watermark(empty_con, "appcontrol", 9999, 1, "x")
        assert reader._get_watermark(empty_con, "ens") == 0

class TestUpdateWatermark:
    def test_status_is_success(self, empty_con, empty_db):
        reader._update_watermark(empty_con, "ens", 99, 7, "batch-x")
        row = empty_db.execute(
            "SELECT Status FROM TransmitWatermark WHERE StreamName = 'ens'"
        ).fetchone()
        assert row[0] == "Success"

    def test_rows_transmitted_recorded(self, empty_con, empty_db):
        reader._update_watermark(empty_con, "ens", 99, 42, "batch-x")
        row = empty_db.execute(
            "SELECT RowsTransmitted FROM TransmitWatermark WHERE StreamName = 'ens'"
        ).fetchone()
        assert row[0] == 42

    def test_batch_id_recorded(self, empty_con, empty_db):
        reader._update_watermark(empty_con, "ens", 99, 1, "my-batch-uuid")
        row = empty_db.execute(
            "SELECT BatchID FROM TransmitWatermark WHERE StreamName = 'ens'"
        ).fetchone()
        assert row[0] == "my-batch-uuid"

    def test_last_transmit_time_is_set(self, empty_con, empty_db):
        reader._update_watermark(empty_con, "ens", 99, 1, "batch-x")
        row = empty_db.execute(
            "SELECT LastTransmitTime FROM TransmitWatermark WHERE StreamName = 'ens'"
        ).fetchone()
        assert row[0] is not None

    def test_last_auto_id_recorded(self, empty_con, empty_db):
        reader._update_watermark(empty_con, "ens", 7654, 1, "b")
        row = empty_db.execute(
            "SELECT LastTransmittedAutoID FROM TransmitWatermark"
        ).fetchone()
        assert row[0] == 7654

    def test_multiple_writes_append_rows(self, empty_con, empty_db):
        reader._update_watermark(empty_con, "ens", 10, 2, "b1")
        reader._update_watermark(empty_con, "ens", 20, 3, "b2")
        count = empty_db.execute(
            "SELECT COUNT(*) FROM TransmitWatermark WHERE StreamName = 'ens'"
        ).fetchone()[0]
        assert count == 2