"""
Prove _fetch_batch SQL filter correctness against the SQLite-backed DB.

SAMPLE_EVENTS layout (from conftest):
  AutoID 1 — ThreatCategory=Malware,                    ThreatEventID=1080  → ENS
  AutoID 2 — ThreatCategory=NULL,                       ThreatEventID=1092  → ENS
  AutoID 3 — ThreatCategory=Solidcore,                  ThreatEventID=34001 → AppControl
  AutoID 4 — ThreatCategory=McAfee Application Control, ThreatEventID=34100 → AppControl
  AutoID 5 — ThreatCategory=Malware,                    ThreatEventID=1234  → ENS

ENS filter excludes: category IN (Solidcore, McAfee App Control, Trellix App Control)
                     OR event_id BETWEEN 34000 AND 34999
AppControl is the exact inverse.
"""

import reader

# ENS SELECT returns columns in this order (reader._FETCH_SQL):
#   0:AutoID  1:ReceivedUTC  2:DetectedUTC  3:AgentGUID  4:SourceHostName
#   5:ThreatName  6:ThreatType  7:ThreatCategory  8:ThreatSeverity  9:ActionTaken
#   10:UserName  11:ThreatFileName  12:ThreatSourceUrl  13:ProcessName
#   14:ThreatEventID  15:AnalyzerName  16:AnalyzerVersion  17:AnalyzerDetectionMethod

class TestENSFilter:
    def test_excludes_solidcore_category(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        cats = {r[7] for r in rows}
        assert "Solidcore" not in cats

    def test_excludes_mcafee_application_control(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        cats = {r[7] for r in rows}
        assert "McAfee Application Control" not in cats

    def test_excludes_trellix_application_control(self, fake_con, empty_db):
        from conftest import _INSERT_SQL
        import datetime
        empty_db.execute(
            _INSERT_SQL,
            (10,
             datetime.datetime(2024, 1, 1, 12, 0, 0), None,
             "GUID-X", "HOST-X",
             "AppCtrl:Trellix", "AppControl", "Trellix Application Control", 2, "Blocked",
             "user", None, None, "svc.exe",
             34200, "AppControl", "11.0", "AppControl"),
        )
        empty_db.commit()
        from _sqlite_db import FakeConnection
        con = FakeConnection(empty_db)
        rows = reader._fetch_batch(con, "ens", 0)
        cats = {r[7] for r in rows}
        assert "Trellix Application Control" not in cats

    def test_excludes_34xxx_event_ids(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        event_ids = [r[14] for r in rows if r[14] is not None]
        assert not any(34000 <= eid <= 34999 for eid in event_ids)

    def test_includes_regular_malware_row(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        auto_ids = {r[0] for r in rows}
        assert 1 in auto_ids

    def test_includes_null_category_row(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        auto_ids = {r[0] for r in rows}
        assert 2 in auto_ids  # ThreatCategory IS NULL

    def test_includes_ransomware_row(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        auto_ids = {r[0] for r in rows}
        assert 5 in auto_ids

    def test_returns_exactly_three_rows(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        assert len(rows) == 3

class TestAppControlFilter:
    def test_includes_solidcore_category(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 0)
        auto_ids = {r[0] for r in rows}
        assert 3 in auto_ids

    def test_includes_mcafee_application_control(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 0)
        auto_ids = {r[0] for r in rows}
        assert 4 in auto_ids

    def test_excludes_regular_malware(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 0)
        auto_ids = {r[0] for r in rows}
        assert 1 not in auto_ids
        assert 5 not in auto_ids

    def test_excludes_null_category_ens_row(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 0)
        auto_ids = {r[0] for r in rows}
        assert 2 not in auto_ids

    def test_all_event_ids_in_34xxx_range(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 0)
        event_ids = [r[14] for r in rows if r[14] is not None]
        assert all(34000 <= eid <= 34999 for eid in event_ids)

    def test_returns_exactly_two_rows(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 0)
        assert len(rows) == 2

class TestWatermarkRespect:
    def test_watermark_zero_returns_all_ens(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        assert len(rows) == 3

    def test_watermark_at_two_skips_auto_ids_one_and_two(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 2)
        auto_ids = {r[0] for r in rows}
        assert 1 not in auto_ids
        assert 2 not in auto_ids
        assert 5 in auto_ids

    def test_watermark_at_five_returns_empty(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 5)
        assert rows == []

    def test_watermark_beyond_max_returns_empty(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 9999)
        assert rows == []

    def test_appcontrol_watermark_respected(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 3)
        auto_ids = {r[0] for r in rows}
        assert 3 not in auto_ids
        assert 4 in auto_ids

class TestOrdering:
    def test_ens_rows_ordered_ascending_by_auto_id(self, fake_con):
        rows = reader._fetch_batch(fake_con, "ens", 0)
        ids = [r[0] for r in rows]
        assert ids == sorted(ids)

    def test_appcontrol_rows_ordered_ascending_by_auto_id(self, fake_con):
        rows = reader._fetch_batch(fake_con, "appcontrol", 0)
        ids = [r[0] for r in rows]
        assert ids == sorted(ids)

class TestBatchSizeLimit:
    def test_batch_size_one_returns_single_row(self, fake_con, monkeypatch):
        monkeypatch.setattr(reader, "BATCH_SIZE", 1)
        rows = reader._fetch_batch(fake_con, "ens", 0)
        assert len(rows) == 1

    def test_batch_size_two_caps_result(self, fake_con, monkeypatch):
        monkeypatch.setattr(reader, "BATCH_SIZE", 2)
        rows = reader._fetch_batch(fake_con, "ens", 0)
        assert len(rows) == 2

    def test_batch_size_large_returns_all(self, fake_con, monkeypatch):
        monkeypatch.setattr(reader, "BATCH_SIZE", 1000)
        rows = reader._fetch_batch(fake_con, "ens", 0)
        assert len(rows) == 3

    def test_first_row_is_lowest_auto_id_when_limited(self, fake_con, monkeypatch):
        monkeypatch.setattr(reader, "BATCH_SIZE", 1)
        rows = reader._fetch_batch(fake_con, "ens", 0)
        assert rows[0][0] == 1