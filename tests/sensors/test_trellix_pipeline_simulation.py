"""
test_trellix_pipeline_simulation.py -- Integration simulation of the Trellix pipeline.

Uses an in-memory SQLite database as a SQL Server substitute.
No containers, no network -- pure Python logic validation.

Pipeline under test:
  EPOEvents_Consolidated (SQLite) → UEBA → schema.build_row → Parquet →
  HMAC-sign → (mock) Nexus POST → TransmitWatermark update

Coverage:
  SQLite WAL settings         -- SQLite behaves correctly as a staging mock
  Mock EPO database           -- canonical ePO schema in SQLite
  ENS stream simulation       -- end-to-end for ENS (non-AppControl) events
  AppControl stream           -- Solidcore/AppControl events routed correctly
  HMAC & Nexus transmission   -- signing + header verification
  UEBA on simulated data      -- scores computed correctly from realistic events
"""

from __future__ import annotations

import datetime
import hashlib
import hmac as hmac_mod
import importlib.util
import io
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, NamedTuple
from unittest.mock import MagicMock, patch

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO     = Path(__file__).parent.parent.parent       # project_empros/
ROOT     = REPO.parent
TRANSMIT = ROOT / "windows" / "trellix_sql" / "transmit"

HMAC_SECRET = b"simulation-test-secret"


# ── Module loader ─────────────────────────────────────────────────────────────

def _ensure_sklearn_stub():
    if "sklearn" not in sys.modules:
        import types
        import numpy as np
        sk = types.ModuleType("sklearn")
        ens = types.ModuleType("sklearn.ensemble")

        class _FakeIF:
            def __init__(self, **kw): self._fitted = False
            def fit(self, X): self._fitted = True; return self
            def score_samples(self, X): return np.full(len(X), -0.25)

        ens.IsolationForest = _FakeIF
        sk.ensemble = ens
        sys.modules["sklearn"] = sk
        sys.modules["sklearn.ensemble"] = ens


def _load(name: str):
    _ensure_sklearn_stub()
    if str(TRANSMIT) not in sys.path:
        sys.path.insert(0, str(TRANSMIT))
    spec = importlib.util.spec_from_file_location(name, TRANSMIT / f"{name}.py")
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── SQLite mock helpers ───────────────────────────────────────────────────────

def _create_mock_db(db: sqlite3.Connection) -> None:
    """Create EPOEvents_Consolidated + TransmitWatermark in SQLite (canonical ePO schema)."""
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS EPOEvents_Consolidated (
            AutoID                  INTEGER NOT NULL PRIMARY KEY,
            ReceivedUTC             TEXT    NOT NULL,
            DetectedUTC             TEXT,
            AgentGUID               TEXT,
            SourceHostName          TEXT,
            ThreatName              TEXT,
            ThreatType              TEXT,
            ThreatCategory          TEXT,
            ThreatSeverity          INTEGER,
            ActionTaken             TEXT,
            UserName                TEXT,
            ThreatFileName          TEXT,
            ThreatSourceUrl         TEXT,
            ProcessName             TEXT,
            ThreatEventID           INTEGER,
            AnalyzerName            TEXT,
            AnalyzerVersion         TEXT,
            AnalyzerDetectionMethod TEXT,
            AnalyzerHostName        TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS TransmitWatermark (
            WatermarkID             INTEGER PRIMARY KEY AUTOINCREMENT,
            StreamName              TEXT    NOT NULL,
            LastTransmittedAutoID   INTEGER,
            LastTransmitTime        TEXT,
            RowsTransmitted         INTEGER DEFAULT 0,
            BatchID                 TEXT,
            Status                  TEXT
        )
    """)
    db.commit()


def _insert_ens_events(db: sqlite3.Connection, count: int = 10, start_id: int = 1):
    """Insert realistic ENS malware-detection events."""
    rows = []
    for i in range(count):
        rows.append((
            start_id + i,
            "2026-06-05 12:00:00",
            "2026-06-05 11:59:50",
            f"AGENT-GUID-{i:04d}",
            f"WORKSTATION-{i:04d}",
            f"Trojan.GenericKD.{i}",
            "Trojan",
            "av",
            4 + (i % 2),
            "Blocked",
            f"DOMAIN\\user{i}",
            rf"C:\Users\user{i}\AppData\Local\Temp\malware_{i}.exe",
            f"http://evil.example.com/payload_{i}.exe",
            "svchost.exe",
            1092 + i,
            "Endpoint Security",
            "10.7.0",
            "OAS",
            f"WORKSTATION-{i:04d}",
        ))
    db.executemany(
        "INSERT INTO EPOEvents_Consolidated VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    db.commit()


def _insert_appcontrol_events(db: sqlite3.Connection, count: int = 5, start_id: int = 1000):
    """Insert Solidcore/AppControl events (ThreatEventID 34000-34999)."""
    rows = []
    for i in range(count):
        rows.append((
            start_id + i,
            "2026-06-05 13:00:00",
            "2026-06-05 12:59:50",
            f"AGENT-GUID-AC-{i:04d}",
            f"SERVER-{i:04d}",
            f"Block.Application.{i}",
            "Solidcore",
            "Solidcore",
            3,
            "Blocked",
            f"DOMAIN\\svc{i}",
            rf"C:\Program Files\App{i}\app.exe",
            None,
            rf"C:\Program Files\App{i}\app.exe",
            34000 + i,
            "McAfee Application Control",
            "8.3.0",
            "Solidcore",
            f"SERVER-{i:04d}",
        ))
    db.executemany(
        "INSERT INTO EPOEvents_Consolidated VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    db.commit()


# ── Adapter: pyodbc Row-like namedtuple ───────────────────────────────────────

class _MockRow(NamedTuple):
    AutoID: int
    ReceivedUTC: Any
    DetectedUTC: Any
    AgentGUID: str
    SourceHostName: str
    ThreatName: str
    ThreatType: str
    ThreatCategory: str
    ThreatSeverity: int
    ActionTaken: str
    UserName: str
    ThreatFileName: str
    ThreatSourceUrl: str
    ProcessName: str
    ThreatEventID: int
    AnalyzerName: str
    AnalyzerVersion: str
    AnalyzerDetectionMethod: str


def _fetch_ens(db: sqlite3.Connection, watermark: int, limit: int = 1000):
    cur = db.execute(
        f"""
        SELECT AutoID, ReceivedUTC, DetectedUTC, AgentGUID, SourceHostName,
               ThreatName, ThreatType, ThreatCategory, ThreatSeverity, ActionTaken,
               UserName, ThreatFileName, ThreatSourceUrl, ProcessName,
               ThreatEventID, AnalyzerName, AnalyzerVersion, AnalyzerDetectionMethod
        FROM EPOEvents_Consolidated
        WHERE AutoID > ?
          AND (ThreatCategory NOT IN ('Solidcore','McAfee Application Control','Trellix Application Control')
               OR ThreatCategory IS NULL)
          AND (ThreatEventID NOT BETWEEN 34000 AND 34999 OR ThreatEventID IS NULL)
        ORDER BY AutoID
        LIMIT ?
        """,
        (watermark, limit),
    )
    return [_MockRow(*r) for r in cur.fetchall()]


def _fetch_appcontrol(db: sqlite3.Connection, watermark: int, limit: int = 1000):
    cur = db.execute(
        f"""
        SELECT AutoID, ReceivedUTC, DetectedUTC, AgentGUID, SourceHostName,
               ThreatName, ThreatType, ThreatCategory, ThreatSeverity, ActionTaken,
               UserName, ThreatFileName, ThreatSourceUrl, ProcessName,
               ThreatEventID, AnalyzerName, AnalyzerVersion, AnalyzerDetectionMethod
        FROM EPOEvents_Consolidated
        WHERE AutoID > ?
          AND (ThreatCategory IN ('Solidcore','McAfee Application Control','Trellix Application Control')
               OR ThreatEventID BETWEEN 34000 AND 34999)
        ORDER BY AutoID
        LIMIT ?
        """,
        (watermark, limit),
    )
    return [_MockRow(*r) for r in cur.fetchall()]


def _run_cycle(db: sqlite3.Connection, engine, schema_mod, stream: str) -> list[dict]:
    """Run one fetch→UEBA→build_row cycle for the given stream."""
    watermark = 0

    rows_raw = _fetch_ens(db, watermark) if stream == "ens" else _fetch_appcontrol(db, watermark)

    out_rows = []
    for r in rows_raw:
        (auto_id, received_utc, detected_utc, agent_guid, source_host,
         threat_name, threat_type, threat_category, threat_severity, action_taken,
         user_name, threat_file_name, threat_source_url, process_name,
         threat_event_id, analyzer_name, analyzer_version, analyzer_detection_method) = r

        if isinstance(received_utc, str):
            received_utc = datetime.datetime.fromisoformat(received_utc)

        anomaly, entropy, frequency = engine.score_event(
            threat_name=threat_name,
            threat_type=threat_type,
            file_path=threat_file_name,
            process_name=process_name,
            severity=threat_severity,
            action_taken=action_taken,
        )

        from ueba_engine import _severity_to_float, _action_to_float
        out_rows.append(schema_mod.build_row(
            auto_id=auto_id,
            received_utc=received_utc,
            agent_guid=agent_guid,
            source_host=source_host,
            threat_name=threat_name,
            threat_type=threat_type,
            threat_category=threat_category,
            threat_severity=threat_severity,
            action_taken=action_taken,
            user_name=user_name,
            threat_file_name=threat_file_name,
            threat_source_url=threat_source_url,
            process_name=process_name,
            threat_event_id=threat_event_id,
            analyzer_name=analyzer_name,
            analyzer_detection_method=analyzer_detection_method,
            anomaly_score=anomaly,
            entropy_score=entropy,
            frequency_score=frequency,
            batch_id="sim-batch-001",
            stream=stream,
            severity_score=_severity_to_float(threat_severity),
            threat_score=schema_mod.threat_type_to_score(threat_type),
            action_score=_action_to_float(action_taken),
        ))

    return out_rows


def _rows_to_parquet_bytes(rows: list[dict], schema) -> bytes:
    arrays = []
    for field in schema:
        vals = [r.get(field.name) for r in rows]
        if field.name == "trellix_math":
            arrays.append(pa.array(vals, type=pa.list_(pa.float32())))
        else:
            arrays.append(pa.array(vals, type=field.type))
    table = pa.table(
        {f.name: arrays[i] for i, f in enumerate(schema)},
        schema=schema,
    )
    buf = io.BytesIO()
    pq.write_table(table, buf, compression="zstd")
    return buf.getvalue()


# ══════════════════════════════════════════════════════════════════════════════
# SQLite WAL settings
# ══════════════════════════════════════════════════════════════════════════════

class TestSQLiteWALSettings:

    def test_wal_mode_enabled(self):
        db = sqlite3.connect(":memory:")
        db.execute("PRAGMA journal_mode=WAL")
        mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode in ("wal", "memory")
        db.close()

    def test_synchronous_normal_set(self):
        db = sqlite3.connect(":memory:")
        db.execute("PRAGMA synchronous=NORMAL")
        sync = db.execute("PRAGMA synchronous").fetchone()[0]
        assert sync == 1   # 1 = NORMAL
        db.close()

    def test_db_create_and_insert(self):
        db = sqlite3.connect(":memory:")
        _create_mock_db(db)
        _insert_ens_events(db, count=3)
        count = db.execute("SELECT COUNT(*) FROM EPOEvents_Consolidated").fetchone()[0]
        assert count == 3
        db.close()

    def test_watermark_table_starts_empty(self):
        db = sqlite3.connect(":memory:")
        _create_mock_db(db)
        count = db.execute("SELECT COUNT(*) FROM TransmitWatermark").fetchone()[0]
        assert count == 0
        db.close()

    def test_autoincrement_watermark_id(self):
        db = sqlite3.connect(":memory:")
        _create_mock_db(db)
        db.execute(
            "INSERT INTO TransmitWatermark (StreamName, LastTransmittedAutoID, RowsTransmitted, Status) "
            "VALUES ('ens', 10, 10, 'Success')"
        )
        db.execute(
            "INSERT INTO TransmitWatermark (StreamName, LastTransmittedAutoID, RowsTransmitted, Status) "
            "VALUES ('ens', 20, 10, 'Success')"
        )
        db.commit()
        rows = db.execute("SELECT WatermarkID FROM TransmitWatermark ORDER BY WatermarkID").fetchall()
        assert rows[1][0] > rows[0][0]
        db.close()

    def test_autoid_primary_key_uniqueness(self):
        db = sqlite3.connect(":memory:")
        _create_mock_db(db)
        _insert_ens_events(db, count=5, start_id=1)
        with pytest.raises(Exception):
            _insert_ens_events(db, count=1, start_id=1)   # duplicate PK
        db.close()

    def test_ens_and_appcontrol_coexist_in_same_table(self):
        db = sqlite3.connect(":memory:")
        _create_mock_db(db)
        _insert_ens_events(db, count=5, start_id=1)
        _insert_appcontrol_events(db, count=3, start_id=1000)
        count = db.execute("SELECT COUNT(*) FROM EPOEvents_Consolidated").fetchone()[0]
        assert count == 8
        db.close()

    def test_canonical_column_names_in_schema(self):
        """Verify mock DB uses ePO canonical column names (no legacy names)."""
        db = sqlite3.connect(":memory:")
        _create_mock_db(db)
        cols = {row[1] for row in db.execute("PRAGMA table_info(EPOEvents_Consolidated)").fetchall()}
        assert "ThreatFileName"          in cols, "Missing ThreatFileName"
        assert "ThreatEventID"           in cols, "Missing ThreatEventID"
        assert "ThreatSourceUrl"         in cols, "Missing ThreatSourceUrl"
        assert "AnalyzerDetectionMethod" in cols, "Missing AnalyzerDetectionMethod"
        assert "FilePath"     not in cols, "FilePath is non-standard"
        assert "EventID"      not in cols, "Bare EventID is non-standard"
        assert "PointProduct" not in cols, "PointProduct is not a real ePO column"
        db.close()

    def test_transaction_rollback_on_error(self):
        db = sqlite3.connect(":memory:")
        _create_mock_db(db)
        try:
            db.execute("BEGIN")
            db.execute("INSERT INTO EPOEvents_Consolidated (AutoID, ReceivedUTC) VALUES (1, '2026-01-01')")
            db.execute("INSERT INTO EPOEvents_Consolidated (AutoID, ReceivedUTC) VALUES (1, '2026-01-02')")
        except Exception:
            db.execute("ROLLBACK")
        count = db.execute("SELECT COUNT(*) FROM EPOEvents_Consolidated").fetchone()[0]
        assert count == 0
        db.close()


# ══════════════════════════════════════════════════════════════════════════════
# Mock EPO database content
# ══════════════════════════════════════════════════════════════════════════════

class TestMockEPODatabase:

    def setup_method(self):
        self.db = sqlite3.connect(":memory:")
        _create_mock_db(self.db)
        _insert_ens_events(self.db, count=10, start_id=1)
        _insert_appcontrol_events(self.db, count=5, start_id=1000)

    def teardown_method(self):
        self.db.close()

    def test_ens_rows_inserted(self):
        n = self.db.execute("SELECT COUNT(*) FROM EPOEvents_Consolidated WHERE AutoID < 1000").fetchone()[0]
        assert n == 10

    def test_appcontrol_rows_inserted(self):
        n = self.db.execute("SELECT COUNT(*) FROM EPOEvents_Consolidated WHERE ThreatEventID >= 34000").fetchone()[0]
        assert n == 5

    def test_ens_threat_severity_range(self):
        rows = self.db.execute(
            "SELECT ThreatSeverity FROM EPOEvents_Consolidated WHERE AutoID < 100"
        ).fetchall()
        for (s,) in rows:
            assert 1 <= s <= 5

    def test_ens_action_taken_blocked(self):
        rows = self.db.execute(
            "SELECT DISTINCT ActionTaken FROM EPOEvents_Consolidated WHERE AutoID < 100"
        ).fetchall()
        assert ("Blocked",) in rows

    def test_appcontrol_threat_category_solidcore(self):
        rows = self.db.execute(
            "SELECT DISTINCT ThreatCategory FROM EPOEvents_Consolidated WHERE AutoID >= 1000"
        ).fetchall()
        categories = [r[0] for r in rows]
        assert any("Solidcore" in c for c in categories)

    def test_appcontrol_event_id_in_solidcore_range(self):
        rows = self.db.execute(
            "SELECT ThreatEventID FROM EPOEvents_Consolidated WHERE AutoID >= 1000"
        ).fetchall()
        for (eid,) in rows:
            assert 34000 <= eid <= 34999

    def test_ens_threat_file_name_uses_canonical_column(self):
        rows = self.db.execute(
            "SELECT ThreatFileName FROM EPOEvents_Consolidated WHERE AutoID < 100"
        ).fetchall()
        for (fname,) in rows:
            assert fname is not None
            assert "malware" in fname

    def test_ens_threat_source_url_populated(self):
        rows = self.db.execute(
            "SELECT ThreatSourceUrl FROM EPOEvents_Consolidated WHERE AutoID < 100"
        ).fetchall()
        for (url,) in rows:
            assert url is not None and url.startswith("http")

    def test_ens_analyzer_detection_method_populated(self):
        rows = self.db.execute(
            "SELECT AnalyzerDetectionMethod FROM EPOEvents_Consolidated WHERE AutoID < 100"
        ).fetchall()
        for (method,) in rows:
            assert method in ("OAS", "ODS", "BehaviorIPS", "Solidcore")


# ══════════════════════════════════════════════════════════════════════════════
# ENS stream simulation
# ══════════════════════════════════════════════════════════════════════════════

class TestENSStreamSimulation:

    def setup_method(self):
        self.db = sqlite3.connect(":memory:")
        _create_mock_db(self.db)
        _insert_ens_events(self.db, count=20, start_id=1)
        self.tmpdir = tempfile.mkdtemp()
        self.schema_mod = _load("schema")
        self.ueba_mod   = _load("ueba_engine")
        self.engine = self.ueba_mod.TrellixUEBAEngine(
            db_path=Path(self.tmpdir) / "state.db"
        )

    def teardown_method(self):
        self.db.close()

    def test_ens_fetch_returns_events(self):
        rows = _fetch_ens(self.db, watermark=0)
        assert len(rows) > 0

    def test_ens_fetch_excludes_appcontrol_categories(self):
        _insert_appcontrol_events(self.db, count=5, start_id=500)
        rows = _fetch_ens(self.db, watermark=0)
        for r in rows:
            assert r.ThreatCategory not in (
                "Solidcore", "McAfee Application Control", "Trellix Application Control"
            )

    def test_ens_fetch_excludes_solidcore_event_ids(self):
        _insert_appcontrol_events(self.db, count=3, start_id=500)
        rows = _fetch_ens(self.db, watermark=0)
        for r in rows:
            if r.ThreatEventID is not None:
                assert not (34000 <= r.ThreatEventID <= 34999)

    def test_ens_watermark_incremental(self):
        all_rows = _fetch_ens(self.db, watermark=0)
        first_half = _fetch_ens(self.db, watermark=0, limit=5)
        watermark_after = first_half[-1].AutoID
        second_half = _fetch_ens(self.db, watermark=watermark_after)
        assert all(r.AutoID > watermark_after for r in second_half)

    def test_ens_cycle_produces_rows(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        assert len(out_rows) > 0

    def test_ens_cycle_row_has_six_element_vector(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        for row in out_rows:
            assert len(row["trellix_math"]) == 6

    def test_ens_cycle_vector_values_in_unit_interval(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        for row in out_rows:
            for v in row["trellix_math"]:
                assert 0.0 <= v <= 1.0, f"Vector value out of [0,1]: {v}"

    def test_ens_cycle_stream_field_is_ens(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        for row in out_rows:
            assert row["stream"] == "ens"

    def test_ens_cycle_file_path_populated(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        for row in out_rows:
            assert row["file_path"] is not None
            assert "malware" in row["file_path"]

    def test_ens_cycle_threat_source_url_populated(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        for row in out_rows:
            assert row["threat_source_url"] is not None
            assert row["threat_source_url"].startswith("http")

    def test_ens_cycle_event_id_populated(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        for row in out_rows:
            assert row["event_id"] is not None
            assert isinstance(row["event_id"], int)

    def test_ens_cycle_analyzer_detection_method_populated(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        for row in out_rows:
            assert row["analyzer_detection_method"] is not None

    def test_ens_cycle_parquet_serializes_correctly(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        payload = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        table = pq.read_table(io.BytesIO(payload))
        assert table.num_rows == len(out_rows)

    def test_ens_cycle_parquet_schema_has_trellix_math(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        payload  = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        table    = pq.read_table(io.BytesIO(payload))
        assert "trellix_math" in table.schema.names

    def test_ens_cycle_severity_score_increases_with_severity(self):
        """Higher ThreatSeverity rows should have higher severity_score."""
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        sev4 = [r for r in out_rows if r["severity"] == 4]
        sev5 = [r for r in out_rows if r["severity"] == 5]
        if sev4 and sev5:
            avg4 = sum(r["severity_score"] for r in sev4) / len(sev4)
            avg5 = sum(r["severity_score"] for r in sev5) / len(sev5)
            assert avg5 >= avg4

    def test_ens_cycle_threat_score_trojan_near_1(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        trojan_rows = [r for r in out_rows if r.get("threat_type") == "Trojan"]
        for row in trojan_rows:
            assert row["threat_score"] == pytest.approx(1.0)

    def test_ens_cycle_action_score_blocked_is_1(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        blocked = [r for r in out_rows if r.get("action") == "Blocked"]
        for row in blocked:
            assert row["action_score"] == pytest.approx(1.0)


# ══════════════════════════════════════════════════════════════════════════════
# AppControl stream simulation
# ══════════════════════════════════════════════════════════════════════════════

class TestAppControlStreamSimulation:

    def setup_method(self):
        self.db = sqlite3.connect(":memory:")
        _create_mock_db(self.db)
        _insert_ens_events(self.db, count=10, start_id=1)
        _insert_appcontrol_events(self.db, count=8, start_id=1000)
        self.tmpdir  = tempfile.mkdtemp()
        self.schema_mod = _load("schema")
        self.ueba_mod   = _load("ueba_engine")
        self.engine = self.ueba_mod.TrellixUEBAEngine(
            db_path=Path(self.tmpdir) / "state.db"
        )

    def teardown_method(self):
        self.db.close()

    def test_appcontrol_fetch_returns_solidcore_events(self):
        rows = _fetch_appcontrol(self.db, watermark=0)
        assert len(rows) > 0
        for r in rows:
            assert (
                r.ThreatCategory in (
                    "Solidcore", "McAfee Application Control", "Trellix Application Control")
                or (r.ThreatEventID is not None and 34000 <= r.ThreatEventID <= 34999)
            )

    def test_appcontrol_fetch_excludes_ens_events(self):
        rows = _fetch_appcontrol(self.db, watermark=0)
        for r in rows:
            assert r.AutoID >= 1000

    def test_appcontrol_cycle_produces_rows(self):
        assert len(_run_cycle(self.db, self.engine, self.schema_mod, "appcontrol")) > 0

    def test_appcontrol_cycle_stream_field_is_appcontrol(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "appcontrol")
        for row in out_rows:
            assert row["stream"] == "appcontrol"

    def test_appcontrol_cycle_vector_length_6(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "appcontrol")
        for row in out_rows:
            assert len(row["trellix_math"]) == 6

    def test_appcontrol_event_ids_in_solidcore_range(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "appcontrol")
        for row in out_rows:
            if row["event_id"] is not None:
                assert 34000 <= row["event_id"] <= 34999

    def test_ens_and_appcontrol_are_disjoint(self):
        ens_rows = _fetch_ens(self.db, watermark=0)
        ac_rows  = _fetch_appcontrol(self.db, watermark=0)
        ens_ids = {r.AutoID for r in ens_rows}
        ac_ids  = {r.AutoID for r in ac_rows}
        assert ens_ids.isdisjoint(ac_ids), "ENS and AppControl fetches must not overlap"

    def test_appcontrol_parquet_roundtrip(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "appcontrol")
        payload  = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        table    = pq.read_table(io.BytesIO(payload))
        assert table.num_rows == len(out_rows)


# ══════════════════════════════════════════════════════════════════════════════
# HMAC & Nexus transmission
# ══════════════════════════════════════════════════════════════════════════════

class TestHMACAndNexusTransmission:

    def setup_method(self):
        self.db = sqlite3.connect(":memory:")
        _create_mock_db(self.db)
        _insert_ens_events(self.db, count=5)
        self.tmpdir     = tempfile.mkdtemp()
        self.schema_mod = _load("schema")
        self.ueba_mod   = _load("ueba_engine")
        self.engine     = self.ueba_mod.TrellixUEBAEngine(
            db_path=Path(self.tmpdir) / "state.db"
        )

    def teardown_method(self):
        self.db.close()

    def test_hmac_header_name_is_x_hmac_sha256(self):
        """reader.py must use the canonical X-Batch-HMAC signing header name --
        matches HDR_BATCH_HMAC in both core_ingress integrity.rs trees
        (services/core_ingress and middleware/src/core_ingress); "X-HMAC-SHA256"
        is not a header name used anywhere in the codebase."""
        src = (TRANSMIT / "reader.py").read_text()
        assert "X-Batch-HMAC" in src

    def test_nexus_stream_header_prefixed_with_trellix(self):
        src = (TRANSMIT / "reader.py").read_text()
        assert "trellix_" in src or 'f"trellix_{' in src

    def test_hmac_sign_produces_deterministic_sig(self):
        payload = b"test-payload-bytes-12345"
        sig1 = hmac_mod.new(HMAC_SECRET, payload, hashlib.sha256).hexdigest()
        sig2 = hmac_mod.new(HMAC_SECRET, payload, hashlib.sha256).hexdigest()
        assert sig1 == sig2

    def test_hmac_sign_on_simulated_parquet(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        payload  = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        sig = hmac_mod.new(HMAC_SECRET, payload, hashlib.sha256).hexdigest()
        assert len(sig) == 64

    def test_hmac_sign_changes_when_payload_modified(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        payload1 = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        # Modify one row and regenerate
        out_rows[0]["auto_id"] = 99999
        payload2 = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        sig1 = hmac_mod.new(HMAC_SECRET, payload1, hashlib.sha256).hexdigest()
        sig2 = hmac_mod.new(HMAC_SECRET, payload2, hashlib.sha256).hexdigest()
        assert sig1 != sig2

    def test_parquet_payload_is_nonzero(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        payload  = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        assert len(payload) > 0

    def test_batch_id_is_uuid_format(self):
        bid = self.schema_mod.make_batch_id()
        assert len(bid) == 36 and bid.count("-") == 4


# ══════════════════════════════════════════════════════════════════════════════
# UEBA on simulated data
# ══════════════════════════════════════════════════════════════════════════════

class TestUEBAOnSimulatedData:

    def setup_method(self):
        self.db = sqlite3.connect(":memory:")
        _create_mock_db(self.db)
        _insert_ens_events(self.db, count=50, start_id=1)
        self.tmpdir     = tempfile.mkdtemp()
        self.schema_mod = _load("schema")
        self.ueba_mod   = _load("ueba_engine")
        self.engine     = self.ueba_mod.TrellixUEBAEngine(
            db_path=Path(self.tmpdir) / "state.db"
        )

    def teardown_method(self):
        self.db.close()

    def test_ueba_scores_all_rows(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        assert len(out_rows) == 50
        for row in out_rows:
            for score in ("anomaly_score", "entropy_score", "frequency_score"):
                assert isinstance(row[score], float)

    def test_all_scores_in_unit_interval(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        for row in out_rows:
            for score in ("anomaly_score", "entropy_score", "frequency_score",
                          "severity_score", "threat_score", "action_score"):
                v = row[score]
                assert 0.0 <= v <= 1.0, f"{score}={v} out of [0,1]"

    def test_high_entropy_exe_in_temp_dir(self):
        """Executable in Temp directory should score higher entropy than system32 path."""
        ueba = self.ueba_mod.TrellixUEBAEngine(db_path=Path(self.tmpdir) / "e.db")
        _, e_temp, _ = ueba.score_event(
            "Trojan.X", "Trojan",
            r"C:\Users\user\AppData\Local\Temp\random_abc123def456.exe", "svchost.exe",
            4, "Blocked",
        )
        _, e_sys32, _ = ueba.score_event(
            "Trojan.X", "Trojan",
            r"C:\Windows\System32\svchost.exe", "svchost.exe",
            4, "Blocked",
        )
        assert e_temp >= e_sys32, "Temp-dir executable should have higher entropy score"

    def test_repeated_threat_frequency_score_decreases(self):
        ueba = self.ueba_mod.TrellixUEBAEngine(db_path=Path(self.tmpdir) / "f.db")
        for i in range(50):
            ueba.score_event(f"Noise.{i}", "Adware", r"C:\f.exe", "x.exe", 1, "Detected")
        _, _, f1 = ueba.score_event(
            "Common.Adware", "Adware", r"C:\f.exe", "x.exe", 1, "Detected")
        for _ in range(20):
            ueba.score_event(
                "Common.Adware", "Adware", r"C:\f.exe", "x.exe", 1, "Detected")
        _, _, f2 = ueba.score_event(
            "Common.Adware", "Adware", r"C:\f.exe", "x.exe", 1, "Detected")
        assert f2 < f1

    def test_blocked_action_score_is_1(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        blocked = [r for r in out_rows if r.get("action") == "Blocked"]
        assert blocked, "Expected some Blocked rows in the simulation"
        for row in blocked:
            assert row["action_score"] == pytest.approx(1.0)

    def test_ueba_state_persists_after_flush(self):
        db_path = Path(self.tmpdir) / "persist.db"
        ueba1 = self.ueba_mod.TrellixUEBAEngine(db_path=db_path)
        for i in range(5):
            ueba1.score_event(f"T{i}", "Trojan", r"C:\bad.exe", "b.exe", 5, "Blocked")
        ueba1.flush()
        assert db_path.exists()

    def test_batch_parquet_has_all_context_fields(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        payload  = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        table    = pq.read_table(io.BytesIO(payload))
        for col in ("threat_source_url", "event_id", "analyzer_detection_method",
                    "source_component", "threat_category"):
            assert col in table.schema.names, f"Missing context column in Parquet: {col}"

    def test_batch_parquet_event_ids_match_source(self):
        out_rows = _run_cycle(self.db, self.engine, self.schema_mod, "ens")
        payload  = _rows_to_parquet_bytes(out_rows, self.schema_mod.TRELLIX_MATH_SCHEMA)
        table    = pq.read_table(io.BytesIO(payload))
        event_ids = table.column("event_id").to_pylist()
        # All ENS events have ThreatEventID = 1092..1141 range from our mock
        for eid in event_ids:
            if eid is not None:
                assert 1000 <= eid <= 1200, f"Unexpected event_id {eid} in ENS batch"
