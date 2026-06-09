"""
Shared fixtures for trellix_sql tier2 tests.

Module-level setup (runs before any test file is imported by pytest):
  1. Adds transmit/ to sys.path so reader/schema/ueba_engine are importable.
  2. Sets all environment variables reader.py reads at module level.
  3. Installs a lightweight pyodbc stub (no ODBC driver in this container).

Fixtures provide:
  - sqlite_db  / fake_con  -- seeded in-memory DB + FakeConnection wrapper
  - empty_db   / empty_con -- schema-only DB (no rows)
  - ueba_engine            -- TrellixUEBAEngine on a tmp SQLite file
  - batch_sequence         -- _BatchSequence on a tmp file, starting at 0
"""

from __future__ import annotations

import datetime
import os
import sys
import types
from pathlib import Path
from typing import Generator

import pytest
import sqlite3

# ---------------------------------------------------------------------------
# 1. Extend sys.path so transmit/ is importable without a package install
# ---------------------------------------------------------------------------
_TRANSMIT = Path(__file__).parents[2] / "transmit"
if str(_TRANSMIT) not in sys.path:
    sys.path.insert(0, str(_TRANSMIT))

# ---------------------------------------------------------------------------
# 2. Environment variables (reader.py raises KeyError at import if missing)
# ---------------------------------------------------------------------------
_ENV = {
    "MSSQL_HOST":             "localhost",
    "MSSQL_PORT":             "1433",
    "MSSQL_USER":             "sa",
    "MSSQL_PASSWORD":         "Testing1234!",
    "NEXUS_INGEST_URL":       "http://nexus-test.local/api/v1/telemetry",
    "NEXUS_AUTH_TOKEN":       "test-bearer-token",
    "NEXUS_INTEGRITY_SECRET": "test-secret-key-for-hmac-signing",
    "NEXUS_SENSOR_ID":        "TEST-SENSOR-001",
    "TRANSMIT_BATCH_SIZE":    "100",
    "TRANSMIT_INTERVAL_SECS": "1",
    "UEBA_REFIT_INTERVAL":    "10",
}
for _k, _v in _ENV.items():
    os.environ.setdefault(_k, _v)

# ---------------------------------------------------------------------------
# 3. pyodbc stub (real driver unavailable in this container)
# ---------------------------------------------------------------------------
_pyodbc = types.ModuleType("pyodbc")
_pyodbc.Connection = object  # type: ignore[attr-defined]
_pyodbc.connect = lambda *a, **kw: None  # type: ignore[attr-defined]
sys.modules.setdefault("pyodbc", _pyodbc)

# ---------------------------------------------------------------------------
# Sample events: 3 ENS + 2 AppControl rows
#
# ENS rows:        AutoID 1, 2, 5  (ThreatCategory not in Solidcore/AppControl;
#                                   ThreatEventID not in 34000-34999)
# AppControl rows: AutoID 3, 4     (ThreatCategory=Solidcore / McAfee...,
#                                   ThreatEventID in 34xxx range)
# ---------------------------------------------------------------------------
SAMPLE_EVENTS = [
    # fmt: off
    # AutoID  ReceivedUTC                              DetectedUTC
    # AgentGUID        SourceHostName
    # ThreatName              ThreatType  ThreatCategory  Sev  Action
    # UserName  ThreatFileName                                   ThreatSourceUrl
    # ProcessName    ThreatEventID  AnalyzerName  AnaVer  DetectionMethod
    (1,
     datetime.datetime(2024, 1, 1, 10, 0, 0), datetime.datetime(2024, 1, 1, 9, 59, 0),
     "GUID-001", "HOST-ALPHA",
     "Trojan.GenericKD", "Trojan", "Malware", 4, "Blocked",
     "alice", r"C:\Users\alice\Downloads\setup.exe", None, "explorer.exe",
     1080, "VSE", "22.0", "Heuristic"),
    (2,
     datetime.datetime(2024, 1, 1, 10, 1, 0), datetime.datetime(2024, 1, 1, 10, 0, 30),
     "GUID-002", "HOST-BETA",
     "EICAR-Test-File", "Test", None, 2, "Detected",
     "bob", r"C:\Windows\Temp\eicar.com", None, "cmd.exe",
     1092, "OAS", "22.0", "Signature"),
    (3,
     datetime.datetime(2024, 1, 1, 10, 2, 0), datetime.datetime(2024, 1, 1, 10, 1, 45),
     "GUID-003", "HOST-GAMMA",
     "AppCtrl:Block:Untrusted", "AppControl", "Solidcore", 3, "Blocked",
     "carol", r"C:\Tools\custom_app.exe", None, "svchost.exe",
     34001, "AppControl", "10.3", "AppControl"),
    (4,
     datetime.datetime(2024, 1, 1, 10, 3, 0), datetime.datetime(2024, 1, 1, 10, 2, 55),
     "GUID-004", "HOST-DELTA",
     "AppCtrl:Block:McAfee", "AppControl", "McAfee Application Control", 2, "Blocked",
     "dave", r"C:\Program Files\trusted.exe", None, "services.exe",
     34100, "AppControl", "10.3", "AppControl"),
    (5,
     datetime.datetime(2024, 1, 1, 10, 4, 0), datetime.datetime(2024, 1, 1, 10, 3, 50),
     "GUID-005", "HOST-EPSILON",
     "Ransom.WannaCry", "Ransomware", "Malware", 5, "Quarantined",
     "eve", r"C:\Users\eve\AppData\Local\Temp\wannacry.exe",
     "http://evil.example.com/payload", "wscript.exe",
     1234, "VSE", "22.0", "Behavioral"),
    # fmt: on
]

_INSERT_SQL = (
    "INSERT INTO EPOEvents_Consolidated "
    "(AutoID, ReceivedUTC, DetectedUTC, AgentGUID, SourceHostName, "
    "ThreatName, ThreatType, ThreatCategory, ThreatSeverity, ActionTaken, "
    "UserName, ThreatFileName, ThreatSourceUrl, ProcessName, "
    "ThreatEventID, AnalyzerName, AnalyzerVersion, AnalyzerDetectionMethod) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sqlite_db() -> Generator[sqlite3.Connection, None, None]:
    """In-memory SQLite DB with EPO schema and all SAMPLE_EVENTS loaded."""
    from _sqlite_db import make_db
    con = make_db()
    con.executemany(_INSERT_SQL, SAMPLE_EVENTS)
    con.commit()
    yield con
    con.close()

@pytest.fixture
def fake_con(sqlite_db: sqlite3.Connection):
    """FakeConnection wrapping the seeded SQLite DB."""
    from _sqlite_db import FakeConnection
    return FakeConnection(sqlite_db)

@pytest.fixture
def empty_db() -> Generator[sqlite3.Connection, None, None]:
    """In-memory SQLite DB with EPO schema but zero event rows."""
    from _sqlite_db import make_db
    con = make_db()
    yield con
    con.close()

@pytest.fixture
def empty_con(empty_db: sqlite3.Connection):
    """FakeConnection wrapping the empty SQLite DB."""
    from _sqlite_db import FakeConnection
    return FakeConnection(empty_db)

@pytest.fixture
def ueba_engine(tmp_path: Path):
    """TrellixUEBAEngine backed by a per-test temporary SQLite file."""
    from ueba_engine import TrellixUEBAEngine
    engine = TrellixUEBAEngine(
        db_path=tmp_path / "state.db",
        refit_interval=5,
    )
    yield engine
    engine.flush()

@pytest.fixture
def batch_sequence(tmp_path: Path):
    """_BatchSequence starting at 0 backed by a per-test temporary file."""
    import reader
    return reader._BatchSequence(tmp_path / ".sequence")