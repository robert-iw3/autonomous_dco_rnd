"""
MSSQL T-SQL → SQLite adapter and schema for tier2 tests.

FakeConnection wraps an in-memory SQLite database and translates the
subset of MSSQL syntax used by reader.py so the watermark and batch-fetch
functions can run against a real in-process database with no ODBC driver.
"""

from __future__ import annotations

import datetime
import re
import sqlite3
from typing import Any

# Register adapters so TIMESTAMP columns roundtrip as datetime.datetime objects.
# reader.py receives datetime objects from pyodbc; SQLite would return strings
# without these adapters, causing build_row()'s .replace(tzinfo=...) to fail.
sqlite3.register_adapter(
    datetime.datetime,
    lambda d: d.isoformat(),
)
sqlite3.register_converter(
    "TIMESTAMP",
    lambda s: datetime.datetime.fromisoformat(s.decode()),
)

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS EPOEvents_Consolidated (
    AutoID                  INTEGER   PRIMARY KEY AUTOINCREMENT,
    ReceivedUTC             TIMESTAMP NOT NULL,
    DetectedUTC             TIMESTAMP,
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
    AnalyzerDetectionMethod TEXT
);

CREATE TABLE IF NOT EXISTS TransmitWatermark (
    WatermarkID             INTEGER PRIMARY KEY AUTOINCREMENT,
    StreamName              TEXT    NOT NULL,
    LastTransmittedAutoID   INTEGER NOT NULL,
    LastTransmitTime        TEXT,
    RowsTransmitted         INTEGER,
    BatchID                 TEXT,
    Status                  TEXT
);
"""

def make_db() -> sqlite3.Connection:
    """Return an in-memory SQLite connection with the EPO schema.

    detect_types=PARSE_DECLTYPES activates the TIMESTAMP converter so
    ReceivedUTC / DetectedUTC columns are returned as datetime objects.
    """
    con = sqlite3.connect(
        ":memory:",
        detect_types=sqlite3.PARSE_DECLTYPES,
    )
    con.executescript(_CREATE_SQL)
    return con

# ---------------------------------------------------------------------------
# Query adapter
# ---------------------------------------------------------------------------

def _adapt_mssql(sql: str, params: list) -> tuple[str, list]:
    """Translate the MSSQL T-SQL subset used by reader.py to SQLite SQL.

    Handles:
      - WITH (NOLOCK)          → remove
      - dbo.                   → remove
      - SYSDATETIME()          → datetime('now')
      - SELECT TOP (N)         → SELECT ... LIMIT N  (literal integer)
      - SELECT TOP (?)         → SELECT ... LIMIT N  (extract first param)
    """
    sql = re.sub(r"\bWITH\s*\(NOLOCK\)", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\bdbo\.", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\bSYSDATETIME\(\)", "datetime('now')", sql, flags=re.IGNORECASE)

    lit = re.search(r"SELECT\s+TOP\s*\((\d+)\)", sql, re.IGNORECASE)
    if lit:
        limit_val = int(lit.group(1))
        sql = re.sub(
            r"SELECT\s+TOP\s*\(\d+\)", "SELECT", sql, count=1, flags=re.IGNORECASE
        )
        sql = sql.rstrip("; \n") + f" LIMIT {limit_val}"
    elif re.search(r"SELECT\s+TOP\s*\(\?\)", sql, re.IGNORECASE):
        limit_val = int(params.pop(0))
        sql = re.sub(
            r"SELECT\s+TOP\s*\(\?\)", "SELECT", sql, count=1, flags=re.IGNORECASE
        )
        sql = sql.rstrip("; \n") + f" LIMIT {limit_val}"

    sql = sql.rstrip("; \n") + ";"
    return sql, params

# ---------------------------------------------------------------------------
# FakeConnection
# ---------------------------------------------------------------------------

class FakeConnection:
    """pyodbc.Connection shim backed by an in-memory SQLite database.

    Translates MSSQL queries on the fly so reader.py functions can be
    called directly in tests without any ODBC driver installation.
    close() is a no-op so the caller can continue querying the DB.
    """

    def __init__(self, sqlite_con: sqlite3.Connection) -> None:
        self._con = sqlite_con

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
        translated, params = _adapt_mssql(sql, list(args))
        return self._con.execute(translated, params)

    def commit(self) -> None:
        self._con.commit()

    def close(self) -> None:
        pass