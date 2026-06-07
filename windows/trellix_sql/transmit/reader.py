"""
reader.py -- Transmission loop: SQL staging → UEBA → Parquet → Nexus.

Entry point for the transmit Docker container.
Reads batches from ConsolidatedEventsENS, applies TrellixUEBAEngine,
serializes to Parquet, HMAC-SHA256 signs, and POSTs to Nexus ingress.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

import pyarrow as pa
import pyarrow.parquet as pq
import pyodbc
import requests

from schema import (
    TRELLIX_MATH_SCHEMA,
    build_row,
    make_batch_id,
    threat_type_to_score,
)
from ueba_engine import (
    TrellixUEBAEngine,
    _action_to_float,
    _severity_to_float,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("reader")

# -- Config from environment ---------------------------------------------------

MSSQL_HOST      = os.environ["MSSQL_HOST"]
MSSQL_PORT      = int(os.environ.get("MSSQL_PORT", 1433))
MSSQL_DB        = os.environ.get("MSSQL_DB", "ConsolidatedEventsENS")
MSSQL_USER      = os.environ["MSSQL_USER"]
MSSQL_PASSWORD  = os.environ["MSSQL_PASSWORD"]

NEXUS_INGEST_URL    = os.environ["NEXUS_INGEST_URL"]
NEXUS_HMAC_SECRET   = os.environ["NEXUS_HMAC_SECRET"].encode()

BATCH_SIZE          = int(os.environ.get("TRANSMIT_BATCH_SIZE", 1000))
INTERVAL_SECS       = int(os.environ.get("TRANSMIT_INTERVAL_SECS", 60))
UEBA_REFIT_INTERVAL = int(os.environ.get("UEBA_REFIT_INTERVAL", 500))

CONFIG_PATH = Path(__file__).parent / "config.json"

_STOP = False


def _handle_signal(sig: int, frame: Any) -> None:
    global _STOP
    log.info("Signal %d received -- draining and stopping.", sig)
    _STOP = True


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


# -- SQL connection ------------------------------------------------------------

def _make_connection() -> pyodbc.Connection:
    dsn = (
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={MSSQL_HOST},{MSSQL_PORT};"
        f"DATABASE={MSSQL_DB};"
        f"UID={MSSQL_USER};"
        f"PWD={MSSQL_PASSWORD};"
        "Encrypt=yes;TrustServerCertificate=yes;"
    )
    return pyodbc.connect(dsn, autocommit=False)


# -- Watermark helpers ---------------------------------------------------------

def _get_watermark(con: pyodbc.Connection, stream: str) -> int:
    row = con.execute(
        "SELECT TOP (1) LastTransmittedAutoID FROM dbo.TransmitWatermark "
        "WHERE StreamName = ? ORDER BY WatermarkID DESC;",
        stream,
    ).fetchone()
    return row[0] if row else 0


def _update_watermark(
    con: pyodbc.Connection,
    stream: str,
    last_auto_id: int,
    rows_transmitted: int,
    batch_id: str,
) -> None:
    con.execute(
        "INSERT INTO dbo.TransmitWatermark "
        "(StreamName, LastTransmittedAutoID, LastTransmitTime, RowsTransmitted, BatchID, Status) "
        "VALUES (?, ?, SYSDATETIME(), ?, ?, 'Success');",
        stream, last_auto_id, rows_transmitted, batch_id,
    )
    con.commit()


# -- Batch fetch ---------------------------------------------------------------

_FETCH_SQL = """
SELECT TOP (?)
    AutoID, ReceivedUTC, DetectedUTC, AgentGUID, SourceHostName,
    ThreatName, ThreatType, ThreatCategory, ThreatSeverity, ActionTaken,
    UserName, ThreatFileName, ThreatSourceUrl, ProcessName,
    ThreatEventID, AnalyzerName, AnalyzerVersion, AnalyzerDetectionMethod
FROM dbo.EPOEvents_Consolidated WITH (NOLOCK)
WHERE AutoID > ?
{stream_filter}
ORDER BY AutoID;
"""

_ENS_FILTER = """
  AND (ThreatCategory NOT IN (
        'Solidcore', 'McAfee Application Control', 'Trellix Application Control')
   OR ThreatCategory IS NULL)
  AND (ThreatEventID NOT BETWEEN 34000 AND 34999 OR ThreatEventID IS NULL)
"""

_AC_FILTER = """
  AND (ThreatCategory IN (
        'Solidcore', 'McAfee Application Control', 'Trellix Application Control')
   OR ThreatEventID BETWEEN 34000 AND 34999)
"""


def _fetch_batch(
    con: pyodbc.Connection, stream: str, last_auto_id: int
) -> list[pyodbc.Row]:
    filt = _ENS_FILTER if stream == "ens" else _AC_FILTER
    sql = _FETCH_SQL.format(stream_filter=filt)
    return con.execute(sql, BATCH_SIZE, last_auto_id).fetchall()


# -- Parquet serialization -----------------------------------------------------

def _rows_to_parquet(rows: list[dict]) -> bytes:
    arrays: dict[str, list] = {f.name: [] for f in TRELLIX_MATH_SCHEMA}
    for row in rows:
        for col in arrays:
            arrays[col].append(row.get(col))

    pa_cols = []
    for field in TRELLIX_MATH_SCHEMA:
        raw = arrays[field.name]
        if field.name == "trellix_math":
            pa_cols.append(pa.array(raw, type=pa.list_(pa.float32())))
        else:
            pa_cols.append(pa.array(raw, type=field.type))

    table = pa.table(dict(zip([f.name for f in TRELLIX_MATH_SCHEMA], pa_cols)),
                     schema=TRELLIX_MATH_SCHEMA)

    buf = io.BytesIO()
    pq.write_table(table, buf, compression="zstd")
    return buf.getvalue()


# -- HMAC signing --------------------------------------------------------------

def _hmac_sign(payload: bytes) -> str:
    return hmac.new(NEXUS_HMAC_SECRET, payload, hashlib.sha256).hexdigest()


# -- Nexus POST ----------------------------------------------------------------

def _send_to_nexus(payload: bytes, batch_id: str, stream: str) -> None:
    sig = _hmac_sign(payload)
    headers = {
        "Content-Type":     "application/octet-stream",
        "X-Nexus-BatchID":  batch_id,
        "X-Nexus-Stream":   f"trellix_{stream}",
        "X-Nexus-Format":   "parquet",
        "X-HMAC-SHA256":    sig,
    }
    resp = requests.post(
        NEXUS_INGEST_URL,
        data=payload,
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    log.info("batch_id=%s stream=%s bytes=%d status=%d",
             batch_id, stream, len(payload), resp.status_code)


# -- Main loop -----------------------------------------------------------------

def _process_stream(
    con: pyodbc.Connection,
    engine: TrellixUEBAEngine,
    stream: str,
) -> int:
    last_auto_id = _get_watermark(con, stream)
    rows = _fetch_batch(con, stream, last_auto_id)

    if not rows:
        return 0

    batch_id = make_batch_id()
    out_rows: list[dict] = []

    for r in rows:
        (auto_id, received_utc, detected_utc, agent_guid, source_host,
         threat_name, threat_type, threat_category, threat_severity, action_taken,
         user_name, threat_file_name, threat_source_url, process_name,
         threat_event_id, analyzer_name, analyzer_version, analyzer_detection_method) = r

        anomaly, entropy, frequency = engine.score_event(
            threat_name=threat_name,
            threat_type=threat_type,
            file_path=threat_file_name,
            process_name=process_name,
            severity=threat_severity,
            action_taken=action_taken,
        )

        out_rows.append(build_row(
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
            batch_id=batch_id,
            stream=stream,
            severity_score=_severity_to_float(threat_severity),
            threat_score=threat_type_to_score(threat_type),
            action_score=_action_to_float(action_taken),
        ))

    payload = _rows_to_parquet(out_rows)
    _send_to_nexus(payload, batch_id, stream)

    last_auto_id_new = rows[-1][0]  # AutoID is column 0
    _update_watermark(con, stream, last_auto_id_new, len(out_rows), batch_id)

    return len(out_rows)


def run() -> None:
    log.info("Transmission reader starting. host=%s db=%s batch=%d interval=%ds",
             MSSQL_HOST, MSSQL_DB, BATCH_SIZE, INTERVAL_SECS)

    db_path = Path(__file__).parent / "ueba_state" / "state.db"
    engine = TrellixUEBAEngine(
        db_path=db_path,
        refit_interval=UEBA_REFIT_INTERVAL,
    )

    while not _STOP:
        try:
            con = _make_connection()
            try:
                total = 0
                for stream in ("ens", "appcontrol"):
                    total += _process_stream(con, engine, stream)
                if total:
                    log.info("Cycle complete: %d rows transmitted.", total)
                else:
                    log.debug("No new rows.")
            finally:
                con.close()
        except Exception:
            log.exception("Transmission error -- will retry next cycle.")

        if _STOP:
            break
        time.sleep(INTERVAL_SECS)

    engine.flush()
    log.info("Reader stopped cleanly.")


if __name__ == "__main__":
    run()