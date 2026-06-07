"""
SysmonSensor.py -- Nexus Sysmon Sensor Agent

Reads Sysmon events from the Windows Event Log
(Microsoft-Windows-Sysmon/Operational), normalises each event into the
sysmon_sensor Parquet schema, computes the windows_math feature vector,
and ships batches to the Nexus middleware ingress via HTTPS POST.

Runs as a Windows service or a standalone console process.

Prerequisites:
  - Sysmon installed and running with nexus sysmon_config.xml
  - Python 3.10+ with dependencies from requirements.txt
  - DeepXDR_Sysmon.ini in the same directory (or env vars set)

Usage:
    python SysmonSensor.py               # run in foreground
    python SysmonSensor.py --install     # install as Windows service
    python SysmonSensor.py --uninstall   # remove Windows service
"""

import argparse
import logging
import os
import sys
import time
import json
import socket
import configparser
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("sysmon.sensor")

# ── Windows-only imports ───────────────────────────────────────────────────────
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import winerror
    import pywintypes
    WINDOWS = True
except ImportError:
    WINDOWS = False
    logger.warning("pywin32 not available -- running in offline/test mode")

from parquet_shipper import ParquetShipper

# ── Sysmon event channel ───────────────────────────────────────────────────────
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# ── Event IDs we capture (must match sysmon_config.xml) ───────────────────────
CAPTURED_EVENT_IDS = {1, 3, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25, 26}

# ── Event-specific field parsers ───────────────────────────────────────────────
# Each function takes the event's EventData string fields (as a dict keyed by
# the field name Sysmon uses in the XML) and returns a normalised record dict.

def _parse_event_data(event) -> dict:
    """Extract EventData fields from a win32evtlog event into a flat dict."""
    record: dict = {}
    try:
        data = win32evtlogutil.SafeFormatMessage(event, SYSMON_CHANNEL)
    except Exception:
        data = ""

    # win32evtlog gives us the event data fields as a list of strings
    # Sysmon formats them as "FieldName: Value\n"
    for line in data.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key and val:
                record[key] = val

    return record


def _normalise(event_id: int, raw: dict, hostname: str) -> dict:
    """
    Map raw Sysmon field names to our schema column names.
    Returns a flat dict ready for ParquetShipper.submit().
    """
    record: dict = {
        "sensor_type":     "sysmon_sensor",
        "sensor_id":       hostname,
        "timestamp":       time.time(),
        "sysmon_event_id": event_id,
    }

    # ── Event 1: Process Create ────────────────────────────────────────────
    if event_id == 1:
        record.update({
            "Image":            raw.get("Image"),
            "CommandLine":      raw.get("CommandLine"),
            "ParentImage":      raw.get("ParentImage"),
            "ParentCommandLine":raw.get("ParentCommandLine"),
            "User":             raw.get("User"),
            "IntegrityLevel":   raw.get("IntegrityLevel"),
            "ProcessId":        _int(raw.get("ProcessId")),
            "ParentProcessId":  _int(raw.get("ParentProcessId")),
            "Hashes":           raw.get("Hashes"),
            "CurrentDirectory": raw.get("CurrentDirectory"),
            "RuleName":         raw.get("RuleName"),
        })

    # ── Event 3: Network Connection ────────────────────────────────────────
    elif event_id == 3:
        record.update({
            "Image":         raw.get("Image"),
            "User":          raw.get("User"),
            "ProcessId":     _int(raw.get("ProcessId")),
            "DestinationIp": raw.get("DestinationIp"),
            "DestinationPort": _int(raw.get("DestinationPort")),
            "Protocol":      raw.get("Protocol"),
            "Initiated":     raw.get("Initiated", "").lower() == "true",
        })

    # ── Event 6: Driver Load ───────────────────────────────────────────────
    elif event_id == 6:
        record.update({
            "ImageLoaded":     raw.get("ImageLoaded"),
            "Hashes":          raw.get("Hashes"),
            "Signed":          raw.get("Signed", "").lower() == "true",
            "SignatureStatus": raw.get("SignatureStatus"),
        })

    # ── Event 7: Image Load ────────────────────────────────────────────────
    elif event_id == 7:
        record.update({
            "Image":           raw.get("Image"),
            "ImageLoaded":     raw.get("ImageLoaded"),
            "Hashes":          raw.get("Hashes"),
            "Signed":          raw.get("Signed", "").lower() == "true",
            "SignatureStatus": raw.get("SignatureStatus"),
            "SignatureIssuer": raw.get("SignatureIssuer"),
        })

    # ── Event 8: CreateRemoteThread ────────────────────────────────────────
    elif event_id == 8:
        record.update({
            "SourceImage": raw.get("SourceImage"),
            "TargetImage": raw.get("TargetImage"),
            "StartAddress":raw.get("StartAddress"),
            "StartModule": raw.get("StartModule"),
        })

    # ── Event 10: ProcessAccess ────────────────────────────────────────────
    elif event_id == 10:
        record.update({
            "SourceImage":  raw.get("SourceImage"),
            "TargetImage":  raw.get("TargetImage"),
            "GrantedAccess":raw.get("GrantedAccess"),
            "User":         raw.get("User"),
        })

    # ── Event 11: FileCreate ───────────────────────────────────────────────
    elif event_id == 11:
        record.update({
            "Image":          raw.get("Image"),
            "TargetFilename": raw.get("TargetFilename"),
            "User":           raw.get("User"),
        })

    # ── Event 12/13/14: Registry ───────────────────────────────────────────
    elif event_id in (12, 13, 14):
        record.update({
            "Image":        raw.get("Image"),
            "TargetObject": raw.get("TargetObject"),
            "Details":      raw.get("Details"),
            "EventType_reg":raw.get("EventType"),  # rename to avoid clash with schema
            "User":         raw.get("User"),
        })

    # ── Event 15: FileCreateStreamHash ────────────────────────────────────
    elif event_id == 15:
        record.update({
            "Image":          raw.get("Image"),
            "TargetFilename": raw.get("TargetFilename"),
            "Hashes":         raw.get("Hashes"),
        })

    # ── Event 17/18: Pipe ─────────────────────────────────────────────────
    elif event_id in (17, 18):
        record.update({
            "Image":    raw.get("Image"),
            "PipeName": raw.get("PipeName"),
            "User":     raw.get("User"),
        })

    # ── Event 22: DNS Query ────────────────────────────────────────────────
    elif event_id == 22:
        record.update({
            "Image":        raw.get("Image"),
            "QueryName":    raw.get("QueryName"),
            "QueryResults": raw.get("QueryResults"),
            "User":         raw.get("User"),
        })

    # ── Event 23/26: FileDelete ────────────────────────────────────────────
    elif event_id in (23, 26):
        record.update({
            "Image":          raw.get("Image"),
            "TargetFilename": raw.get("TargetFilename"),
            "User":           raw.get("User"),
        })

    # ── Event 25: ProcessTampering ─────────────────────────────────────────
    elif event_id == 25:
        record.update({
            "Image":         raw.get("Image"),
            "TamperingType": raw.get("Type"),
            "User":          raw.get("User"),
        })

    return record


def _int(val) -> int | None:
    if val is None:
        return None
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return None


# ── Main sensor loop ───────────────────────────────────────────────────────────

class SysmonSensor:
    """
    Tails the Sysmon event log and submits normalised records to ParquetShipper.
    Uses win32evtlog bookmark API to resume after restart.
    """

    BOOKMARK_PATH = Path(os.environ.get(
        "NEXUS_BOOKMARK_PATH",
        r"C:\ProgramData\NexusSysmonSensor\bookmark.xml"
    ))

    def __init__(self):
        self.hostname = os.environ.get("NEXUS_SENSOR_ID", socket.gethostname())
        self.shipper  = ParquetShipper()
        self._running = True

    def run(self) -> None:
        if not WINDOWS:
            logger.error("SysmonSensor requires Windows with pywin32 installed.")
            return

        self.BOOKMARK_PATH.parent.mkdir(parents=True, exist_ok=True)
        log_handle = win32evtlog.EvtOpenChannelConfig(SYSMON_CHANNEL)

        # Build query for our event IDs
        id_filter = " or ".join(f"EventID={eid}" for eid in sorted(CAPTURED_EVENT_IDS))
        query_str = f"*[System[{id_filter}]]"

        query = win32evtlog.EvtQuery(
            SYSMON_CHANNEL,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
            query_str,
        )

        # Seek to bookmark if available
        if self.BOOKMARK_PATH.exists():
            try:
                bookmark_xml = self.BOOKMARK_PATH.read_text()
                bookmark = win32evtlog.EvtCreateBookmark(bookmark_xml)
                win32evtlog.EvtSeek(query, 1, bookmark,
                                    win32evtlog.EvtSeekRelativeToBookmark)
                logger.info("Resumed from bookmark")
            except Exception as e:
                logger.warning(f"Bookmark seek failed ({e}), starting from current")

        bookmark = win32evtlog.EvtCreateBookmark(None)
        poll_ms  = int(os.environ.get("NEXUS_POLL_MS", "500"))

        logger.info(f"Sysmon sensor running on {self.hostname}")
        event_count = 0

        while self._running:
            try:
                events = win32evtlog.EvtNext(query, 100, 0, 0)
            except pywintypes.error as e:
                if e.winerror == winerror.ERROR_NO_MORE_ITEMS:
                    time.sleep(poll_ms / 1000.0)
                    continue
                raise

            if not events:
                time.sleep(poll_ms / 1000.0)
                continue

            for event in events:
                try:
                    event_id  = win32evtlog.EvtGetEventMetadataProperty(
                        win32evtlog.EvtOpenEventMetadata(log_handle, event),
                        win32evtlog.EvtEventMetadataEventID, 0
                    ) if False else int(
                        win32evtlog.EvtFormatMessage(event,
                            win32evtlog.EvtFormatMessageId) or 0
                    )
                except Exception:
                    # Fallback: parse event ID from XML
                    try:
                        xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                        import re
                        m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
                        event_id = int(m.group(1)) if m else 0
                    except Exception:
                        event_id = 0

                if event_id not in CAPTURED_EVENT_IDS:
                    win32evtlog.EvtUpdateBookmark(bookmark, event)
                    continue

                raw    = _parse_event_data(event)
                record = _normalise(event_id, raw, self.hostname)
                self.shipper.submit(record)
                event_count += 1

                win32evtlog.EvtUpdateBookmark(bookmark, event)

            # Persist bookmark every batch
            try:
                bxml = win32evtlog.EvtRender(bookmark, win32evtlog.EvtRenderBookmark)
                self.BOOKMARK_PATH.write_text(bxml)
            except Exception as e:
                logger.debug(f"Bookmark save failed: {e}")

            if event_count % 1000 == 0 and event_count > 0:
                logger.info(f"Processed {event_count} Sysmon events")

    def stop(self) -> None:
        self._running = False
        self.shipper.shutdown()


# ── Entrypoint ─────────────────────────────────────────────────────────────────

def _configure_logging():
    log_dir = Path(os.environ.get("NEXUS_LOG_DIR", r"C:\ProgramData\NexusSysmonSensor\logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_dir / "sysmon_sensor.log"),
        ]
    )


def main():
    parser = argparse.ArgumentParser(description="Nexus Sysmon Sensor Agent")
    parser.add_argument("--config", default="DeepXDR_Sysmon.ini",
                        help="Path to sensor config INI file")
    args = parser.parse_args()

    _configure_logging()

    # Load INI config into env vars (env vars take precedence)
    if Path(args.config).exists():
        cfg = configparser.ConfigParser()
        cfg.read(args.config)
        if "TRANSMISSION" in cfg:
            for key, envvar in [
                ("MiddlewareEndpoint", "NEXUS_MIDDLEWARE_URL"),
                ("AuthToken",          "NEXUS_AUTH_TOKEN"),
                ("IntegritySecret",    "NEXUS_INTEGRITY_SECRET"),
                ("SensorId",           "NEXUS_SENSOR_ID"),
                ("MaxBatchSize",       "NEXUS_MAX_BATCH_ROWS"),
                ("TrustSelfSignedCert","NEXUS_TLS_VERIFY"),
            ]:
                val = cfg["TRANSMISSION"].get(key)
                if val and envvar not in os.environ:
                    # Invert TrustSelfSignedCert → TLS_VERIFY
                    if key == "TrustSelfSignedCert":
                        val = "false" if val.lower() == "true" else "true"
                    os.environ[envvar] = val

    sensor = SysmonSensor()
    try:
        sensor.run()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sensor.stop()


if __name__ == "__main__":
    main()
