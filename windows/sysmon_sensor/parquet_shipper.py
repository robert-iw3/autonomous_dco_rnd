"""
parquet_shipper.py -- Hive-partitioned Parquet writer + S3 HTTPS uploader.

Matches the partition scheme worker_s3_archive.rs writes for all other sensors:
  telemetry/{sensor_type}/dt={YYYY-MM-DD}/hour={HH}/{uuid}.parquet

Configuration via environment variables (same as middleware sensor profiles):
  NEXUS_MIDDLEWARE_URL    -- https://middleware.internal:8443/api/v1/telemetry
  NEXUS_AUTH_TOKEN        -- Bearer token
  NEXUS_INTEGRITY_SECRET  -- HMAC-SHA256 shared secret
  NEXUS_SENSOR_ID         -- hostname override (default: socket.gethostname())
  NEXUS_MAX_BATCH_ROWS    -- rows per Parquet batch (default: 500)
  NEXUS_TLS_VERIFY        -- "true"/"false" (default: true)

Designed to run on the endpoint alongside the Sysmon sensor agent.
Can also ship directly to S3 (MinIO) if NEXUS_S3_ENDPOINT is set --
useful for air-gapped deployments where the middleware is unavailable.
"""

import os
import io
import json
import time
import random
import uuid
import socket
import hashlib
import hmac
import logging
import threading
from datetime import datetime, timezone
from typing import List

import pyarrow as pa
import pyarrow.parquet as pq
import requests
from schema import SCHEMA, compute_features

logger = logging.getLogger("sysmon.shipper")

SENSOR_TYPE = "sysmon_sensor"


class ParquetShipper:
    """
    Collects normalised Sysmon event dicts, serializes them to in-memory
    Parquet, then ships to the Nexus middleware ingress via HTTPS POST.

    Thread-safe: a background timer flushes the buffer every flush_interval_s
    seconds even if max_batch_rows has not been reached.
    """

    def __init__(self):
        self.middleware_url    = os.environ.get(
            "NEXUS_MIDDLEWARE_URL",
            "https://middleware.internal:8443/api/v1/telemetry"
        )
        self.auth_token        = os.environ.get("NEXUS_AUTH_TOKEN", "ChangeMe-Rotate-In-Production")
        self.integrity_secret  = os.environ.get("NEXUS_INTEGRITY_SECRET", "Nexus-Integrity-SharedKey-Rotate-Me").encode()
        self.sensor_id         = os.environ.get("NEXUS_SENSOR_ID", socket.gethostname())
        self.max_batch_rows    = int(os.environ.get("NEXUS_MAX_BATCH_ROWS", "500"))
        self.flush_interval_s  = int(os.environ.get("NEXUS_FLUSH_INTERVAL_S", "30"))
        self.tls_verify           = os.environ.get("NEXUS_TLS_VERIFY", "true").lower() == "true"
        self.initial_backoff_s    = float(os.environ.get("NEXUS_INITIAL_BACKOFF_S",  "2.0"))
        self.max_backoff_s        = float(os.environ.get("NEXUS_MAX_BACKOFF_S",     "60.0"))
        self._current_backoff     = self.initial_backoff_s

        # S3 direct mode (air-gap fallback)
        self.s3_endpoint = os.environ.get("NEXUS_S3_ENDPOINT", "")
        self.s3_bucket   = os.environ.get("NEXUS_S3_BUCKET",   "nexus-cold-storage")
        self.s3_key      = os.environ.get("MINIO_ACCESS_KEY",  "")
        self.s3_secret   = os.environ.get("MINIO_SECRET_KEY",  "")

        self._lock         = threading.Lock()
        self._buffer: List[dict] = []
        self._sequence     = 0

        self._timer = threading.Timer(self.flush_interval_s, self._flush_on_timer)
        self._timer.daemon = True
        self._timer.start()

    # ── Public API ─────────────────────────────────────────────────────────────

    def submit(self, record: dict) -> None:
        """Enqueue a normalised Sysmon record dict. Thread-safe."""
        with self._lock:
            self._buffer.append(record)
            if len(self._buffer) >= self.max_batch_rows:
                self._flush_locked()

    def flush(self) -> None:
        """Force flush the current buffer. Thread-safe."""
        with self._lock:
            self._flush_locked()

    def shutdown(self) -> None:
        """Flush and cancel the background timer."""
        self._timer.cancel()
        self.flush()

    # ── Internal ───────────────────────────────────────────────────────────────

    def _flush_on_timer(self) -> None:
        self.flush()
        # Reschedule
        self._timer = threading.Timer(self.flush_interval_s, self._flush_on_timer)
        self._timer.daemon = True
        self._timer.start()

    def _flush_locked(self) -> None:
        """Must be called with self._lock held."""
        if not self._buffer:
            return
        batch  = self._buffer[:]
        self._buffer.clear()
        self._sequence += 1
        seq = self._sequence

        # Release lock before I/O
        threading.Thread(
            target=self._ship,
            args=(batch, seq),
            daemon=True,
        ).start()

    def _compute_backoff(self, response=None) -> float:
        """Return a backoff duration and advance the cap. Respects Retry-After on 503/429."""
        if response is not None and response.status_code in (503, 429):
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = min(float(retry_after), self.max_backoff_s)
                    logger.info(f"Retry-After={wait:.0f}s honoured")
                    return wait
                except ValueError:
                    pass
        wait = random.uniform(0, self._current_backoff)
        self._current_backoff = min(self._current_backoff * 2, self.max_backoff_s)
        return wait

    def _ship(self, batch: List[dict], sequence: int) -> None:
        """Serialize batch to Parquet and POST to middleware (or S3 fallback)."""
        try:
            parquet_bytes = self._to_parquet(batch)
        except Exception as e:
            logger.error(f"Parquet serialization failed: {e}")
            return

        ts   = int(time.time())
        hmac_val = self._compute_hmac(parquet_bytes, sequence, ts)

        headers = {
            "Authorization":      f"Bearer {self.auth_token}",
            "Content-Type":       "application/vnd.apache.parquet",
            "X-Sensor-Type":      SENSOR_TYPE,
            "X-Sensor-Id":        self.sensor_id,
            "X-Batch-Sequence":   str(sequence),
            "X-Batch-Timestamp":  str(ts),
            "X-Batch-HMAC":       hmac_val,
        }

        try:
            resp = requests.post(
                self.middleware_url,
                data=parquet_bytes,
                headers=headers,
                verify=self.tls_verify,
                timeout=30,
            )
            if resp.status_code in (200, 202):
                logger.debug(f"Shipped {len(batch)} events (seq={sequence})")
                self._current_backoff = self.initial_backoff_s  # reset on success
            elif resp.status_code == 403:
                logger.error(
                    "[INTEGRITY] Middleware 403 -- sensor may be banned. "
                    "Check NEXUS_INTEGRITY_SECRET and sensor_id."
                )
                # Do not retry a 403; it indicates a permanent auth failure.
            else:
                wait = self._compute_backoff(resp)
                logger.warning(
                    f"Middleware returned {resp.status_code} -- backing off {wait:.1f}s: "
                    f"{resp.text[:120]}"
                )
                time.sleep(wait)
                if self.s3_endpoint:
                    self._ship_s3_direct(parquet_bytes, len(batch))
        except requests.RequestException as e:
            wait = self._compute_backoff()
            logger.error(f"Middleware POST failed -- backing off {wait:.1f}s: {e}")
            time.sleep(wait)
            if self.s3_endpoint:
                self._ship_s3_direct(parquet_bytes, len(batch))

    def _to_parquet(self, batch: List[dict]) -> bytes:
        """Convert a list of record dicts to Parquet bytes using the SCHEMA."""
        rows = {field.name: [] for field in SCHEMA}

        for event in batch:
            # Compute ML feature vector (6D windows_math)
            cmd_ent, pc_score, int_score, anomaly, ga_score, dt_score = compute_features(event)

            for field in SCHEMA:
                name = field.name
                if name == "command_entropy":
                    rows[name].append(cmd_ent)
                elif name == "parent_child_score":
                    rows[name].append(pc_score)
                elif name == "integrity_score":
                    rows[name].append(int_score)
                elif name == "anomaly_score":
                    rows[name].append(anomaly)
                elif name == "grant_access_score":
                    rows[name].append(ga_score)
                elif name == "driver_trust_score":
                    rows[name].append(dt_score)
                elif name == "payload_raw":
                    rows[name].append(json.dumps(event, default=str))
                elif name == "sensor_type":
                    rows[name].append(SENSOR_TYPE)
                elif name == "sensor_id":
                    rows[name].append(self.sensor_id)
                else:
                    val = event.get(name)
                    # Type coercion for Parquet
                    if field.type == pa.bool_():
                        rows[name].append(bool(val) if val is not None else None)
                    elif field.type == pa.int32():
                        try:
                            rows[name].append(int(val) if val is not None else None)
                        except (ValueError, TypeError):
                            rows[name].append(None)
                    elif field.type == pa.float64():
                        try:
                            rows[name].append(float(val) if val is not None else None)
                        except (ValueError, TypeError):
                            rows[name].append(None)
                    else:
                        rows[name].append(str(val) if val is not None else None)

        table = pa.table(rows, schema=SCHEMA)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd", compression_level=3)
        return buf.getvalue()

    def _compute_hmac(self, payload: bytes, sequence: int, timestamp: int) -> str:
        """HMAC-SHA256(payload || seq_u64_be || sensor_id_bytes || ts_u64_be).

        Must match middleware/src/core_ingress/src/integrity.rs::compute_hmac exactly:
          mac.update(payload)
          mac.update(&seq.to_be_bytes())    // 8-byte big-endian u64
          mac.update(sensor_id.as_bytes())  // raw UTF-8 bytes
          mac.update(&ts.to_be_bytes())     // 8-byte big-endian u64
        """
        import struct
        mac = hmac.new(self.integrity_secret, digestmod=hashlib.sha256)
        mac.update(payload)
        mac.update(struct.pack(">Q", sequence))        # big-endian uint64
        mac.update(self.sensor_id.encode("utf-8"))
        mac.update(struct.pack(">Q", timestamp))       # big-endian uint64
        return mac.hexdigest()

    def _ship_s3_direct(self, parquet_bytes: bytes, row_count: int) -> None:
        """Air-gap fallback: write directly to S3/MinIO if middleware is down."""
        if not self.s3_endpoint:
            return
        try:
            import boto3
            from botocore.config import Config

            s3 = boto3.client(
                "s3",
                endpoint_url=self.s3_endpoint,
                aws_access_key_id=self.s3_key,
                aws_secret_access_key=self.s3_secret,
                config=Config(signature_version="s3v4"),
            )
            now  = datetime.now(timezone.utc)
            key  = (
                f"telemetry/{SENSOR_TYPE}/"
                f"dt={now.strftime('%Y-%m-%d')}/"
                f"hour={now.strftime('%H')}/"
                f"{uuid.uuid4()}.parquet"
            )
            s3.put_object(Bucket=self.s3_bucket, Key=key, Body=parquet_bytes)
            logger.info(f"S3 direct: {row_count} rows → s3://{self.s3_bucket}/{key}")
        except Exception as e:
            logger.error(f"S3 direct fallback failed: {e}")
