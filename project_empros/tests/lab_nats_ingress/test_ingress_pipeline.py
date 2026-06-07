"""
Lab 3: Sensor → Ingress → NATS Integrity Pipeline
===================================================

Validates the full sensor transmission path:
  Parquet → HMAC stamp → POST /api/v1/telemetry → integrity check → NATS JetStream

What it proves:
  - HMAC-SHA256 signing from sensor matches ingress verification
  - Sequence counter gap detection works (out-of-order and replay)
  - Cross-OS collision detection fires correctly (→ 403 + ban)
  - Temporal drift rejection works (timestamps >120s stale)
  - Valid payloads publish to NATS JetStream subject nexus.{type}.telemetry
  - Invalid payloads are rejected with correct HTTP status codes

Prerequisites:
  docker compose -f tests/lab_nats_ingress/docker-compose.yml up -d
  pip install -r tests/lab_nats_ingress/requirements.txt

Run:
  pytest tests/lab_nats_ingress/test_ingress_pipeline.py -v
"""

import asyncio
import hashlib
import hmac as hmac_lib
import io
import os
import struct
import time
import uuid

import jwt
import nats
import nats.js.api
import nats.js.errors
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import requests

# ── Environment ───────────────────────────────────────────────────────────────

INGRESS_URL     = os.getenv("INGRESS_URL",  "http://localhost:8080")
NATS_URL        = os.getenv("NATS_URL",     "nats://localhost:4222")
JWT_SECRET      = os.getenv("JWT_SECRET",   "lab3-test-jwt-secret")
HMAC_SECRET     = os.getenv("INTEGRITY_HMAC_SECRET", "lab3-test-integrity-secret")

TELEMETRY_PATH  = "/api/v1/telemetry"

# Session-unique prefix prevents sequence replay from a prior run against the
# same ingress container (which retains in-memory sensor state).
_RUN_ID = uuid.uuid4().hex[:8]

# ── Helpers ───────────────────────────────────────────────────────────────────

def make_jwt() -> str:
    return jwt.encode(
        {"sub": "lab3-sensor", "exp": int(time.time()) + 3600, "aud": "nexus-ingress"},
        JWT_SECRET,
        algorithm="HS256",
    )


def compute_hmac(parquet_bytes: bytes, sequence: int, sensor_id: str,
                 timestamp: int, secret: str = HMAC_SECRET) -> str:
    mac = hmac_lib.new(secret.encode(), digestmod=hashlib.sha256)
    mac.update(parquet_bytes)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode())
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()


def make_parquet(records: list[dict]) -> bytes:
    df = pd.DataFrame(records)
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf, compression="zstd")
    return buf.getvalue()


def make_headers(
    parquet_bytes: bytes,
    sensor_type: str,
    sensor_id: str = "lab3-host-01",
    sequence: int = 1,
    timestamp: int | None = None,
    hmac_override: str | None = None,
) -> dict:
    ts  = timestamp if timestamp is not None else int(time.time())
    sig = hmac_override or compute_hmac(parquet_bytes, sequence, sensor_id, ts)
    return {
        "Authorization":     f"Bearer {make_jwt()}",
        "Content-Type":      "application/vnd.apache.parquet",
        "X-Sensor-Type":     sensor_type,
        "X-Sensor-Id":       sensor_id,
        "X-Batch-Sequence":  str(sequence),
        "X-Batch-Timestamp": str(ts),
        "X-Batch-HMAC":      sig,
    }


def post_telemetry(parquet_bytes: bytes, headers: dict) -> requests.Response:
    return requests.post(
        f"{INGRESS_URL}{TELEMETRY_PATH}",
        data=parquet_bytes,
        headers=headers,
        timeout=10,
    )


# ── Canonical test records ────────────────────────────────────────────────────
# Column names match nexus.toml schema_mappings exactly.

SYSMON_RECORD = {
    "sensor_type":        "sysmon_sensor",
    "sensor_id":          "WIN-LAB3-01",
    "timestamp":          str(int(time.time())),
    "sysmon_event_id":    1,
    "Image":              "powershell.exe",
    "CommandLine":        "powershell.exe -enc aQBlAHgA",
    "ParentImage":        "WINWORD.EXE",
    "User":               "CORP\\jsmith",
    "IntegrityLevel":     "Medium",
    "ProcessId":          1234,
    "command_entropy":    0.85,
    "parent_child_score": 0.75,
    "integrity_score":    0.33,
    "anomaly_score":      0.50,
    "grant_access_score": 0.0,
    "driver_trust_score": 0.0,
}

LINUX_SENTINEL_RECORD = {
    "endpoint_id":        "linux-srv-lab3",
    "sensor_id":          "linux-sentinel-lab3",
    "event_id":           str(uuid.uuid4()),
    "timestamp":          str(int(time.time())),
    "level":              "HIGH",
    "mitre_tactic":       "TA0004",
    "mitre_technique":    "T1068",
    "pid":                12345,
    "ppid":               1,
    "uid":                1001,
    "comm":               "unshare",
    "command_line":       "unshare -Urm",
    "parent_comm":        "bash",
    "user_name":          "www-data",
    "shannon_entropy":    0.72,
    "execution_velocity": 0.45,
    "tuple_rarity":       0.88,
    "path_depth":         4,
    "anomaly_score":      0.55,
    "message":            "Privilege escalation via OverlayFS",
}


# ── Session-scoped setup: NATS streams must exist before ingress can publish ──

@pytest.fixture(scope="session", autouse=True)
def wait_for_services():
    """Block until core_ingress /healthz responds (max 60s)."""
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            r = requests.get(f"{INGRESS_URL}/healthz", timeout=2)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(1)
    else:
        pytest.fail("core_ingress did not become healthy within 60s")


@pytest.fixture(scope="session", autouse=True)
def setup_nats_streams(wait_for_services):  # noqa: F811
    """Create JetStream streams so ingress publish calls succeed."""
    async def _create():
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()
        for name, subjects in [
            ("Tier5_Telemetry",    ["nexus.*.telemetry"]),
            ("Nexus_Math_Alerts",  ["nexus.alerts.math"]),
            ("Nexus_DLQ",          ["nexus.dlq.>"]),
        ]:
            try:
                await js.add_stream(name=name, subjects=subjects)
            except nats.js.errors.BadRequestError:
                pass  # already exists from a prior run
        await nc.close()

    asyncio.run(_create())


# ── Suite 1: Basic gateway checks ─────────────────────────────────────────────

class TestGatewayHealth:
    def test_healthz_returns_200(self):
        r = requests.get(f"{INGRESS_URL}/healthz", timeout=5)
        assert r.status_code == 200

    def test_no_auth_returns_401(self):
        buf = make_parquet([SYSMON_RECORD])
        hdrs = make_headers(buf, "sysmon_sensor")
        hdrs.pop("Authorization")
        r = post_telemetry(buf, hdrs)
        assert r.status_code == 401

    def test_invalid_token_returns_401(self):
        buf = make_parquet([SYSMON_RECORD])
        hdrs = make_headers(buf, "sysmon_sensor")
        hdrs["Authorization"] = "Bearer this.is.garbage"
        r = post_telemetry(buf, hdrs)
        assert r.status_code == 401

    def test_wrong_content_type_returns_415(self):
        buf = make_parquet([SYSMON_RECORD])
        hdrs = make_headers(buf, "sysmon_sensor")
        hdrs["Content-Type"] = "application/json"
        r = post_telemetry(buf, hdrs)
        assert r.status_code == 415


# ── Suite 2: Missing integrity headers ────────────────────────────────────────

class TestMissingHeaders:
    def _post_without(self, header_key: str) -> requests.Response:
        buf  = make_parquet([SYSMON_RECORD])
        hdrs = make_headers(buf, "sysmon_sensor", sensor_id=f"missing-hdr-{_RUN_ID}")
        hdrs.pop(header_key)
        return post_telemetry(buf, hdrs)

    def test_missing_sensor_id_returns_400(self):
        assert self._post_without("X-Sensor-Id").status_code == 400

    def test_missing_hmac_returns_400(self):
        assert self._post_without("X-Batch-HMAC").status_code == 400

    def test_missing_sequence_returns_400(self):
        assert self._post_without("X-Batch-Sequence").status_code == 400

    def test_missing_timestamp_returns_400(self):
        assert self._post_without("X-Batch-Timestamp").status_code == 400


# ── Suite 3: HMAC integrity verification ──────────────────────────────────────

class TestHMACIntegrity:
    def test_valid_hmac_accepted_202(self):
        buf  = make_parquet([SYSMON_RECORD])
        hdrs = make_headers(buf, "sysmon_sensor", sensor_id=f"hmac-valid-{_RUN_ID}", sequence=1)
        r    = post_telemetry(buf, hdrs)
        assert r.status_code == 202, f"Expected 202, got {r.status_code}"

    def test_tampered_payload_returns_400(self):
        buf  = make_parquet([SYSMON_RECORD])
        hdrs = make_headers(buf, "sysmon_sensor", sensor_id="hmac-tamper-01", sequence=1)
        tampered = buf[:-1] + bytes([buf[-1] ^ 0xFF])
        r = post_telemetry(tampered, hdrs)
        assert r.status_code == 400

    def test_wrong_secret_returns_400(self):
        buf  = make_parquet([SYSMON_RECORD])
        bad_sig = compute_hmac(buf, 1, f"hmac-wrong-secret-{_RUN_ID}", int(time.time()), secret="wrong-secret")
        hdrs = make_headers(buf, "sysmon_sensor", sensor_id=f"hmac-wrong-secret-{_RUN_ID}",
                            sequence=1, hmac_override=bad_sig)
        r = post_telemetry(buf, hdrs)
        assert r.status_code == 400

    def test_hmac_binds_to_sequence(self):
        """HMAC signed for seq=1 must fail for seq=2."""
        buf = make_parquet([SYSMON_RECORD])
        ts  = int(time.time())
        sid = f"hmac-seq-bind-{_RUN_ID}"
        sig_for_seq1 = compute_hmac(buf, 1, sid, ts)
        # Present seq=2 in header but HMAC was computed for seq=1
        hdrs = make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=2,
                            timestamp=ts, hmac_override=sig_for_seq1)
        r = post_telemetry(buf, hdrs)
        assert r.status_code == 400

    def test_linux_sentinel_hmac_valid(self):
        buf  = make_parquet([LINUX_SENTINEL_RECORD])
        hdrs = make_headers(buf, "linux_sentinel", sensor_id=f"sentinel-hmac-{_RUN_ID}", sequence=1)
        r    = post_telemetry(buf, hdrs)
        assert r.status_code == 202


# ── Suite 4: Temporal drift rejection ─────────────────────────────────────────

class TestTemporalDrift:
    MAX_SKEW = 120  # must match integrity.rs MAX_CLOCK_SKEW_SECS

    def test_stale_timestamp_returns_400(self):
        buf  = make_parquet([SYSMON_RECORD])
        old_ts = int(time.time()) - self.MAX_SKEW - 5
        hdrs = make_headers(buf, "sysmon_sensor", sensor_id=f"drift-stale-{_RUN_ID}",
                            sequence=1, timestamp=old_ts)
        r = post_telemetry(buf, hdrs)
        assert r.status_code == 400, f"Stale batch should be rejected, got {r.status_code}"

    def test_future_timestamp_returns_400(self):
        buf    = make_parquet([SYSMON_RECORD])
        future = int(time.time()) + self.MAX_SKEW + 5
        hdrs   = make_headers(buf, "sysmon_sensor", sensor_id=f"drift-future-{_RUN_ID}",
                              sequence=1, timestamp=future)
        r = post_telemetry(buf, hdrs)
        assert r.status_code == 400

    def test_within_skew_window_accepted(self):
        buf  = make_parquet([SYSMON_RECORD])
        ts   = int(time.time()) - (self.MAX_SKEW // 2)
        hdrs = make_headers(buf, "sysmon_sensor", sensor_id=f"drift-valid-{_RUN_ID}",
                            sequence=1, timestamp=ts)
        r = post_telemetry(buf, hdrs)
        assert r.status_code == 202


# ── Suite 5: Sequence counter enforcement ─────────────────────────────────────

class TestSequenceCounters:
    def test_sequential_batches_accepted(self):
        sid = f"seq-linear-{uuid.uuid4().hex[:8]}"
        buf = make_parquet([SYSMON_RECORD])
        for seq in (1, 2, 3):
            hdrs = make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=seq)
            r    = post_telemetry(buf, hdrs)
            assert r.status_code == 202, f"seq={seq} rejected: {r.status_code}"

    def test_replay_same_sequence_returns_400(self):
        sid = f"seq-replay-{uuid.uuid4().hex[:8]}"
        buf = make_parquet([SYSMON_RECORD])
        # seq=1 accepted
        r1 = post_telemetry(buf, make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=1))
        assert r1.status_code == 202
        # seq=1 again → replay
        r2 = post_telemetry(buf, make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=1))
        assert r2.status_code == 400, f"Replay should be rejected, got {r2.status_code}"

    def test_out_of_order_sequence_returns_400(self):
        """Send seq=5 then seq=3 -- going backwards must be rejected."""
        sid = f"seq-ooo-{uuid.uuid4().hex[:8]}"
        buf = make_parquet([SYSMON_RECORD])
        r1 = post_telemetry(buf, make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=5))
        assert r1.status_code == 202
        r2 = post_telemetry(buf, make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=3))
        assert r2.status_code == 400, f"Out-of-order seq should be rejected, got {r2.status_code}"

    def test_gap_with_higher_sequence_accepted(self):
        """seq=1 then seq=10 (gap) is valid -- gaps are not contiguous-only enforced."""
        sid = f"seq-gap-{uuid.uuid4().hex[:8]}"
        buf = make_parquet([SYSMON_RECORD])
        r1  = post_telemetry(buf, make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=1))
        r2  = post_telemetry(buf, make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=10))
        assert r1.status_code == 202
        assert r2.status_code == 202


# ── Suite 6: Cross-OS collision detection ────────────────────────────────────

class TestCrossOsCollision:
    def _linux_sentinel_with_windows_cols(self) -> bytes:
        """Build a Parquet claiming to be linux_sentinel but containing
        windows-exclusive columns -- must trigger collision detection → 403."""
        record = {
            **LINUX_SENTINEL_RECORD,
            # These are in linux_sentinel's exclusion set (integrity.rs)
            "Image":          "powershell.exe",
            "CommandLine":    "powershell.exe -enc aQBlAHgA",
            "signature_name": "YARA_beacon",
        }
        return make_parquet([record])

    def test_cross_os_returns_403(self):
        sid = f"cross-os-{uuid.uuid4().hex[:8]}"
        buf = self._linux_sentinel_with_windows_cols()
        hdrs = make_headers(buf, "linux_sentinel", sensor_id=sid, sequence=1)
        r    = post_telemetry(buf, hdrs)
        assert r.status_code == 403, f"Cross-OS collision must return 403, got {r.status_code}"

    def test_banned_sensor_returns_403_on_retry(self):
        """After cross-OS ban, subsequent valid requests from same sensor must fail."""
        sid = f"ban-retry-{uuid.uuid4().hex[:8]}"
        buf = self._linux_sentinel_with_windows_cols()
        hdrs = make_headers(buf, "linux_sentinel", sensor_id=sid, sequence=1)
        post_telemetry(buf, hdrs)  # triggers ban

        # Now send a clean valid payload from the same sensor_id
        clean_buf  = make_parquet([LINUX_SENTINEL_RECORD])
        clean_hdrs = make_headers(clean_buf, "linux_sentinel", sensor_id=sid, sequence=2)
        r = post_telemetry(clean_buf, clean_hdrs)
        assert r.status_code == 403, f"Banned sensor must stay banned, got {r.status_code}"

    def test_network_tap_with_endpoint_cols_returns_403(self):
        """network_tap records must not carry endpoint process columns."""
        record = {
            "session_id":     str(uuid.uuid4()),
            "tls_ja3":        "abc123",
            "byte_ratio":     0.85,
            "src_ip":         "10.0.0.1",
            "timestamp_start": str(int(time.time())),
            "sensor_name":    "tap-lab3",
            # These are in network_tap's exclusion set
            "pid":            1234,
            "comm":           "nc",
            "shannon_entropy": 0.7,
        }
        sid = f"nettap-col-{uuid.uuid4().hex[:8]}"
        buf  = make_parquet([record])
        hdrs = make_headers(buf, "network_tap", sensor_id=sid, sequence=1)
        r    = post_telemetry(buf, hdrs)
        assert r.status_code == 403


# ── Suite 7: NATS message delivery verification ───────────────────────────────

class TestNatsDelivery:
    """Verify that valid payloads land in JetStream after the ingress accepts them."""

    def _publish_and_subscribe(self, sensor_type: str, sensor_id: str,
                                record: dict, sequence: int = 1) -> bytes | None:
        async def _run():
            nc  = await nats.connect(NATS_URL)
            js  = nc.jetstream()

            # DeliverPolicy.NEW so prior stream messages don't replay into this sub
            new_cfg = nats.js.api.ConsumerConfig(
                deliver_policy=nats.js.api.DeliverPolicy.NEW
            )
            sub = await js.subscribe(f"nexus.{sensor_type}.telemetry",
                                      stream="Tier5_Telemetry", config=new_cfg)

            buf  = make_parquet([record])
            hdrs = make_headers(buf, sensor_type, sensor_id=sensor_id,
                                sequence=sequence)
            resp = requests.post(f"{INGRESS_URL}{TELEMETRY_PATH}",
                                  data=buf, headers=hdrs, timeout=10)
            assert resp.status_code == 202, f"POST returned {resp.status_code}"

            try:
                msg = await asyncio.wait_for(sub.next_msg(), timeout=8.0)
                payload = msg.data
                await msg.ack()
            except asyncio.TimeoutError:
                payload = None

            await sub.unsubscribe()
            await nc.close()
            return payload

        return asyncio.run(_run())

    def test_sysmon_batch_lands_in_jetstream(self):
        payload = self._publish_and_subscribe(
            "sysmon_sensor", f"nats-sysmon-{uuid.uuid4().hex[:8]}", SYSMON_RECORD, sequence=50)
        assert payload is not None, "sysmon batch did not arrive in NATS within timeout"
        assert len(payload) > 0

    def test_linux_sentinel_batch_lands_in_jetstream(self):
        payload = self._publish_and_subscribe(
            "linux_sentinel", f"nats-sentinel-{uuid.uuid4().hex[:8]}", LINUX_SENTINEL_RECORD, sequence=50)
        assert payload is not None, "linux_sentinel batch did not arrive in NATS within timeout"

    def test_nats_subject_matches_sensor_type(self):
        """Subject nexus.sysmon_sensor.telemetry must carry the sysmon batch -- not another subject."""
        async def _run():
            nc  = await nats.connect(NATS_URL)
            js  = nc.jetstream()

            new_cfg = nats.js.api.ConsumerConfig(
                deliver_policy=nats.js.api.DeliverPolicy.NEW
            )
            sub_wrong = await js.subscribe("nexus.linux_sentinel.telemetry",
                                            stream="Tier5_Telemetry",
                                            config=new_cfg)

            buf  = make_parquet([SYSMON_RECORD])
            sid  = f"nats-route-{uuid.uuid4().hex[:8]}"
            hdrs = make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=60)
            requests.post(f"{INGRESS_URL}{TELEMETRY_PATH}", data=buf, headers=hdrs, timeout=10)

            # Should NOT receive on linux_sentinel subject
            received = False
            try:
                await asyncio.wait_for(sub_wrong.next_msg(), timeout=2.0)
                received = True
            except asyncio.TimeoutError:
                pass

            await sub_wrong.unsubscribe()
            await nc.close()
            assert not received, "sysmon batch incorrectly routed to linux_sentinel subject"

        asyncio.run(_run())

    def test_nats_message_contains_sensor_id_header(self):
        """Forwarded NATS message must preserve the X-Sensor-Id header."""
        async def _run():
            sid = f"nats-hdr-{uuid.uuid4().hex[:8]}"
            nc  = await nats.connect(NATS_URL)
            js  = nc.jetstream()

            # Start from NEW so prior stream messages don't interfere
            new_cfg = nats.js.api.ConsumerConfig(
                deliver_policy=nats.js.api.DeliverPolicy.NEW
            )
            sub = await js.subscribe("nexus.sysmon_sensor.telemetry",
                                      stream="Tier5_Telemetry", config=new_cfg)

            buf  = make_parquet([SYSMON_RECORD])
            hdrs = make_headers(buf, "sysmon_sensor", sensor_id=sid, sequence=70)
            requests.post(f"{INGRESS_URL}{TELEMETRY_PATH}", data=buf, headers=hdrs, timeout=10)

            msg = await asyncio.wait_for(sub.next_msg(), timeout=8.0)
            await msg.ack()
            await sub.unsubscribe()
            await nc.close()

            assert msg.headers is not None, "NATS message missing forwarded headers"
            forwarded_sid = msg.headers.get("X-Sensor-Id")
            assert forwarded_sid == sid, f"Sensor-Id not forwarded: {forwarded_sid}"

        asyncio.run(_run())
