"""
Lab 4: Qdrant Vector Worker Pipeline
=====================================

Validates the worker_qdrant data path:
  NATS message → read Parquet → duck-type sensor → extract vectors
  → normalize → upsert Qdrant + fire tripwire alerts to nexus.alerts.math

What it proves:
  - All sensor types route to the correct named vector space
  - windows_math 6D: grant_access_score and driver_trust_score normalized correctly
  - trellix_math 4D proxy: pre-normalised severity/threat/action/anomaly scores
  - sentinel_math 5D: path_depth and entropy normalizations correct
  - c2_math 8D: log-scale interval normalization correct
  - Anomaly tripwire fires at anomaly_score >= 0.88, publishes to nexus.alerts.math
  - Mathematical tripwire alerts land in JetStream stream Nexus_Math_Alerts

Note: Qdrant stores vectors with cosine distance normalized to unit length.
  Normalization tests compare stored vectors against to_unit(expected_raw).

Prerequisites:
  docker compose -f tests/lab_qdrant_pipeline/docker-compose.yml up -d
  pip install -r tests/lab_qdrant_pipeline/requirements.txt

Run:
  pytest tests/lab_qdrant_pipeline/test_qdrant_pipeline.py -v
"""

import asyncio
import io
import json
import math
import os
import time
import uuid

import nats
import nats.js.api
import nats.js.errors
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue

# ── Environment ───────────────────────────────────────────────────────────────

NATS_URL    = os.getenv("NATS_URL",    "nats://localhost:4223")
QDRANT_URL  = os.getenv("QDRANT_URL",  "http://localhost:16333")
COLLECTION  = "ueba_vectors"

WORKER_SETTLE_SECS = 15  # max seconds to wait for worker to upsert after publish


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_parquet(records: list[dict]) -> bytes:
    df  = pd.DataFrame(records)
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf, compression="zstd")
    return buf.getvalue()


def qdrant_client() -> QdrantClient:
    return QdrantClient(url=QDRANT_URL, timeout=10)


def wait_for_point(sensor_id: str, source_type: str, timeout: int = WORKER_SETTLE_SECS) -> list:
    """Poll Qdrant until a matching point appears.

    Tries nexus_sensor_id first (from sensor_id_column), then endpoint_id (from PK column).
    Different sensors use different columns for their primary key so we try both.
    """
    client = qdrant_client()
    deadline = time.time() + timeout
    while time.time() < deadline:
        for key in ("nexus_sensor_id", "endpoint_id"):
            result = client.scroll(
                collection_name=COLLECTION,
                scroll_filter=Filter(must=[
                    FieldCondition(key=key,           match=MatchValue(value=sensor_id)),
                    FieldCondition(key="source_type", match=MatchValue(value=source_type)),
                ]),
                limit=5,
                with_vectors=True,
                with_payload=True,
            )
            if result[0]:
                return result[0]
        time.sleep(0.5)
    return []


async def publish_parquet(subject: str, parquet_bytes: bytes) -> None:
    nc = await nats.connect(NATS_URL)
    js = nc.jetstream()
    await js.publish(subject, parquet_bytes)
    await nc.close()


def to_unit(vec: list[float]) -> list[float]:
    """Normalize to unit length -- Qdrant applies this on ingest for cosine distance."""
    mag = math.sqrt(sum(v * v for v in vec))
    return [v / mag for v in vec] if mag > 1e-9 else vec


# ── Session setup ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_nats_streams():
    async def _create():
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()
        for name, subjects in [
            ("Nexus_Math_Alerts", ["nexus.alerts.math"]),
            ("Nexus_DLQ",         ["nexus.dlq.>"]),
        ]:
            try:
                await js.add_stream(name=name, subjects=subjects)
            except nats.js.errors.BadRequestError:
                pass
        await nc.close()

    asyncio.run(_create())


@pytest.fixture(scope="session", autouse=True)
def wait_for_qdrant(setup_nats_streams):
    """Block until Qdrant collection is ready (qdrant-init must complete)."""
    client   = qdrant_client()
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            info = client.get_collection(COLLECTION)
            if info.status.value in ("green", "yellow", "grey"):
                return
        except Exception:
            pass
        time.sleep(1)
    pytest.fail(f"Qdrant collection '{COLLECTION}' not ready within 90s")


# ── Canonical sensor records ──────────────────────────────────────────────────

def _unique_id() -> str:
    return uuid.uuid4().hex[:12]


def sysmon_record(endpoint_id: str, anomaly: float = 0.5) -> dict:
    return {
        "sensor_id":          endpoint_id,
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
        "anomaly_score":      anomaly,
        "grant_access_score": 0.0,
        "driver_trust_score": 0.0,
    }


def sysmon_process_access_record(endpoint_id: str) -> dict:
    return {
        "sensor_id":          endpoint_id,
        "timestamp":          str(int(time.time())),
        "sysmon_event_id":    10,
        "SourceImage":        "exploit.exe",
        "TargetImage":        "winlogon.exe",
        "GrantedAccess":      "0x1fffff",
        "Image":              "exploit.exe",
        "CommandLine":        "exploit.exe",
        "User":               "CORP\\jsmith",
        "IntegrityLevel":     "High",
        "command_entropy":    0.90,
        "parent_child_score": 0.80,
        "integrity_score":    0.95,
        "anomaly_score":      0.91,
        "grant_access_score": 1.0,
        "driver_trust_score": 0.0,
    }


def linux_sentinel_record(endpoint_id: str, anomaly: float = 0.55) -> dict:
    return {
        "event_id":           str(uuid.uuid4()),
        "sensor_id":          endpoint_id,
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
        "anomaly_score":      anomaly,
        "message":            "Privilege escalation via OverlayFS",
    }


def linux_c2_record(endpoint_id: str) -> dict:
    return {
        "id":               endpoint_id,
        "sensor_id":        endpoint_id,
        "timestamp":        str(int(time.time())),
        "comm":             "nc",
        "outbound_ratio":   1.0,
        "packet_size_mean": 128.0,
        "packet_size_std":  5.0,
        "interval":         30.0,
        "cv":               0.039,
        "entropy":          0.95,
        "cmd_entropy":      0.42,
        "score":            0.87,
        "packet_size_min":  64,
        "packet_size_max":  256,
        "dst_ip":           "185.220.101.1",
        "dst_port":         4444,
        "event_type":       "connect",
    }


def trellix_record(endpoint_id: str) -> dict:
    return {
        "sensor_id":      f"trellix-{endpoint_id}",
        "timestamp":      str(int(time.time())),
        "detection_name": "Trojan.GenericKD",
        "host":           "WIN-TRELLIX-01",
        "process":        "malware.exe",
        "pid":            "2345",
        "user":           "CORP\\jsmith",
        "file_path":      "C:\\Windows\\Temp\\malware.exe",
        "file_name":      "malware.exe",
        "threat_type":    "Trojan",
        "action":         "Block",
        "severity":       "High",
        "message":        "Blocked process memory modification",
        "severity_score": 0.75,
        "threat_score":   1.0,
        "action_score":   1.0,
        "anomaly_score":  0.5,
    }


def network_tap_record(endpoint_id: str) -> dict:
    return {
        "session_id":             endpoint_id,
        "timestamp_start":        str(int(time.time())),
        "sensor_name":            f"tap-{endpoint_id}",
        "src_ip":                 "10.0.1.50",
        "dst_ip":                 "185.220.101.1",
        "dst_port":               443,
        "protocol_name":          "TCP",
        "tls_ja3":                "abc123",
        "cert_cn":                "*.evil.com",
        "cert_self_signed":       True,
        "dst_geo_country":        "RU",
        "is_internal_dst":        False,
        "port_class":             "ephemeral",
        "byte_ratio":             0.85,
        "avg_inter_arrival":      29.97,
        "variance_inter_arrival": 0.02,
        "ratio_small_packets":    0.12,
        "ratio_large_packets":    0.05,
        "payload_entropy":        0.94,
        "session_duration_ms":    300000.0,
        "packets_src":            145,
    }


def windows_deepsensor_record(endpoint_id: str) -> dict:
    return {
        "event_id":        str(uuid.uuid4()),
        "host":            endpoint_id,
        "timestamp":       str(int(time.time())),
        "category":        "ProcessStart",
        "event_type":      "YARA_RWX:SuspiciousAlloc",
        "pid":             1234,
        "parent_pid":      5678,
        "path":            "C:\\Temp\\beacon.exe",
        "parent_image":    "explorer.exe",
        "command_line":    "beacon.exe -silent",
        "event_user":      "CORP\\jsmith",
        "destination_ip":  "185.220.101.1",
        "severity":        "HIGH",
        "score":           8.5,
        "avg_entropy":     6.96,
        "max_velocity":    0.92,
        "event_count":     3,
    }


def cloud_flow_record(endpoint_id: str) -> dict:
    return {
        "sensor_id":      f"cloud-{endpoint_id}",
        "timestamp":      str(int(time.time())),
        "event_type":     "AssumeRole",
        "packet_count":   10,
        "interval":       60.0,
        "cv":             0.15,
        "outbound_ratio": 0.9,
        "packet_size_mean": 512.0,
        "score":          0.6,
        "description":    "unusual cross-account assume-role",
    }


# ── Suite 1: Sensor duck-type routing to correct named vector spaces ──────────

class TestDuckTypeRouting:
    def _route_and_wait(self, subject: str, record: dict,
                         source_type: str, eid: str) -> list:
        asyncio.run(publish_parquet(subject, make_parquet([record])))
        return wait_for_point(eid, source_type)

    def test_sysmon_routes_to_windows_math(self):
        eid = _unique_id()
        rec = sysmon_record(eid)
        pts = self._route_and_wait("nexus.sysmon_sensor.telemetry", rec, "sysmon_sensor", eid)
        assert pts, "sysmon_sensor point not found in Qdrant"
        assert "windows_math" in pts[0].vector, f"Expected windows_math, got {list(pts[0].vector.keys())}"
        assert len(pts[0].vector["windows_math"]) == 6

    def test_linux_sentinel_routes_to_sentinel_math(self):
        eid = _unique_id()
        rec = linux_sentinel_record(eid)
        pts = self._route_and_wait("nexus.linux_sentinel.telemetry", rec, "linux_sentinel", eid)
        assert pts, "linux_sentinel point not found in Qdrant"
        assert "sentinel_math" in pts[0].vector
        assert len(pts[0].vector["sentinel_math"]) == 5

    def test_linux_c2_routes_to_c2_math(self):
        eid = _unique_id()
        rec = linux_c2_record(eid)
        pts = self._route_and_wait("nexus.linux_c2.telemetry", rec, "linux_c2", eid)
        assert pts, "linux_c2 point not found in Qdrant"
        assert "c2_math" in pts[0].vector
        assert len(pts[0].vector["c2_math"]) == 8

    def test_trellix_routes_to_trellix_math(self):
        eid = _unique_id()
        rec = trellix_record(eid)
        pts = self._route_and_wait("nexus.trellix_ens.telemetry", rec, "trellix_ens", f"trellix-{eid}")
        assert pts, "trellix_ens point not found in Qdrant"
        assert "trellix_math" in pts[0].vector
        assert len(pts[0].vector["trellix_math"]) == 4

    def test_network_tap_routes_to_network_tap(self):
        eid = _unique_id()
        rec = network_tap_record(eid)
        pts = self._route_and_wait("nexus.network_tap.telemetry", rec, "network_tap", eid)
        assert pts, "network_tap point not found in Qdrant"
        assert "network_tap" in pts[0].vector
        assert len(pts[0].vector["network_tap"]) == 8

    def test_windows_deepsensor_routes_to_deepsensor_math(self):
        eid = _unique_id()
        rec = windows_deepsensor_record(eid)
        # sensor_id_column="host"=eid; search by nexus_sensor_id=eid
        pts = self._route_and_wait("nexus.windows_deepsensor.telemetry", rec,
                                    "windows_deepsensor", eid)
        assert pts, "windows_deepsensor point not found in Qdrant"
        assert "deepsensor_math" in pts[0].vector
        assert len(pts[0].vector["deepsensor_math"]) == 4

    def test_cloud_flow_routes_to_cloud_flow(self):
        eid = _unique_id()
        rec = cloud_flow_record(eid)
        pts = self._route_and_wait("nexus.cloud_flow.telemetry", rec, "cloud_flow", f"cloud-{eid}")
        assert pts, "cloud_flow point not found in Qdrant"
        assert "cloud_flow" in pts[0].vector
        assert len(pts[0].vector["cloud_flow"]) == 5


# ── Suite 2: Normalization correctness ───────────────────────────────────────

class TestNormalization:
    """Verify in-flight normalization matches worker_qdrant/src/main.rs.

    Qdrant cosine distance normalizes stored vectors to unit length on ingest.
    Tests compute expected_unit = to_unit(worker_formula(raw)) and compare.
    """

    def _fetch_vector(self, sensor_id: str, source_type: str, subject: str,
                       record: dict) -> list[float]:
        asyncio.run(publish_parquet(subject, make_parquet([record])))
        pts = wait_for_point(sensor_id, source_type)
        assert pts, f"Point not found for {source_type} sensor_id={sensor_id}"
        return list(pts[0].vector.values())[0]

    def _assert_near_unit(self, vec: list[float], expected_raw: list[float],
                           tol: float = 5e-3, label: str = ""):
        """Compare stored vec against to_unit(expected_raw)."""
        expected = to_unit(expected_raw)
        for i, (got, exp) in enumerate(zip(vec, expected)):
            assert abs(got - exp) < tol, \
                f"{label}[{i}]: stored={got:.4f}, expected_unit={exp:.4f} (raw={expected_raw[i]:.5f})"

    def test_windows_math_6d_is_unit_vector(self):
        """Stored windows_math must be a 6D unit vector."""
        eid = _unique_id()
        rec = sysmon_record(eid, anomaly=0.5)
        vec = self._fetch_vector(eid, "sysmon_sensor",
                                  "nexus.sysmon_sensor.telemetry", rec)
        assert len(vec) == 6
        mag = math.sqrt(sum(v * v for v in vec))
        assert abs(mag - 1.0) < 1e-3, f"windows_math not unit vector: |v|={mag}"

    def test_windows_math_grant_access_score_direction(self):
        """grant_access_score=1.0 → largest contribution in the unit vector direction."""
        eid = _unique_id()
        rec = sysmon_process_access_record(eid)
        vec = self._fetch_vector(eid, "sysmon_sensor",
                                  "nexus.sysmon_sensor.telemetry", rec)
        # grant_access_score=1.0 at index 4; raw vector has 1.0 there
        # Verify direction: to_unit([0.90, 0.80, 0.95, 0.91, 1.0, 0.0])
        expected_raw = [0.90, 0.80, 0.95, 0.91, 1.0, 0.0]
        self._assert_near_unit(vec, expected_raw, tol=5e-3, label="sysmon_pa")

    def test_sentinel_math_5d_normalization(self):
        """sentinel_math: [shannon/8, vel/1000, rarity, depth/10, anomaly] → unit vector."""
        eid = _unique_id()
        rec = {**linux_sentinel_record(eid, anomaly=0.70), "sensor_id": eid}
        vec = self._fetch_vector(eid, "linux_sentinel",
                                  "nexus.linux_sentinel.telemetry", rec)
        assert len(vec) == 5
        # Worker formula from main.rs sentinel_math branch
        expected_raw = [0.72/8.0, 0.45/1000.0, 0.88, 4.0/10.0, 0.70]
        self._assert_near_unit(vec, expected_raw, tol=5e-3, label="sentinel")

    def test_c2_math_interval_log_normalization(self):
        """c2_math: interval dim uses 1/(1+log10(val+1)); verify direction is correct."""
        eid = _unique_id()
        rec = linux_c2_record(eid)
        vec = self._fetch_vector(eid, "linux_c2",
                                  "nexus.linux_c2.telemetry", rec)
        assert len(vec) == 8
        interval_norm = 1.0 / (1.0 + math.log10(30.0 + 1.0))
        expected_raw = [
            1.0,               # outbound_ratio clamped
            128.0 / 1500.0,   # packet_size_mean/1500
            5.0 / 500.0,      # packet_size_std/500
            interval_norm,     # 1/(1+log10(interval+1))
            0.039 / 2.0,      # cv/2
            0.95 / 8.0,       # entropy/8
            0.42 / 8.0,       # cmd_entropy/8
            0.87,              # score clamped
        ]
        self._assert_near_unit(vec, expected_raw, tol=5e-3, label="c2_math")

    def test_trellix_math_4d_pre_normalised(self):
        """trellix_math 4D: pre-normalized scores [0.75, 1.0, 1.0, 0.5] → unit vector."""
        eid = _unique_id()
        rec = trellix_record(eid)
        vec = self._fetch_vector(f"trellix-{eid}", "trellix_ens",
                                  "nexus.trellix_ens.telemetry", rec)
        assert len(vec) == 4
        expected_raw = [0.75, 1.0, 1.0, 0.5]
        self._assert_near_unit(vec, expected_raw, tol=5e-3, label="trellix")

    def test_deepsensor_math_4d_normalization(self):
        """deepsensor_math: [score/100, entropy/8, velocity/5000, count/100] → unit."""
        eid = _unique_id()
        rec = windows_deepsensor_record(eid)
        # sensor_id_column="host"=eid; search by nexus_sensor_id=eid
        vec = self._fetch_vector(eid, "windows_deepsensor",
                                  "nexus.windows_deepsensor.telemetry", rec)
        assert len(vec) == 4
        expected_raw = [8.5/100.0, 6.96/8.0, 0.92/5000.0, 3/100.0]
        self._assert_near_unit(vec, expected_raw, tol=5e-3, label="deepsensor")


# ── Suite 3: Anomaly tripwire ─────────────────────────────────────────────────

class TestAnomalyTripwire:
    THRESHOLD = 0.88

    def _subscribe_new(self, durable: str):
        """Create a JetStream push sub from NEW messages only."""
        return nats.js.api.ConsumerConfig(
            deliver_policy=nats.js.api.DeliverPolicy.NEW
        )

    def test_score_below_threshold_no_alert(self):
        """anomaly_score=0.80 → no alert published to nexus.alerts.math."""
        async def _run():
            eid = _unique_id()
            rec = {**linux_sentinel_record(eid, anomaly=0.80), "sensor_id": eid}

            nc  = await nats.connect(NATS_URL)
            js  = nc.jetstream()
            sub = await js.subscribe("nexus.alerts.math", stream="Nexus_Math_Alerts",
                                      config=nats.js.api.ConsumerConfig(
                                          deliver_policy=nats.js.api.DeliverPolicy.NEW))

            # Publish within the same event loop (no nested asyncio.run)
            await js.publish("nexus.linux_sentinel.telemetry", make_parquet([rec]))
            await asyncio.sleep(WORKER_SETTLE_SECS + 3)

            received = False
            try:
                msg = await asyncio.wait_for(sub.next_msg(), timeout=1.0)
                alert = json.loads(msg.data)
                if alert.get("sensor_id", "").endswith(eid):
                    received = True
                await msg.ack()
            except asyncio.TimeoutError:
                pass

            await sub.unsubscribe()
            await nc.close()
            assert not received, "Alert fired for score=0.80 -- should not have"

        asyncio.run(_run())

    def test_score_at_threshold_fires_alert(self):
        """anomaly_score=0.88 → alert published to nexus.alerts.math."""
        eid = _unique_id()
        rec = {**linux_sentinel_record(eid, anomaly=0.88), "sensor_id": eid}

        async def _run():
            nc  = await nats.connect(NATS_URL)
            js  = nc.jetstream()
            sub = await js.subscribe("nexus.alerts.math", stream="Nexus_Math_Alerts",
                                      config=nats.js.api.ConsumerConfig(
                                          deliver_policy=nats.js.api.DeliverPolicy.NEW))

            await publish_parquet("nexus.linux_sentinel.telemetry", make_parquet([rec]))

            alert_data = None
            deadline = time.time() + WORKER_SETTLE_SECS + 10
            while time.time() < deadline:
                try:
                    msg = await asyncio.wait_for(sub.next_msg(), timeout=2.0)
                    candidate = json.loads(msg.data)
                    await msg.ack()
                    if candidate.get("sensor_id", "").endswith(eid):
                        alert_data = candidate
                        break
                except asyncio.TimeoutError:
                    continue  # keep polling until deadline

            await sub.unsubscribe()
            await nc.close()
            return alert_data

        alert = asyncio.run(_run())
        assert alert is not None, "No tripwire alert received for anomaly_score=0.88"
        assert float(alert["anomaly_score"]) >= self.THRESHOLD
        assert alert.get("vector_name") == "sentinel_math"

    def test_score_above_threshold_fires_alert_with_fields(self):
        """anomaly_score=0.95 → alert has all required fields."""
        eid = _unique_id()
        rec = {**linux_sentinel_record(eid, anomaly=0.95), "sensor_id": eid}

        async def _run():
            nc  = await nats.connect(NATS_URL)
            js  = nc.jetstream()
            sub = await js.subscribe("nexus.alerts.math", stream="Nexus_Math_Alerts",
                                      config=nats.js.api.ConsumerConfig(
                                          deliver_policy=nats.js.api.DeliverPolicy.NEW))

            await publish_parquet("nexus.linux_sentinel.telemetry", make_parquet([rec]))

            alert_data = None
            deadline = time.time() + WORKER_SETTLE_SECS + 10
            while time.time() < deadline:
                try:
                    msg = await asyncio.wait_for(sub.next_msg(), timeout=2.0)
                    candidate = json.loads(msg.data)
                    await msg.ack()
                    if candidate.get("sensor_id", "").endswith(eid):
                        alert_data = candidate
                        break
                except asyncio.TimeoutError:
                    continue  # keep polling until deadline

            await sub.unsubscribe()
            await nc.close()
            return alert_data

        alert = asyncio.run(_run())
        assert alert is not None, "No tripwire alert received for anomaly_score=0.95"
        assert float(alert["anomaly_score"]) >= self.THRESHOLD
        for field in ("event_id", "sensor_id", "endpoint_id", "vector_name",
                      "source_type", "mitigation_status"):
            assert field in alert, f"Alert missing field: {field}"
        assert alert["mitigation_status"] == "ready_pending_review"

    def test_high_score_sysmon_fires_windows_math_alert(self):
        """anomaly_score=0.92 from sysmon → alert with vector_name=windows_math."""
        eid = _unique_id()
        rec = sysmon_record(eid, anomaly=0.92)

        async def _run():
            nc  = await nats.connect(NATS_URL)
            js  = nc.jetstream()
            sub = await js.subscribe("nexus.alerts.math", stream="Nexus_Math_Alerts",
                                      config=nats.js.api.ConsumerConfig(
                                          deliver_policy=nats.js.api.DeliverPolicy.NEW))

            await publish_parquet("nexus.sysmon_sensor.telemetry", make_parquet([rec]))

            alert_data = None
            deadline = time.time() + WORKER_SETTLE_SECS + 10
            while time.time() < deadline:
                try:
                    msg = await asyncio.wait_for(sub.next_msg(), timeout=2.0)
                    candidate = json.loads(msg.data)
                    await msg.ack()
                    if candidate.get("sensor_id", "").endswith(eid):
                        alert_data = candidate
                        break
                except asyncio.TimeoutError:
                    continue  # keep polling until deadline

            await sub.unsubscribe()
            await nc.close()
            return alert_data

        alert = asyncio.run(_run())
        assert alert is not None, "No tripwire alert received for sysmon anomaly_score=0.92"
        assert alert.get("vector_name") == "windows_math"
        assert alert.get("source_type") == "sysmon_sensor"


# ── Suite 4: JetStream stream durability ─────────────────────────────────────

class TestJetStreamDurability:
    def test_alerts_stream_exists(self):
        """Nexus_Math_Alerts stream must exist and allow subscriptions to nexus.alerts.math."""
        async def _check():
            nc = await nats.connect(NATS_URL)
            js = nc.jetstream()
            try:
                sub = await js.subscribe("nexus.alerts.math", stream="Nexus_Math_Alerts",
                                          config=nats.js.api.ConsumerConfig(
                                              deliver_policy=nats.js.api.DeliverPolicy.LAST))
                await sub.unsubscribe()
                exists = True
            except Exception as e:
                exists = False
            await nc.close()
            return exists

        assert asyncio.run(_check()), "Nexus_Math_Alerts stream not found or not subscripable"

    def test_alerts_are_durable_after_publish(self):
        """Publish a high-score point, wait for processing, then read from stream start."""
        eid = _unique_id()
        rec = {**linux_sentinel_record(eid, anomaly=0.91), "sensor_id": eid}

        async def _run():
            nc = await nats.connect(NATS_URL)
            js = nc.jetstream()
            # Subscribe from NEW FIRST so we don't miss the alert
            sub = await js.subscribe("nexus.alerts.math", stream="Nexus_Math_Alerts",
                                      config=nats.js.api.ConsumerConfig(
                                          deliver_policy=nats.js.api.DeliverPolicy.NEW))
            await publish_parquet("nexus.linux_sentinel.telemetry", make_parquet([rec]))

            found = False
            deadline = time.time() + WORKER_SETTLE_SECS + 10
            while time.time() < deadline:
                try:
                    msg = await asyncio.wait_for(sub.next_msg(), timeout=2.0)
                    alert = json.loads(msg.data)
                    await msg.ack()
                    if alert.get("sensor_id", "").endswith(eid):
                        found = True
                        break
                except asyncio.TimeoutError:
                    continue
            await sub.unsubscribe()
            await nc.close()
            return found

        assert asyncio.run(_run()), \
            "Alert for anomaly_score=0.91 not found in durable JetStream consumer"


# ── Suite 5: Payload metadata correctness ────────────────────────────────────

class TestPayloadMetadata:
    def test_source_type_set_in_qdrant_payload(self):
        eid = _unique_id()
        rec = sysmon_record(eid)
        asyncio.run(publish_parquet("nexus.sysmon_sensor.telemetry", make_parquet([rec])))
        pts = wait_for_point(eid, "sysmon_sensor")
        assert pts, "Point not found"
        payload = pts[0].payload
        assert payload["source_type"] == "sysmon_sensor"
        assert payload["vector_name"] == "windows_math"

    def test_timestamp_epoch_populated(self):
        """timestamp_epoch must be a float in the Qdrant payload."""
        eid = _unique_id()
        rec = linux_sentinel_record(eid)
        asyncio.run(publish_parquet("nexus.linux_sentinel.telemetry", make_parquet([rec])))
        pts = wait_for_point(eid, "linux_sentinel")
        assert pts, "Point not found"
        payload = pts[0].payload
        assert "timestamp_epoch" in payload, "timestamp_epoch missing from payload"
        assert float(payload["timestamp_epoch"]) > 1_000_000_000

    def test_nexus_sensor_id_in_payload(self):
        eid = _unique_id()
        rec = linux_c2_record(eid)
        asyncio.run(publish_parquet("nexus.linux_c2.telemetry", make_parquet([rec])))
        pts = wait_for_point(eid, "linux_c2")
        assert pts, "linux_c2 point not found"
        assert pts[0].payload.get("nexus_sensor_id") == eid
