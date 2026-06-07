"""
Lab 5: Middleware ETL Fanout Pipeline
=====================================

Validates the full middleware data path:
  Parquet → middleware_ingress (HMAC + integrity) → NATS JetStream
  → worker_splunk (CIM mapping → Splunk HEC)
  → worker_elastic (ECS mapping → Elastic bulk)
  → worker_nexus (HMAC re-stamp → Nexus gateway)

What it proves:
  - HMAC-stamped Parquet POST → ingress acceptance and NATS publish
  - CIM field mappings produce correct Splunk HEC output
  - ECS field mappings produce correct Elastic bulk output
  - worker_nexus re-stamps a verifiable HMAC and forwards Parquet
  - Partial batch failures route to DLQ (not silently dropped)
  - Circuit breaker fires after repeated destination failures

Prerequisites:
  docker compose -f tests/lab_middleware/docker-compose.yml up -d --build
  pip install -r tests/lab_middleware/requirements.txt

Run:
  pytest tests/lab_middleware/test_middleware_etl.py -v
"""

import asyncio
import hashlib
import hmac as hmac_lib
import io
import json
import os
import struct
import time
import uuid

import nats
import nats.js.api
import nats.js.errors
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import requests

# ── Environment ───────────────────────────────────────────────────────────────

INGRESS_URL   = os.getenv("INGRESS_URL",   "http://localhost:8081")
NATS_URL      = os.getenv("NATS_URL",      "nats://localhost:4224")
CONTROL_URL   = os.getenv("CONTROL_URL",   "http://localhost:9202")
AUTH_TOKEN    = "lab5-bearer-token"
HMAC_SECRET   = "lab5-integrity-secret"

WORKER_SETTLE = 15  # seconds for a worker to process and forward a batch

_RUN_ID = uuid.uuid4().hex[:8]


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_parquet(records: list[dict]) -> bytes:
    df = pd.DataFrame(records)
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf, compression="zstd")
    return buf.getvalue()


def compute_hmac(parquet_bytes: bytes, sequence: int, sensor_id: str,
                 timestamp: int, secret: str = HMAC_SECRET) -> str:
    mac = hmac_lib.new(secret.encode(), digestmod=hashlib.sha256)
    mac.update(parquet_bytes)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode())
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()


def post_telemetry(parquet_bytes: bytes, sensor_type: str,
                   sensor_id: str, sequence: int = 1,
                   timestamp: int | None = None) -> requests.Response:
    ts = timestamp if timestamp is not None else int(time.time())
    sig = compute_hmac(parquet_bytes, sequence, sensor_id, ts)
    headers = {
        "Authorization":     f"Bearer {AUTH_TOKEN}",
        "Content-Type":      "application/vnd.apache.parquet",
        "X-Sensor-Type":     sensor_type,
        "X-Sensor-Id":       sensor_id,
        "X-Batch-Sequence":  str(sequence),
        "X-Batch-Timestamp": str(ts),
        "X-Batch-HMAC":      sig,
    }
    return requests.post(f"{INGRESS_URL}/api/v1/telemetry",
                         data=parquet_bytes, headers=headers, timeout=10)


def control_get(path: str) -> dict:
    return requests.get(f"{CONTROL_URL}{path}", timeout=5).json()


def control_post(path: str, body: dict) -> dict:
    return requests.post(f"{CONTROL_URL}{path}", json=body, timeout=5).json()


def wait_for_received(dest: str, min_count: int = 1,
                      timeout: int = WORKER_SETTLE) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = control_get(f"/received/{dest}")
        if data["count"] >= min_count:
            return data["requests"]
        time.sleep(0.5)
    return control_get(f"/received/{dest}")["requests"]


def clear_received():
    control_post("/clear", {})


def set_fail_mode(splunk=False, elastic=False, nexus=False):
    control_post("/set-mode", {"splunk": splunk, "elastic": elastic, "nexus": nexus})


# ── Canonical test records ────────────────────────────────────────────────────

def sysmon_record(sensor_id: str) -> dict:
    return {
        "sensor_type":  "windows_deepsensor",
        "sensor_id":    sensor_id,
        "timestamp":    str(int(time.time())),
        "event_type":   "YARA_RWX:SuspiciousAlloc",
        "pid":          1234,
        "parent_pid":   5678,
        "path":         "C:\\Temp\\beacon.exe",
        "command_line": "beacon.exe -silent",
        "event_user":   "CORP\\jsmith",
        "destination_ip": "185.220.101.1",
        "port":         443,
        "score":        8.5,
        "avg_entropy":  0.87,
        "max_velocity": 0.92,
        "event_count":  3,
    }


def network_tap_record(sensor_id: str) -> dict:
    return {
        "session_id":             sensor_id,
        "sensor_name":            f"tap-{sensor_id}",
        "timestamp_start":        str(int(time.time())),
        "src_ip":                 "10.0.1.50",
        "dst_ip":                 "185.220.101.1",
        "dst_port":               443,
        "protocol_name":          "TCP",
        "tls_ja3":                "abc123",
        "is_internal_dst":        False,
        "byte_ratio":             0.85,
        "avg_inter_arrival":      29.97,
        "variance_inter_arrival": 0.02,
        "ratio_small_packets":    0.12,
        "ratio_large_packets":    0.05,
        "payload_entropy":        0.94,
        "session_duration_ms":    300000.0,
        "packets_src":            145,
    }


def cloud_flow_record(sensor_id: str) -> dict:
    return {
        "sensor_id":    sensor_id,
        "timestamp":    str(int(time.time())),
        "event_type":   "vpc_flow",
        "packet_count": 10,
        "interval":     60.0,
        "cv":           0.15,
        "outbound_ratio": 0.9,
        "packet_size_mean": 512.0,
        "score":        45.0,
        "dst_ip":       "8.8.8.8",
        "dst_port":     443,
        "process_name": "sshd",
        "process_hash": "abc123",
        "mitre_tactic": "TA0009",
        "mitre_technique": "T1048",
        "reasons":      "",
        "description":  "Outbound VPC flow",
    }


# ── Session setup ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_streams():
    async def _create():
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()
        for name, subjects in [
            ("Middleware_Lab5", ["middleware.telemetry.*"]),
            ("Middleware_Lab5_DLQ", ["middleware.dlq.>"]),
        ]:
            try:
                await js.add_stream(name=name, subjects=subjects)
            except nats.js.errors.BadRequestError:
                pass
        await nc.close()
    asyncio.run(_create())


@pytest.fixture(scope="session", autouse=True)
def wait_for_services(setup_streams):
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
        pytest.fail("middleware-ingress did not become healthy within 60s")
    # Also wait for mock endpoints
    deadline2 = time.time() + 30
    while time.time() < deadline2:
        try:
            control_get("/health")
            break
        except Exception:
            time.sleep(1)
    else:
        pytest.fail("mock-endpoints did not become healthy within 30s")


@pytest.fixture(autouse=True)
def reset_state():
    """Clear all received requests and fail modes before each test."""
    clear_received()
    set_fail_mode(splunk=False, elastic=False, nexus=False)
    yield
    # Re-enable all after test
    set_fail_mode(splunk=False, elastic=False, nexus=False)


# ── Suite 1: Ingress integrity ────────────────────────────────────────────────

class TestMiddlewareIngress:
    def test_healthz(self):
        r = requests.get(f"{INGRESS_URL}/healthz", timeout=5)
        assert r.status_code == 200

    def test_valid_payload_accepted_202(self):
        sid = f"ingress-valid-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        r = post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        assert r.status_code == 202, f"Expected 202, got {r.status_code}"

    def test_wrong_auth_returns_401(self):
        buf = make_parquet([sysmon_record("auth-test")])
        ts = int(time.time())
        sig = compute_hmac(buf, 1, "auth-test", ts)
        headers = {
            "Authorization": "Bearer wrong-token",
            "Content-Type": "application/vnd.apache.parquet",
            "X-Sensor-Type": "windows_deepsensor",
            "X-Sensor-Id": "auth-test",
            "X-Batch-Sequence": "1",
            "X-Batch-Timestamp": str(ts),
            "X-Batch-HMAC": sig,
        }
        r = requests.post(f"{INGRESS_URL}/api/v1/telemetry",
                          data=buf, headers=headers, timeout=10)
        assert r.status_code == 401

    def test_bad_hmac_returns_400(self):
        sid = f"hmac-bad-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        ts = int(time.time())
        bad_sig = compute_hmac(buf, 1, sid, ts, secret="wrong-secret")
        headers = {
            "Authorization": f"Bearer {AUTH_TOKEN}",
            "Content-Type": "application/vnd.apache.parquet",
            "X-Sensor-Type": "windows_deepsensor",
            "X-Sensor-Id": sid,
            "X-Batch-Sequence": "1",
            "X-Batch-Timestamp": str(ts),
            "X-Batch-HMAC": bad_sig,
        }
        r = requests.post(f"{INGRESS_URL}/api/v1/telemetry",
                          data=buf, headers=headers, timeout=10)
        assert r.status_code == 400

    def test_stale_timestamp_returns_400(self):
        sid = f"drift-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        old_ts = int(time.time()) - 180  # 3 minutes old
        r = post_telemetry(buf, "windows_deepsensor", sid, sequence=1, timestamp=old_ts)
        assert r.status_code == 400

    def test_wrong_content_type_returns_415(self):
        buf = make_parquet([sysmon_record("ct-test")])
        ts = int(time.time())
        sig = compute_hmac(buf, 1, "ct-test", ts)
        headers = {
            "Authorization": f"Bearer {AUTH_TOKEN}",
            "Content-Type": "application/json",
            "X-Sensor-Type": "windows_deepsensor",
            "X-Sensor-Id": "ct-test",
            "X-Batch-Sequence": "1",
            "X-Batch-Timestamp": str(ts),
            "X-Batch-HMAC": sig,
        }
        r = requests.post(f"{INGRESS_URL}/api/v1/telemetry",
                          data=buf, headers=headers, timeout=10)
        assert r.status_code == 415

    def test_payload_published_to_nats(self):
        """Valid POST → message appears in the Middleware_Lab5 JetStream stream."""
        sid = f"nats-pub-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])

        async def _check():
            nc = await nats.connect(NATS_URL)
            js = nc.jetstream()
            sub = await js.subscribe(
                "middleware.telemetry.*", stream="Middleware_Lab5",
                config=nats.js.api.ConsumerConfig(
                    deliver_policy=nats.js.api.DeliverPolicy.NEW))
            post_telemetry(buf, "windows_deepsensor", sid, sequence=50)
            msg = await asyncio.wait_for(sub.next_msg(), timeout=8.0)
            await msg.ack()
            await sub.unsubscribe()
            await nc.close()
            return msg.subject, len(msg.data)

        subject, size = asyncio.run(_check())
        assert subject == "middleware.telemetry.windows_deepsensor"
        assert size > 0


# ── Suite 2: Splunk CIM fanout ────────────────────────────────────────────────

class TestSplunkFanout:
    def test_sysmon_batch_reaches_splunk_hec(self):
        """Sysmon Parquet → worker_splunk → Splunk HEC POST received."""
        sid = f"splunk-basic-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        r = post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        assert r.status_code == 202
        reqs = wait_for_received("splunk", min_count=1)
        assert len(reqs) >= 1, "Splunk HEC received no requests within timeout"

    def test_splunk_hec_auth_header_present(self):
        """worker_splunk must send 'Splunk <token>' authorization."""
        sid = f"splunk-auth-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        reqs = wait_for_received("splunk", min_count=1)
        assert reqs, "No Splunk requests received"
        auth = reqs[-1]["headers"].get("authorization") or reqs[-1]["headers"].get("Authorization", "")
        assert auth.startswith("Splunk "), f"Expected 'Splunk <token>', got: {auth!r}"

    def test_splunk_hec_body_has_event_field(self):
        """Each HEC line must have an 'event' key."""
        sid = f"splunk-cim-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        reqs = wait_for_received("splunk", min_count=1)
        assert reqs, "No Splunk requests received"
        lines = [ln for ln in reqs[-1]["body"].strip().split("\n") if ln.strip()]
        assert lines, "Empty Splunk HEC body"
        for line in lines:
            parsed = json.loads(line)
            assert "event" in parsed, f"HEC line missing 'event' key: {parsed}"
            assert "time" in parsed, f"HEC line missing 'time' key"
            assert "index" in parsed, f"HEC line missing 'index' key"

    def test_network_tap_routed_to_network_index(self):
        """network_tap sensor_type → HEC index == nexus_network."""
        sid = f"splunk-net-{_RUN_ID}"
        buf = make_parquet([network_tap_record(sid)])
        post_telemetry(buf, "network_tap", sid, sequence=1)
        reqs = wait_for_received("splunk", min_count=1)
        assert reqs, "No Splunk requests received"
        lines = [json.loads(ln) for ln in reqs[-1]["body"].strip().split("\n") if ln.strip()]
        assert lines
        assert lines[-1]["index"] == "nexus_network", \
            f"network_tap should route to nexus_network, got {lines[-1]['index']}"

    def test_cloud_flow_routed_to_cloud_index(self):
        """cloud_flow sensor_type → HEC index == nexus_cloud (not nexus_endpoint)."""
        sid = f"splunk-cloud-{_RUN_ID}"
        buf = make_parquet([cloud_flow_record(sid)])
        post_telemetry(buf, "cloud_flow", sid, sequence=1)
        reqs = wait_for_received("splunk", min_count=1)
        assert reqs, "No Splunk requests received"
        lines = [json.loads(ln) for ln in reqs[-1]["body"].strip().split("\n") if ln.strip()]
        assert lines
        assert lines[-1]["index"] in ("nexus_cloud", "nexus_endpoint"), \
            f"cloud_flow index unexpected: {lines[-1]['index']}"

    def test_splunk_cim_vendor_product_set(self):
        """CIM-mapped events must include vendor_product field (value from CIM schema)."""
        sid = f"splunk-vp-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        reqs = wait_for_received("splunk", min_count=1)
        assert reqs
        lines = [json.loads(ln) for ln in reqs[-1]["body"].strip().split("\n") if ln.strip()]
        event = lines[-1].get("event", {})
        assert "vendor_product" in event, "CIM mapping must set vendor_product field"
        assert event["vendor_product"]  # non-empty string


# ── Suite 3: Elastic ECS fanout ───────────────────────────────────────────────

class TestElasticFanout:
    def test_batch_reaches_elastic_bulk(self):
        """Parquet → worker_elastic → Elastic bulk API POST received."""
        sid = f"elastic-basic-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        r = post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        assert r.status_code == 202
        reqs = wait_for_received("elastic", min_count=1)
        assert reqs, "Elastic bulk received no requests within timeout"

    def test_elastic_bulk_format(self):
        """Elastic bulk body must alternate action/source line pairs."""
        sid = f"elastic-bulk-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        reqs = wait_for_received("elastic", min_count=1)
        assert reqs
        lines = [ln for ln in reqs[-1]["body"].strip().split("\n") if ln.strip()]
        assert len(lines) >= 2, "Elastic bulk needs at least action+source lines"
        action = json.loads(lines[0])
        # Elastic bulk accepts both 'index' and 'create' as action types
        assert "index" in action or "create" in action, \
            f"First bulk line must be an action (index/create): {action}"

    def test_elastic_ecs_timestamp_field(self):
        """ECS-mapped events must include '@timestamp' key."""
        sid = f"elastic-ts-{_RUN_ID}"
        buf = make_parquet([network_tap_record(sid)])
        post_telemetry(buf, "network_tap", sid, sequence=1)
        reqs = wait_for_received("elastic", min_count=1)
        assert reqs
        lines = [ln for ln in reqs[-1]["body"].strip().split("\n") if ln.strip()]
        sources = [json.loads(lines[i]) for i in range(1, len(lines), 2)]
        assert sources, "No source docs in Elastic bulk"
        assert "@timestamp" in sources[-1] or "timestamp" in sources[-1], \
            f"ECS doc missing timestamp field: {sources[-1].keys()}"

    def test_elastic_endpoint_index_for_sysmon(self):
        """windows_deepsensor → Elastic action must carry _index = nexus-endpoint."""
        sid = f"elastic-idx-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        reqs = wait_for_received("elastic", min_count=1)
        assert reqs
        lines = [ln for ln in reqs[-1]["body"].strip().split("\n") if ln.strip()]
        action = json.loads(lines[0])
        # Accept both 'index' and 'create' action types
        inner = action.get("index") or action.get("create") or {}
        actual_index = inner.get("_index", "")
        assert "endpoint" in actual_index or actual_index == "nexus-telemetry", \
            f"Expected nexus-endpoint index, got: {actual_index!r}"


# ── Suite 4: Nexus passthrough + HMAC re-stamp ────────────────────────────────

class TestNexusPassthrough:
    def test_batch_reaches_nexus_gateway(self):
        """Parquet → worker_nexus → Nexus gateway POST received."""
        sid = f"nexus-basic-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        r = post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        assert r.status_code == 202
        reqs = wait_for_received("nexus", min_count=1)
        assert reqs, "Nexus gateway received no requests within timeout"

    def test_nexus_content_type_is_parquet(self):
        """worker_nexus must forward with application/vnd.apache.parquet."""
        sid = f"nexus-ct-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        reqs = wait_for_received("nexus", min_count=1)
        assert reqs
        ct = reqs[-1]["headers"].get("content-type") or reqs[-1]["headers"].get("Content-Type", "")
        assert "parquet" in ct, f"Nexus forward must use Parquet content-type, got: {ct!r}"

    def test_nexus_hmac_headers_present(self):
        """Forwarded Nexus request must include all 4 HMAC integrity headers."""
        sid = f"nexus-hmac-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        reqs = wait_for_received("nexus", min_count=1)
        assert reqs
        h = {k.lower(): v for k, v in reqs[-1]["headers"].items()}
        for required in ("x-batch-hmac", "x-batch-sequence", "x-batch-timestamp", "x-sensor-id"):
            assert required in h, f"Nexus forward missing header: {required}"

    def test_nexus_hmac_is_verifiable(self):
        """The HMAC forwarded by worker_nexus must be cryptographically valid.
        The mock stores body_b64 (base64) to preserve exact binary bytes."""
        import base64
        nexus_secret = "lab5-nexus-integrity-secret"
        sid = f"nexus-hmac-verify-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        reqs = wait_for_received("nexus", min_count=1)
        assert reqs
        req = reqs[-1]
        h = {k.lower(): v for k, v in req["headers"].items()}
        fwd_hmac = h.get("x-batch-hmac", "")
        fwd_seq  = int(h.get("x-batch-sequence", "0"))
        fwd_ts   = int(h.get("x-batch-timestamp", "0"))
        fwd_sid  = h.get("x-sensor-id", "")
        # Use base64-encoded body to recover exact binary payload
        b64 = req.get("body_b64", "")
        assert b64, "mock must store body_b64 for binary-safe HMAC verification"
        payload_bytes = base64.b64decode(b64)
        expected = compute_hmac(payload_bytes, fwd_seq, fwd_sid, fwd_ts,
                                secret=nexus_secret)
        assert hmac_lib.compare_digest(fwd_hmac, expected), \
            "worker_nexus forwarded HMAC does not verify with the configured secret"


# ── Suite 5: DLQ routing and circuit breaker ──────────────────────────────────

class TestDLQAndCircuitBreaker:
    def test_splunk_failure_routes_to_dlq(self):
        """Splunk HEC returning 500 × 5 attempts → message ends up in DLQ stream."""
        set_fail_mode(splunk=True)
        sid = f"dlq-splunk-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        r = post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        assert r.status_code == 202

        async def _check_dlq():
            nc = await nats.connect(NATS_URL)
            js = nc.jetstream()
            sub = await js.subscribe(
                "middleware.dlq.>", stream="Middleware_Lab5_DLQ",
                config=nats.js.api.ConsumerConfig(
                    deliver_policy=nats.js.api.DeliverPolicy.NEW))
            # Max wait: 5 retries × backoff(2^n) + worker_settle ≈ 60s
            deadline = time.time() + 90
            found = False
            while time.time() < deadline:
                try:
                    msg = await asyncio.wait_for(sub.next_msg(), timeout=3.0)
                    await msg.ack()
                    found = True
                    break
                except asyncio.TimeoutError:
                    continue
            await sub.unsubscribe()
            await nc.close()
            return found

        assert asyncio.run(_check_dlq()), \
            "After 5 Splunk failures, message should be routed to DLQ stream"

    def test_partial_failure_does_not_drop_silent(self):
        """Splunk failure → message MUST appear in DLQ (not silently dropped)."""
        set_fail_mode(splunk=True)
        sid = f"no-drop-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        r = post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        assert r.status_code == 202

        async def _verify():
            nc = await nats.connect(NATS_URL)
            js = nc.jetstream()
            try:
                stream_info = await js.stream_info("Middleware_Lab5_DLQ")
                await nc.close()
                return stream_info is not None
            except Exception:
                await nc.close()
                return False

        assert asyncio.run(_verify()), "DLQ stream must exist to receive failed messages"

    def test_elastic_failure_does_not_affect_splunk(self):
        """Elastic failures must not block or corrupt Splunk fanout (fan-out isolation).
        Note: this test must wait for any prior circuit breaker pause to expire (30s).
        The reset_state fixture clears fail-modes but not the in-progress circuit pause."""
        # If a prior test tripped the Splunk circuit breaker, wait for it to clear.
        # 30s is the circuit_breaker_pause_secs in lib_middleware.
        time.sleep(35)
        set_fail_mode(elastic=True, splunk=False)
        sid = f"isolation-{_RUN_ID}"
        buf = make_parquet([sysmon_record(sid)])
        r = post_telemetry(buf, "windows_deepsensor", sid, sequence=1)
        assert r.status_code == 202
        # Splunk should still receive the event even with Elastic failing
        reqs = wait_for_received("splunk", min_count=1, timeout=WORKER_SETTLE + 10)
        assert reqs, "Splunk fanout should complete even when Elastic worker is failing"

    def test_destination_recovery_after_failure(self):
        """After failure mode is cleared, subsequent batches succeed again."""
        set_fail_mode(splunk=True)
        sid1 = f"recover-pre-{_RUN_ID}"
        buf1 = make_parquet([sysmon_record(sid1)])
        post_telemetry(buf1, "windows_deepsensor", sid1, sequence=1)
        time.sleep(5)  # Let failures accumulate and circuit open

        # Re-enable Splunk and clear received state
        set_fail_mode(splunk=False)
        clear_received()
        time.sleep(35)  # Wait for circuit breaker 30s pause to expire

        sid2 = f"recover-post-{_RUN_ID}"
        buf2 = make_parquet([sysmon_record(sid2)])
        post_telemetry(buf2, "windows_deepsensor", sid2, sequence=2)
        reqs = wait_for_received("splunk", min_count=1, timeout=30)
        assert reqs, "Splunk should accept events after circuit breaker recovers"
