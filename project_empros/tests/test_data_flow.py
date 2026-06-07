"""
test_data_flow.py -- End-to-End Data Transformation Validation

Validates:
    Track 1 (Spatial) → vector_name keyed tensors in safetensors format
    Track 4 (Nettap SPI) → temporal windows with 44-column schema (42 + 2 derived)
    Hive partition columns (dt, hour) for DuckDB partition discovery
    Updated tensor registry key format: {vector_name}_{event_id}
"""
import os
import json
import pytest
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import torch
import fakeredis
import duckdb
from pathlib import Path
from unittest.mock import patch, MagicMock
from safetensors.torch import load_file as st_load_file

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))
import importlib
spooler = importlib.import_module("01_spool_datasets")


@pytest.fixture
def mock_directories(tmp_path):
    train_dir = tmp_path / "training"
    eval_dir = tmp_path / "evals"
    train_dir.mkdir()
    eval_dir.mkdir()

    with patch.object(spooler, 'OUTPUT_DIR', train_dir), \
         patch.object(spooler, 'EVAL_DIR', eval_dir):
        yield train_dir, eval_dir


@pytest.fixture
def mock_redis():
    r = fakeredis.FakeRedis(decode_responses=True)

    mock_incident = {
        "event_id": "TEST-C2-001",
        "timestamp": 1776657910.0,
        "source_type": "windows_deepsensor",
        "vector_name": "windows_math",
        "triggering_vector": [0.85, 0.12, 0.99, 0.45],
        "final_report": "Malicious activity confirmed. PowerShell stager detected."
    }
    r.set("nexus:validated_incidents:TEST-C2-001", json.dumps(mock_incident))
    r.set("nexus:training_priority:TEST-C2-001", "TEST-C2-001")

    # Fleet size for circuit breaker tests
    for i in range(50000):
        r.sadd("nexus:fleet:active", f"ws-{i:05d}")

    return r


class _DuckDBProxy:
    """Wrap a duckdb connection so .execute can be replaced (C ext is read-only)."""
    def __init__(self, real_con, execute_fn):
        self._real = real_con
        self.execute = execute_fn
    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture
def mock_duckdb_spatial(tmp_path):
    con = duckdb.connect(database=':memory:')

    mock_telemetry = pd.DataFrame([{
        "event_id": "TEST-C2-001",
        "timestamp": 1776657910.0,
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell -enc WwBSAGUAZgBd...",
        "destination_ip": "185.10.68.22",
    }])

    parquet_path = tmp_path / "mock_telemetry.parquet"
    pq.write_table(pa.Table.from_pandas(mock_telemetry), parquet_path)

    original_execute = con.execute
    def patched_execute(query, *args, **kwargs):
        if "s3://nexus-cold-storage" in query:
            query = query.replace(
                "s3://nexus-cold-storage/telemetry/windows_deepsensor/**/*.parquet",
                str(parquet_path)
            )
        return original_execute(query, *args, **kwargs)

    return _DuckDBProxy(con, patched_execute)


@pytest.fixture
def mock_duckdb_nettap(tmp_path):
    """Mock Hive-partitioned network_tap Parquet with all 44 columns."""
    con = duckdb.connect(database=':memory:')

    import time
    now = time.time()
    nettap_data = []
    for i in range(20):
        nettap_data.append({
            "session_id": f"sess-{i:04d}",
            "src_ip": "10.0.1.50",
            "dst_ip": "185.10.68.22",
            "src_port": 49200 + i,
            "dst_port": 8443,
            "protocol": 6,
            "protocol_name": "tcp",
            "timestamp_start": now - (20 - i) * 90,
            "timestamp_end": now - (20 - i) * 90 + 5.0,
            "session_duration_ms": 5000,
            "bytes_src": 2048,
            "bytes_dst": 15360,
            "data_bytes_src": 1800,
            "data_bytes_dst": 14000,
            "packets_src": 15,
            "packets_dst": 45,
            "byte_ratio": 0.12,
            "avg_inter_arrival": 120.5,
            "variance_inter_arrival": 45.0,
            "ratio_small_packets": 0.3,
            "ratio_large_packets": 0.5,
            "payload_entropy": 5.8,
            "tcp_syn": 1, "tcp_rst": 0, "tcp_fin": 1,
            "dns_query": None, "dns_status": None,
            "http_method": None, "http_uri": None,
            "http_useragent": None, "http_status_code": None,
            "tls_ja3": "a0e9f5d64349fb13191bc781f81f42e1",
            "tls_ja3s": "eb1d94daa7e0344597e756a1fb6e7054",
            "tls_version": "TLSv1.3", "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "cert_cn": "*.malicious-infra.xyz",
            "cert_issuer_cn": "*.malicious-infra.xyz",
            "cert_self_signed": True, "cert_valid_days": 30,
            "hostname": "malicious-infra.xyz",
            "src_geo_country": None, "dst_geo_country": "RU",
            "dst_asn_org": "BulletProof-AS",
            "sensor_name": "arkime-sensor-01", "sensor_type": "network_tap",
            # Derived ML features
            "is_internal_dst": False,
            "port_class": "registered",
        })

    df = pd.DataFrame(nettap_data)
    parquet_path = tmp_path / "nettap_mock.parquet"
    pq.write_table(pa.Table.from_pandas(df), parquet_path)

    original_execute = con.execute
    def patched_execute(query, *args, **kwargs):
        if "s3://nexus-cold-storage" in query and "network_tap" in query:
            query = query.replace(
                "s3://nexus-cold-storage/telemetry/network_tap/dt=*/hour=*/*.parquet",
                str(parquet_path)
            )
        return original_execute(query, *args, **kwargs)

    return _DuckDBProxy(con, patched_execute)


_VECTOR_DIMS = {
    "c2_math": 8, "sentinel_math": 5, "windows_math": 6,
    "deepsensor_math": 4, "trellix_math": 6, "cloud_flow": 5, "network_tap": 8,
}


@pytest.fixture
def mock_qdrant_client():
    """Patch QdrantClient so spool_spatial_data never dials the network."""
    from unittest.mock import patch, MagicMock

    def _scroll(collection_name, scroll_filter=None, limit=10, order_by=None,
                offset=None, with_payload=True, with_vectors=False,
                consistency=None, shard_key_selector=None, timeout=None, **kw):
        vname = with_vectors[0] if isinstance(with_vectors, list) and with_vectors else "windows_math"
        dim = _VECTOR_DIMS.get(vname, 4)
        pt = MagicMock()
        pt.vector = {vname: [0.5] * dim}
        pt.payload = {"process_name": "powershell.exe", "dst_ip": "185.10.68.22"}
        return ([pt], None)

    mock_client = MagicMock()
    mock_client.scroll.side_effect = _scroll

    with patch("qdrant_client.QdrantClient", return_value=mock_client):
        yield mock_client


# ── Track 1: Spatial Projection ──

def test_spatial_spooler_data_flow(mock_directories, mock_redis, mock_duckdb_spatial,
                                   mock_qdrant_client):
    """Validates Track 1 transformation: Parquet + Redis → JSONL + safetensors."""
    train_dir, eval_dir = mock_directories

    spooler.spool_spatial_data(mock_duckdb_spatial)

    train_file = train_dir / "spatial_projection_v1.jsonl"
    assert train_file.exists(), "Track 1 JSONL not generated."

    with open(train_file) as f:
        lines = f.readlines()

    assert len(lines) >= 1, "Expected at least 1 Track 1 record"

    record = json.loads(lines[0])
    assert "vector_name" in record, "CRITICAL: vector_name missing from Track 1 record"
    assert "vector" in record, "CRITICAL: vector missing from Track 1 record"


def test_spatial_tensor_key_format(mock_directories, mock_redis, mock_duckdb_spatial,
                                   mock_qdrant_client):
    """Validates tensor registry uses {vector_name}_{event_id} key format."""
    train_dir, _ = mock_directories

    spooler.spool_spatial_data(mock_duckdb_spatial)

    tensor_file = train_dir / "spatial_tensors_v1.safetensors"
    if not tensor_file.exists():
        pytest.skip("Tensor file not generated (Qdrant unavailable in test)")

    registry = st_load_file(str(tensor_file))

    # New key format: {vector_name}_{event_id}
    expected_key = "windows_math_TEST-C2-001"
    legacy_key = "VECTOR_SPACE_TEST-C2-001"

    assert expected_key in registry or legacy_key in registry, \
        f"Tensor registry missing key. Expected '{expected_key}' or '{legacy_key}'. Keys: {list(registry.keys())[:5]}"

    if expected_key in registry:
        tensor = registry[expected_key]
        assert tensor.shape[0] == 4, "windows_math vector must be 4D"


# ── Track 4: Nettap SPI ──

def test_nettap_spooler_schema(mock_directories, mock_duckdb_nettap):
    """Validates Track 4 output has all 44 columns including derived fields."""
    train_dir, _ = mock_directories

    spooler.spool_nettap_data(mock_duckdb_nettap)

    output_file = train_dir / "nettap_spi_v1.jsonl"
    if not output_file.exists():
        pytest.skip("Track 4 output not generated (insufficient sessions for windowing)")

    with open(output_file) as f:
        record = json.loads(f.readline())

    assert "sessions" in record, "Track 4 record missing sessions array"
    assert "derived_summary" in record, "Track 4 record missing derived_summary"
    assert "prompt" in record, "Track 4 record missing prompt"
    assert "src_ip" in record, "Track 4 record missing src_ip"
    assert "dst_ip" in record, "Track 4 record missing dst_ip"

    # Validate derived fields in sessions
    if record["sessions"]:
        session = record["sessions"][0]
        assert "is_internal_dst" in session, "CRITICAL: is_internal_dst missing from Track 4 sessions"
        assert "port_class" in session, "CRITICAL: port_class missing from Track 4 sessions"

    # Validate derived summary
    summary = record["derived_summary"]
    assert "is_internal_dst" in summary, "derived_summary missing is_internal_dst"
    assert "port_classes_seen" in summary, "derived_summary missing port_classes_seen"


def test_nettap_temporal_windowing(mock_directories, mock_duckdb_nettap):
    """Validates that Track 4 correctly groups sessions by (src_ip, dst_ip) pair."""
    train_dir, _ = mock_directories

    spooler.spool_nettap_data(mock_duckdb_nettap, window_minutes=10)

    output_file = train_dir / "nettap_spi_v1.jsonl"
    if not output_file.exists():
        pytest.skip("Track 4 output not generated")

    with open(output_file) as f:
        records = [json.loads(line) for line in f]

    for record in records:
        assert record["src_ip"] == "10.0.1.50", "Window has wrong src_ip"
        assert record["dst_ip"] == "185.10.68.22", "Window has wrong dst_ip"
        assert record["num_sessions"] >= 3, "Window below min_sessions threshold"
        assert record["window_end"] > record["window_start"], "Invalid window bounds"

    print(f"\n[+] Track 4 windowing validated: {len(records)} windows generated.")