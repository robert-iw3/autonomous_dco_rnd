"""
Tier-0 - End-to-end data-contract test for linux/c2_sensor.

Seeds a synthetic SQLite `flows` table with mock telemetry rows, drives the
*real* NexusForwarder.extract_to_spool() pipeline to materialise an actual
Parquet file, then validates the resulting schema against:

  * [schema_mappings.linux_c2] in the central nexus.toml (identifier_column,
    sensor_id_column, vector_columns, context_columns -- what worker_qdrant
    duck-types on for routing/storage)
  * sensor_profiles/linux_sensor.toml sensor_type == "linux-c2-sensor"
    (must match the X-Sensor-Type the forwarder actually transmits)
"""

import os
import sqlite3
import time
import pyarrow.parquet as pq
import pytest
import tomllib

pytestmark = pytest.mark.tier0

CONTRACT = {
    "identifier_column": "outbound_ratio",
    "sensor_id_column": "sensor_id",
    "primary_key_column": "id",
    "timestamp_column": "timestamp",
    "vector_columns": [
        "outbound_ratio", "packet_size_mean", "packet_size_std",
        "interval", "cv", "entropy", "cmd_entropy", "score",
    ],
    "context_columns": [
        "process_name", "pid", "uid", "process_hash", "event_type",
        "dst_ip", "dst_port", "packet_size_min", "packet_size_max",
        "dns_query", "dns_flags", "mitre_tactic", "ml_result",
        "reasons", "suppressed", "hostname",
    ],
}

EXPECTED_SENSOR_TYPE = "linux-c2-sensor"

def _seed_flows_db(db_path, rows=5):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL, process_name TEXT, pid INTEGER, uid INTEGER,
            process_hash TEXT, event_type TEXT, dst_ip TEXT, dst_port INTEGER,
            outbound_ratio REAL, packet_size_mean REAL, packet_size_std REAL,
            packet_size_min INTEGER, packet_size_max INTEGER, packet_count INTEGER,
            interval REAL, cv REAL, entropy REAL, cmd_entropy REAL,
            dns_query TEXT, dns_flags INTEGER, mitre_tactic TEXT, score INTEGER,
            ml_result TEXT, reasons TEXT, suppressed INTEGER, sensor_id TEXT
        )
    """)
    now = time.time()
    for i in range(rows):
        conn.execute(
            "INSERT INTO flows (timestamp, process_name, pid, uid, process_hash, event_type, "
            "dst_ip, dst_port, outbound_ratio, packet_size_mean, packet_size_std, packet_size_min, "
            "packet_size_max, packet_count, interval, cv, entropy, cmd_entropy, dns_query, dns_flags, "
            "mitre_tactic, score, ml_result, reasons, suppressed, sensor_id) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now + i, f"proc{i}.exe", 1000 + i, 0, "deadbeef", "connect",
             f"10.0.0.{i}", 443, 0.5, 512.0, 32.0, 64, 1024, 10,
             60.0, 0.1, 4.2, 3.1, "example.com", 0, "TA0011", 80,
             "beacon", "[]", 0, "test-sensor-host"),
        )
    conn.commit()
    conn.close()

@pytest.fixture()
def synthetic_spool(tmp_path, repo_root):
    """Drives the real NexusForwarder pipeline against synthetic data and
    returns the path to the materialised Parquet file."""
    from nexus_forwarder import NexusForwarder

    db_path = tmp_path / "baseline.db"
    _seed_flows_db(str(db_path))

    spool_dir = tmp_path / "spool"
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'[nexus]\nenabled = true\nspool_dir = "{spool_dir}"\n'
        f'gateway_url = "https://nexus-edge.local/api/v1/telemetry"\n'
        f'integrity_secret = "test-secret"\n'
    )

    forwarder = NexusForwarder(config_path=str(config_path), db_path=str(db_path))
    forwarder.extract_to_spool()

    parquet_files = list(spool_dir.glob("*.parquet"))
    assert parquet_files, "extract_to_spool() did not materialise a Parquet file from synthetic data"
    return parquet_files[0]

class TestParquetSchemaContract:
    def test_identifier_and_sensor_id_columns_present(self, synthetic_spool):
        schema = pq.read_schema(synthetic_spool)
        names = set(schema.names)
        assert CONTRACT["identifier_column"] in names
        assert CONTRACT["sensor_id_column"] in names
        assert CONTRACT["primary_key_column"] in names
        assert CONTRACT["timestamp_column"] in names

    def test_all_vector_columns_present(self, synthetic_spool):
        names = set(pq.read_schema(synthetic_spool).names)
        missing = [c for c in CONTRACT["vector_columns"] if c not in names]
        assert not missing, f"c2_math vector columns missing from outbound schema: {missing}"

    def test_all_context_columns_present(self, synthetic_spool):
        names = set(pq.read_schema(synthetic_spool).names)
        missing = [c for c in CONTRACT["context_columns"] if c not in names]
        assert not missing, f"context columns missing from outbound schema: {missing}"

    def test_synthetic_rows_round_trip_through_parquet(self, synthetic_spool):
        table = pq.read_table(synthetic_spool)
        assert table.num_rows == 5
        assert table.column("process_name")[0].as_py() == "proc0.exe"
        assert table.column("sensor_id")[0].as_py() == "test-sensor-host"

class TestSensorTypeContract:
    def test_sensor_type_matches_central_sensor_profile(self, repo_root):
        profile_path = os.path.join(
            repo_root, "..", "..", "project_empros", "middleware", "config",
            "sensor_profiles", "linux_sensor.toml",
        )
        profile_path = os.path.normpath(profile_path)
        assert os.path.exists(profile_path), f"reference sensor profile not found: {profile_path}"
        with open(profile_path, "rb") as f:
            profile = tomllib.load(f)
        assert profile["transmission"]["sensor_type"] == EXPECTED_SENSOR_TYPE

    def test_forwarder_transmits_declared_sensor_type(self, python_engine_dir):
        src = open(os.path.join(python_engine_dir, "nexus_forwarder.py")).read()
        assert f'"linux-c2-sensor"' in src