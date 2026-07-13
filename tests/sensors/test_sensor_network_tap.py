"""
test_sensor_network_tap.py -- Validation of the network_tap gateway pipeline.

Architecture:
  Network traffic → Arkime ML gateway (Rust) → Redpanda (Kafka) → Redis cache →
  SQLite WAL session buffer → Parquet (ZSTD) → X-Batch-HMAC → Nexus ingress

Sensor type: "network_tap"
Vector: network_tap 8D = [byte_ratio, avg_inter_arrival, variance_inter_arrival,
                           ratio_small_packets, ratio_large_packets, payload_entropy,
                           session_duration_ms, packets_src]
Identifier: session_id

Coverage:
  Source structure   -- infra/network_tap/gateway Cargo.toml, config.toml
  config.toml        -- HTTPS enforcement, network_tap sensor_type, credentials from env
  network_tap 8D     -- All vector columns in nexus.toml, all float [0,1] or raw values
  Mock Parquet       -- session-level records, roundtrip, ZSTD compression
  Nexus config       -- network_tap mapping, network_tap_math or vector_columns
  Worker Qdrant      -- network_tap branch in main.rs
"""

import io
import re
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO         = Path(__file__).parent.parent.parent
ROOT         = REPO.parent
TAP_DIR      = ROOT / "infra" / "network_tap" / "gateway"
SERVICES_CFG = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG    = REPO / "tests"    / "config" / "nexus.toml"
WORKER_RUST  = REPO / "services" / "worker_qdrant" / "src" / "main.rs"

NETWORK_TAP_VECTOR_COLS = [
    "byte_ratio", "avg_inter_arrival", "variance_inter_arrival",
    "ratio_small_packets", "ratio_large_packets", "payload_entropy",
    "session_duration_ms", "packets_src",
]


# ── Source structure ──────────────────────────────────────────────────────────

class TestNetworkTapSourceStructure:

    def test_gateway_dir_exists(self):
        assert TAP_DIR.exists()

    def test_cargo_toml_exists(self):
        assert (TAP_DIR / "Cargo.toml").exists()

    def test_cargo_name_arkime_ml_gateway(self):
        src = (TAP_DIR / "Cargo.toml").read_text()
        assert "arkime-ml-gateway" in src or "arkime_ml_gateway" in src

    def test_config_toml_exists(self):
        assert (TAP_DIR / "config.toml").exists()

    def test_src_main_rs_exists(self):
        src_dir = TAP_DIR / "src"
        assert (src_dir / "main.rs").exists()

    def test_docker_compose_exists(self):
        tap_root = ROOT / "infra" / "network_tap"
        assert (TAP_DIR / "docker-compose.yaml").exists() or \
               (TAP_DIR / "docker-compose.yml").exists() or \
               any(tap_root.rglob("docker-compose.yml")) or \
               any(tap_root.rglob("docker-compose.yaml"))


# ── config.toml ───────────────────────────────────────────────────────────────

class TestNetworkTapConfig:

    def _cfg(self):
        return (TAP_DIR / "config.toml").read_text()

    def test_sensor_type_network_tap(self):
        assert "network_tap" in self._cfg()

    def test_gateway_url_is_https(self):
        cfg = self._cfg()
        urls = re.findall(r'(?:gateway_url|nexus_url|ingress_url)\s*=\s*"([^"]+)"', cfg)
        for url in urls:
            assert url.startswith("https://"), f"gateway_url not HTTPS: {url}"

    def test_no_plaintext_credentials(self):
        cfg = self._cfg()
        # Active (uncommented) integrity_secret must not be a real secret value.
        # Allowed: env-var substitution (${...}), empty string, or ALL_CAPS_UNDERSCORES
        # deployment placeholders (e.g. INJECT_FROM_SECRETS_MANAGER, CHANGE_VIA_ENV).
        active = [l for l in cfg.splitlines()
                  if re.match(r'\s*integrity_secret\s*=', l)]
        for line in active:
            m = re.search(r'=\s*"([^"]*)"', line)
            if m:
                val = m.group(1)
                is_env_var    = val.startswith("${")
                is_empty      = val == ""
                is_placeholder = re.match(r'^[A-Z][A-Z0-9_]+$', val) is not None
                if not (is_env_var or is_empty or is_placeholder):
                    pytest.fail(f"Hardcoded integrity_secret in config.toml: {val}")

    def test_batch_size_configured(self):
        assert "batch_size" in self._cfg()

    def test_redpanda_or_kafka_configured(self):
        cfg = self._cfg().lower()
        assert "redpanda" in cfg or "kafka" in cfg or "bootstrap" in cfg

    def test_redis_configured(self):
        cfg = self._cfg().lower()
        assert "redis" in cfg

    def test_sqlite_storage_configured(self):
        cfg = self._cfg().lower()
        assert "sqlite" in cfg or "spool_db" in cfg or ".db" in cfg


# ── Rust source inspection ────────────────────────────────────────────────────

class TestNetworkTapRustSource:

    def _nexus(self):
        # HMAC, Parquet schema, session fields live in src/transmit/nexus.rs
        return (TAP_DIR / "src" / "transmit" / "nexus.rs").read_text()

    def _main(self):
        return (TAP_DIR / "src" / "main.rs").read_text()

    def test_x_batch_hmac_header_present(self):
        src = self._nexus()
        assert "X-Batch-HMAC" in src or "HDR_BATCH_HMAC" in src

    def test_x_sensor_type_network_tap(self):
        # sensor_type is set in config.toml (sensor_type = "network_tap")
        assert "network_tap" in (TAP_DIR / "config.toml").read_text()

    def test_session_id_field_present(self):
        assert "session_id" in self._nexus()

    def test_parquet_output_format(self):
        assert "parquet" in self._nexus().lower()

    def test_payload_entropy_field_present(self):
        src = self._nexus()
        assert "payload_entropy" in src

    def test_byte_ratio_field_present(self):
        assert "byte_ratio" in self._nexus()

    def test_sequence_counter_used(self):
        src = self._nexus()
        assert "sequence" in src.lower()

    def test_hmac_canonical_construction(self):
        # to_be_bytes lives in integrity/stamper.rs (shared HMAC construction module)
        stamper = (TAP_DIR / "src" / "integrity" / "stamper.rs").read_text()
        nexus   = self._nexus()
        assert "to_be_bytes" in stamper or "to_be_bytes" in nexus or \
               "be_bytes" in stamper.lower()


# ── Mock Parquet - network_tap 8D ─────────────────────────────────────────────

def _build_network_tap_schema() -> pa.Schema:
    return pa.schema([
        pa.field("sensor_id",                pa.string(),  nullable=False),
        pa.field("sensor_type",              pa.string(),  nullable=False),
        pa.field("timestamp",               pa.float64(), nullable=False),
        pa.field("session_id",              pa.string(),  nullable=False),
        # network_tap 8D vector scalars
        pa.field("byte_ratio",              pa.float64(), nullable=True),
        pa.field("avg_inter_arrival",       pa.float64(), nullable=True),
        pa.field("variance_inter_arrival",  pa.float64(), nullable=True),
        pa.field("ratio_small_packets",     pa.float64(), nullable=True),
        pa.field("ratio_large_packets",     pa.float64(), nullable=True),
        pa.field("payload_entropy",         pa.float64(), nullable=True),
        pa.field("session_duration_ms",     pa.float64(), nullable=True),
        pa.field("packets_src",             pa.float64(), nullable=True),
        # Context
        pa.field("src_ip",                  pa.string(),  nullable=True),
        pa.field("dst_ip",                  pa.string(),  nullable=True),
        pa.field("src_port",                pa.int32(),   nullable=True),
        pa.field("dst_port",                pa.int32(),   nullable=True),
        pa.field("protocol",                pa.string(),  nullable=True),
        pa.field("community_id",            pa.string(),  nullable=True),
        pa.field("total_bytes",             pa.int64(),   nullable=True),
        pa.field("total_packets",           pa.int64(),   nullable=True),
        pa.field("ml_label",               pa.string(),  nullable=True),
    ])


def _build_network_tap_row(i: int = 0) -> dict:
    return {
        "sensor_id":               "network-tap-prod-01",
        "sensor_type":             "network_tap",
        "timestamp":               1748000000.0 + i,
        "session_id":              f"sess-{i:010d}-abcd",
        "byte_ratio":              min(1.0, 0.3 + i * 0.03),
        "avg_inter_arrival":       0.001 + i * 0.0001,
        "variance_inter_arrival":  0.0001,
        "ratio_small_packets":     min(1.0, 0.4 + i * 0.02),
        "ratio_large_packets":     min(1.0, 0.2 + i * 0.01),
        "payload_entropy":         min(1.0, (3.5 + i * 0.1) / 8.0),
        "session_duration_ms":     float(500 + i * 100),
        "packets_src":             float(10 + i),
        "src_ip":                  f"10.0.{i % 10}.{(i % 254) + 1}",
        "dst_ip":                  f"203.0.113.{(i % 254) + 1}",
        "src_port":                49152 + i,
        "dst_port":                443,
        "protocol":                "TCP",
        "community_id":            f"1:FlowAbCd{i:04d}==",
        "total_bytes":             2000 + i * 100,
        "total_packets":           25 + i,
        "ml_label":                "NORMAL" if i % 3 != 0 else "SUSPICIOUS",
    }


class TestNetworkTapMockParquet:

    def test_schema_has_session_id_identifier(self):
        assert "session_id" in _build_network_tap_schema().names

    def test_schema_has_all_eight_vector_columns(self):
        schema = _build_network_tap_schema()
        for col in NETWORK_TAP_VECTOR_COLS:
            assert col in schema.names, f"Missing vector column: {col}"

    def test_parquet_roundtrip(self):
        schema = _build_network_tap_schema()
        rows   = [_build_network_tap_row(i) for i in range(20)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        t2 = pq.read_table(buf)
        assert t2.num_rows == 20

    def test_vector_columns_non_negative(self):
        for i in range(15):
            row = _build_network_tap_row(i)
            for col in NETWORK_TAP_VECTOR_COLS:
                assert row[col] >= 0.0, f"Row {i} {col}={row[col]} negative"

    def test_byte_ratio_bounded(self):
        for i in range(15):
            assert 0.0 <= _build_network_tap_row(i)["byte_ratio"] <= 1.0

    def test_sensor_type_network_tap(self):
        assert _build_network_tap_row(0)["sensor_type"] == "network_tap"


# ── Nexus config alignment ────────────────────────────────────────────────────

class TestNetworkTapNexusConfig:

    def test_network_tap_mapping_exists(self):
        assert "[schema_mappings.network_tap]" in SERVICES_CFG.read_text()

    def test_network_tap_identifier_is_session_id(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.network_tap]"):]
        assert 'identifier_column = "session_id"' in block[:400]

    def test_network_tap_all_vector_columns_in_cfg(self):
        src = SERVICES_CFG.read_text()
        for col in NETWORK_TAP_VECTOR_COLS:
            assert col in src, f"Missing vector column in nexus.toml: {col}"

    def test_network_tap_in_tests_cfg(self):
        assert "network_tap" in TESTS_CFG.read_text()

    def test_worker_rust_network_tap_branch(self):
        src = WORKER_RUST.read_text()
        assert "network_tap" in src or "session_id" in src
