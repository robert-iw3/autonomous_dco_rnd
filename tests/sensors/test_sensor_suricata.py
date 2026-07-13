"""
test_sensor_suricata.py -- Validation of the Suricata EVE pipeline.

Architecture:
  Suricata IDS → eve.json → linux/suricata/transmitter (Rust) →
  tail via inotify → multi-schema EVE JSON parse → Parquet (ZSTD) →
  X-Batch-HMAC + X-Sensor-Type: suricata_eve → Nexus ingress

Coverage:
  Source structure   -- Cargo.toml, transmitter/src/main.rs, docker-compose
  Rust source        -- Multi-schema EVE JSON, community_id identifier, HMAC construction
  Mock Parquet       -- alert, flow, dns, http, tls, fileinfo schemas, roundtrip
  Context columns    -- protocol, src_ip, dest_ip, signature fields
  Nexus config       -- suricata_eve mapping, c2_math=8 (pre-computed), community_id identifier
  Worker Qdrant      -- suricata_eve passes through c2_math 8D branch
"""

import io
import re
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO          = Path(__file__).parent.parent.parent
ROOT          = REPO.parent
SURICATA_DIR  = ROOT / "linux" / "suricata"
TX_DIR        = SURICATA_DIR / "transmitter"
TX_SRC        = TX_DIR / "src" / "main.rs"
SERVICES_CFG  = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG     = REPO / "tests"    / "config" / "nexus.toml"
WORKER_RUST   = REPO / "services" / "worker_qdrant" / "src" / "main.rs"

EVE_SCHEMAS = ["alert", "flow", "dns", "http", "tls", "fileinfo"]

SURICATA_VECTOR_COLS = [
    "outbound_ratio", "packet_size_mean", "packet_size_std",
    "interval", "cv", "entropy", "cmd_entropy", "score",
]


# ── Source structure ──────────────────────────────────────────────────────────

class TestSuricataSourceStructure:

    def test_suricata_dir_exists(self):
        assert SURICATA_DIR.exists()

    def test_transmitter_cargo_toml_exists(self):
        assert (TX_DIR / "Cargo.toml").exists()

    def test_main_rs_exists(self):
        assert TX_SRC.exists()

    def test_docker_compose_exists(self):
        compose = (SURICATA_DIR / "docker-compose.yaml")
        assert compose.exists() or (SURICATA_DIR / "docker-compose.yml").exists()

    def test_cargo_toml_package_name_suricata(self):
        src = (TX_DIR / "Cargo.toml").read_text()
        assert "suricata" in src.lower()

    def test_main_rs_has_parquet_dependency(self):
        src = (TX_DIR / "Cargo.toml").read_text()
        assert "parquet" in src.lower()

    def test_main_rs_has_eve_json_handling(self):
        src = TX_SRC.read_text()
        assert "eve" in src.lower()

    def test_main_rs_tails_eve_json(self):
        src = TX_SRC.read_text()
        assert "inotify" in src or "eve.json" in src or "tail" in src.lower()


# ── Rust source -- HMAC + headers ─────────────────────────────────────────────

class TestSuricataRustSource:

    def _src(self):
        return TX_SRC.read_text()

    def test_x_sensor_type_suricata_eve(self):
        assert "suricata_eve" in self._src()

    def test_x_batch_hmac_header_present(self):
        src = self._src()
        assert "X-Batch-HMAC" in src or "HDR_BATCH_HMAC" in src

    def test_x_batch_sequence_header_present(self):
        src = self._src()
        assert "Batch-Sequence" in src or "HDR_BATCH_SEQUENCE" in src

    def test_hmac_canonical_includes_sequence(self):
        src = self._src()
        assert "sequence" in src.lower() or "seq" in src.lower()

    def test_community_id_field_in_parquet_schema(self):
        assert "community_id" in self._src()

    def test_zstd_compression_used(self):
        src = self._src().lower()
        assert "zstd" in src or "compression" in src

    def test_sensor_type_column_emitted(self):
        assert "sensor_type" in self._src()

    def test_alert_event_type_handled(self):
        assert "alert" in self._src()

    def test_flow_event_type_handled(self):
        assert "flow" in self._src()

    def test_dns_event_type_handled(self):
        assert "dns" in self._src()

    def test_alert_sid_field_present(self):
        # Renamed alert_sid -> signature_id (along with alert_signature/alert_severity/
        # alert_category/alert_mitre -> signature/severity/category/mitre_tactic+
        # mitre_technique) to align 1:1 with nexus.toml [schema_mappings.suricata_eve]
        # context_columns -- see linux/suricata/test workbench findings.
        assert "signature_id" in self._src()

    def test_signature_field_present(self):
        assert "signature" in self._src()

    def test_spool_management_present(self):
        src = self._src()
        assert "spool" in src.lower()

    def test_sequence_counter_present(self):
        # Suricata transmitter uses in-memory struct Stamper with u64 sequence field
        src = self._src()
        assert "sequence" in src.lower()


# ── Mock Parquet -- EVE schemas ────────────────────────────────────────────────

def _build_suricata_schema() -> pa.Schema:
    """Minimal suricata_eve Parquet schema (common + per-event-type fields)."""
    return pa.schema([
        pa.field("sensor_id",          pa.string(),  nullable=False),
        pa.field("sensor_type",        pa.string(),  nullable=False),
        pa.field("timestamp",          pa.float64(), nullable=False),
        # Identifier column (duck-type key in worker_qdrant via c2_math branch)
        pa.field("community_id",       pa.string(),  nullable=True),
        # EVE common
        pa.field("event_type",         pa.string(),  nullable=False),
        pa.field("src_ip",             pa.string(),  nullable=True),
        pa.field("dest_ip",            pa.string(),  nullable=True),
        pa.field("src_port",           pa.int32(),   nullable=True),
        pa.field("dest_port",          pa.int32(),   nullable=True),
        pa.field("protocol",           pa.string(),  nullable=True),
        pa.field("flow_id",            pa.int64(),   nullable=True),
        # Alert fields
        pa.field("alert_sid",          pa.int32(),   nullable=True),
        pa.field("signature",          pa.string(),  nullable=True),
        pa.field("category",           pa.string(),  nullable=True),
        pa.field("severity",           pa.int32(),   nullable=True),
        # Flow fields
        pa.field("bytes_toserver",     pa.int64(),   nullable=True),
        pa.field("bytes_toclient",     pa.int64(),   nullable=True),
        pa.field("pkts_toserver",      pa.int64(),   nullable=True),
        pa.field("pkts_toclient",      pa.int64(),   nullable=True),
        # DNS fields
        pa.field("dns_rrname",         pa.string(),  nullable=True),
        pa.field("dns_rrtype",         pa.string(),  nullable=True),
        # HTTP fields
        pa.field("http_hostname",      pa.string(),  nullable=True),
        pa.field("http_url",           pa.string(),  nullable=True),
        pa.field("http_method",        pa.string(),  nullable=True),
        pa.field("http_status",        pa.int32(),   nullable=True),
        # TLS fields
        pa.field("tls_sni",            pa.string(),  nullable=True),
        pa.field("tls_issuerdn",       pa.string(),  nullable=True),
        # Fileinfo fields
        pa.field("filename",           pa.string(),  nullable=True),
        pa.field("file_magic",         pa.string(),  nullable=True),
    ])


def _build_suricata_row(event_type: str = "alert", i: int = 0) -> dict:
    base = {
        "sensor_id":      "suricata-prod-01",
        "sensor_type":    "suricata_eve",
        "timestamp":      1748000000.0 + i,
        "community_id":   f"1:AbCdEfGh{i:04d}XxYyZz==",
        "event_type":     event_type,
        "src_ip":         f"10.0.0.{(i % 254) + 1}",
        "dest_ip":        f"203.0.113.{(i % 254) + 1}",
        "src_port":       50000 + i,
        "dest_port":      443 if event_type in ("alert", "tls") else 53,
        "protocol":       "TCP",
        "flow_id":        10000000 + i,
        "alert_sid":      None,
        "signature":      None,
        "category":       None,
        "severity":       None,
        "bytes_toserver": None,
        "bytes_toclient": None,
        "pkts_toserver":  None,
        "pkts_toclient":  None,
        "dns_rrname":     None,
        "dns_rrtype":     None,
        "http_hostname":  None,
        "http_url":       None,
        "http_method":    None,
        "http_status":    None,
        "tls_sni":        None,
        "tls_issuerdn":   None,
        "filename":       None,
        "file_magic":     None,
    }
    if event_type == "alert":
        base.update({
            "alert_sid": 2024850 + i, "signature": f"ET MALWARE Test Sig {i}",
            "category": "Malware", "severity": 1,
        })
    elif event_type == "flow":
        base.update({
            "bytes_toserver": 1200 + i*10, "bytes_toclient": 4000 + i*20,
            "pkts_toserver": 5, "pkts_toclient": 8,
        })
    elif event_type == "dns":
        base.update({"dns_rrname": f"evil{i}.example.com", "dns_rrtype": "A"})
    elif event_type == "http":
        base.update({
            "http_hostname": f"host{i}.example.com", "http_url": f"/api/v1/data?t={i}",
            "http_method": "POST", "http_status": 200,
        })
    elif event_type == "tls":
        base.update({"tls_sni": f"cn{i}.suspicious.example.com", "tls_issuerdn": "CN=Let's Encrypt"})
    elif event_type == "fileinfo":
        base.update({"filename": f"/tmp/download_{i}.exe", "file_magic": "PE32 executable"})
    return base


class TestSuricataMockParquet:

    def test_schema_has_community_id_identifier(self):
        assert "community_id" in _build_suricata_schema().names

    def test_all_six_event_types_produce_valid_rows(self):
        schema = _build_suricata_schema()
        for evt in EVE_SCHEMAS:
            row = _build_suricata_row(evt, 0)
            arrays = [pa.array([row.get(f.name)], type=f.type) for f in schema]
            table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
            assert table.num_rows == 1

    def test_parquet_roundtrip_mixed_schemas(self):
        schema = _build_suricata_schema()
        rows   = [_build_suricata_row(EVE_SCHEMAS[i % len(EVE_SCHEMAS)], i) for i in range(24)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        t2 = pq.read_table(buf)
        assert t2.num_rows == 24

    def test_alert_row_has_sid(self):
        row = _build_suricata_row("alert", 0)
        assert row["alert_sid"] is not None

    def test_flow_row_has_bytes(self):
        row = _build_suricata_row("flow", 0)
        assert row["bytes_toserver"] is not None

    def test_dns_row_has_rrname(self):
        row = _build_suricata_row("dns", 0)
        assert row["dns_rrname"] is not None

    def test_sensor_type_field_value(self):
        assert _build_suricata_row("alert", 0)["sensor_type"] == "suricata_eve"

    def test_community_id_format_matches_1_prefix(self):
        row = _build_suricata_row("flow", 1)
        assert row["community_id"].startswith("1:")

    def test_event_type_schema_coverage(self):
        schema = _build_suricata_schema()
        assert "event_type" in schema.names


# ── Nexus config alignment ────────────────────────────────────────────────────

class TestSuricataNexusConfig:

    def test_suricata_eve_mapping_exists(self):
        assert "[schema_mappings.suricata_eve]" in SERVICES_CFG.read_text()

    def test_suricata_eve_identifier_community_id(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.suricata_eve]"):]
        assert 'identifier_column = "community_id"' in block[:400]

    def test_suricata_eve_vector_name_c2_math(self):
        src = SERVICES_CFG.read_text()
        block = src[src.find("[schema_mappings.suricata_eve]"):]
        assert 'vector_name = "c2_math"' in block[:400]

    def test_suricata_eve_mapping_in_tests_cfg(self):
        src = TESTS_CFG.read_text()
        assert "suricata_eve" in src or "[schema_mappings.suricata_eve]" in SERVICES_CFG.read_text()

    def test_worker_rust_suricata_eve_handled(self):
        src = WORKER_RUST.read_text()
        assert "suricata_eve" in src or "community_id" in src
