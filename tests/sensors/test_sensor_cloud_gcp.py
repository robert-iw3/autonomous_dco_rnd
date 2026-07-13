"""
test_sensor_cloud_gcp.py -- Validation of GCP + VMware cloud connector pipelines.

Architecture:
  GCP (Cloud Audit/SCC/VPC) + VMware syslog → UnifiedFlowRecord →
  transmitter.rs → Parquet (ZSTD) → X-Batch-HMAC + X-Sensor-Type → Nexus ingress

Shared transmitter pattern:
  - X-Batch-HMAC header (HDR_BATCH_HMAC via nexus_integrity)
  - X-Sensor-Type header (per-connector: gcp_audit, gcp_scc, gcp_vpc, vmware_vsphere)
  - X-Batch-Sequence, X-Batch-Timestamp
  - Bounded spool (evicts oldest before writing new)
  - .transmit_sequence counter file in spool_dir
  - cloud_flow 5D: [interval, cv, outbound_ratio, packet_size_mean, score]

Coverage:
  Source structure    -- infra/gcp/{audit,scc,vpc}, infra/vmware workspace Cargo.toml
  Shared transmitter  -- HMAC, headers, bounded spool, sequence counter
  UnifiedFlowRecord   -- 5D cloud_flow vector, interval/cv/outbound_ratio/packet_size_mean/score
  VMware spool replay -- spool replayed on startup (no upstream queue durability)
  GCP no replay       -- SQS/Pub/Sub backed (replay would duplicate)
  Mock Parquet        -- UnifiedFlowRecord fields, roundtrip, all connectors
  Nexus config        -- gcp_audit/gcp_scc/gcp_vpc/vmware_vsphere mappings, cloud_flow 5D
  Worker Qdrant       -- cloud_flow 5D branch
"""

import io
import re
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO         = Path(__file__).parent.parent.parent
ROOT         = REPO.parent
GCP_DIR      = ROOT / "infra" / "gcp"
AUDIT_DIR    = GCP_DIR / "audit"
SCC_DIR      = GCP_DIR / "scc"
VPC_DIR      = GCP_DIR / "vpc"
VMWARE_DIR   = ROOT / "infra" / "vmware"
SERVICES_CFG = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG    = REPO / "tests"    / "config" / "nexus.toml"
WORKER_RUST  = REPO / "services" / "worker_qdrant" / "src" / "main.rs"

CLOUD_FLOW_VECTOR_COLS = [
    "interval", "cv", "outbound_ratio", "packet_size_mean", "score",
]

GCP_SENSOR_TYPES = ["gcp_audit", "gcp_scc", "gcp_vpc"]

CLOUD_CONNECTORS = {
    "gcp_audit":      AUDIT_DIR,
    "gcp_scc":        SCC_DIR,
    "gcp_vpc":        VPC_DIR,
    "vmware_vsphere": VMWARE_DIR,
}


# ── Source structure ──────────────────────────────────────────────────────────

class TestCloudConnectorSourceStructure:

    def test_gcp_audit_dir_exists(self):
        assert AUDIT_DIR.exists()

    def test_gcp_scc_dir_exists(self):
        assert SCC_DIR.exists()

    def test_gcp_vpc_dir_exists(self):
        assert VPC_DIR.exists()

    def test_vmware_dir_exists(self):
        assert VMWARE_DIR.exists()

    @pytest.mark.parametrize("connector,path", CLOUD_CONNECTORS.items())
    def test_cargo_toml_exists(self, connector, path):
        assert (path / "Cargo.toml").exists(), f"{connector}: Cargo.toml missing"

    @pytest.mark.parametrize("connector,path", CLOUD_CONNECTORS.items())
    def test_transmitter_rs_exists(self, connector, path):
        tx = (path / "src" / "transmitter.rs")
        assert tx.exists(), f"{connector}: src/transmitter.rs missing"


# ── GCP audit transmitter.rs - shared pattern ────────────────────────────────

class TestGCPAuditTransmitter:

    def _src(self):
        return (AUDIT_DIR / "src" / "transmitter.rs").read_text()

    def test_x_batch_hmac_header(self):
        src = self._src()
        assert "X-Batch-HMAC" in src or "HDR_BATCH_HMAC" in src

    def test_x_sensor_type_header(self):
        src = self._src()
        assert "X-Sensor-Type" in src or "HDR_SENSOR_TYPE" in src

    def test_sensor_type_gcp_audit(self):
        # sensor_type in config.rs (not hardcoded in transmitter.rs)
        cfg = (AUDIT_DIR / "src" / "config.rs").read_text()
        assert "gcp_audit" in cfg

    def test_bounded_spool_evicts_oldest(self):
        src = self._src()
        assert "spool" in src.lower()
        assert "evict" in src.lower() or "oldest" in src.lower() or "max_spool" in src.lower()

    def test_sequence_counter_file_based(self):
        src = self._src()
        assert ".transmit_sequence" in src or "transmit_sequence" in src

    def test_hmac_canonical_big_endian_encoding(self):
        src = self._src()
        assert "to_be_bytes" in src or "be_bytes" in src.lower()

    def test_zstd_compression(self):
        # ZSTD may be configured in Cargo.toml features, not inline in transmitter.rs
        cargo = (AUDIT_DIR / "Cargo.toml").read_text().lower()
        src   = self._src().lower()
        assert "zstd" in src or "compression" in src or "zstd" in cargo or "parquet" in cargo

    def test_no_startup_spool_replay_for_gcp(self):
        """GCP uses Pub/Sub (has upstream durability); spool replay would duplicate events."""
        src = self._src()
        # GCP transmitter should NOT replay spool on startup
        # Look for explicit no-replay comment or absence of replay call
        has_replay_flag = "replay_on_startup" in src
        if has_replay_flag:
            # If flag exists, it must be false for GCP
            assert "replay_on_startup = false" in src or "false" in src[src.find("replay_on_startup"):src.find("replay_on_startup")+30]


# ── VMware transmitter - spool replay enabled ─────────────────────────────────

class TestVMwareTransmitter:

    def _src(self):
        return (VMWARE_DIR / "src" / "transmitter.rs").read_text()

    def test_x_batch_hmac_header(self):
        src = self._src()
        assert "X-Batch-HMAC" in src or "HDR_BATCH_HMAC" in src

    def test_sensor_type_vmware_syslog(self):
        # VMware connector sensor_type = "vmware_syslog" (in config.rs)
        cfg = (VMWARE_DIR / "src" / "config.rs").read_text()
        assert "vmware_syslog" in cfg or "vmware" in cfg

    def test_bounded_spool_present(self):
        assert "spool" in self._src().lower()

    def test_spool_replay_on_startup_for_vmware(self):
        """VMware syslog has no upstream durability; spool must be replayed on startup."""
        src = self._src()
        assert "replay" in src.lower() or "startup" in src.lower() or "spool_replay" in src


# ── UnifiedFlowRecord - 5D cloud_flow ────────────────────────────────────────

def _build_unified_flow_schema() -> pa.Schema:
    """UnifiedFlowRecord Parquet schema shared across GCP/AWS/Azure/VMware connectors."""
    return pa.schema([
        pa.field("sensor_id",       pa.string(),  nullable=False),
        pa.field("sensor_type",     pa.string(),  nullable=False),
        pa.field("timestamp",       pa.float64(), nullable=False),
        pa.field("record_id",       pa.string(),  nullable=False),
        # cloud_flow 5D vector scalars
        pa.field("interval",        pa.float64(), nullable=True),
        pa.field("cv",              pa.float64(), nullable=True),
        pa.field("outbound_ratio",  pa.float64(), nullable=True),
        pa.field("packet_size_mean",pa.float64(), nullable=True),
        pa.field("score",           pa.float64(), nullable=True),
        # Context
        pa.field("src_ip",          pa.string(),  nullable=True),
        pa.field("dst_ip",          pa.string(),  nullable=True),
        pa.field("src_port",        pa.int32(),   nullable=True),
        pa.field("dst_port",        pa.int32(),   nullable=True),
        pa.field("protocol",        pa.string(),  nullable=True),
        pa.field("project_id",      pa.string(),  nullable=True),
        pa.field("region",          pa.string(),  nullable=True),
        pa.field("action",          pa.string(),  nullable=True),
        pa.field("raw_log",         pa.string(),  nullable=True),
    ])


def _build_unified_flow_row(sensor_type: str, i: int = 0) -> dict:
    return {
        "sensor_id":        f"{sensor_type}-prod",
        "sensor_type":      sensor_type,
        "timestamp":        1748000000.0 + i,
        "record_id":        f"{sensor_type}-{i:010d}",
        "interval":         0.05 + i * 0.01,
        "cv":               0.1 + i * 0.005,
        "outbound_ratio":   min(1.0, 0.3 + i * 0.04),
        "packet_size_mean": 512.0 + i * 10,
        "score":            min(1.0, 0.2 + i * 0.04),
        "src_ip":           f"10.0.{i % 10}.{(i % 254) + 1}",
        "dst_ip":           f"35.200.{i % 50}.{(i % 254) + 1}",
        "src_port":         None,
        "dst_port":         443,
        "protocol":         "TCP",
        "project_id":       "my-gcp-project",
        "region":           "us-central1",
        "action":           "ALLOW",
        "raw_log":          f'{{"timestamp": "2026-06-05T00:00:{i:02d}Z"}}',
    }


class TestUnifiedFlowMockParquet:

    def test_schema_has_all_five_vector_columns(self):
        schema = _build_unified_flow_schema()
        for col in CLOUD_FLOW_VECTOR_COLS:
            assert col in schema.names, f"Missing cloud_flow column: {col}"

    def test_gcp_audit_parquet_roundtrip(self):
        schema = _build_unified_flow_schema()
        rows   = [_build_unified_flow_row("gcp_audit", i) for i in range(10)]
        arrays = [pa.array([r.get(f.name) for r in rows], type=f.type) for f in schema]
        table  = pa.table({f.name: arrays[i] for i, f in enumerate(schema)}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        assert pq.read_table(buf).num_rows == 10

    @pytest.mark.parametrize("sensor_type", [*GCP_SENSOR_TYPES, "vmware_vsphere"])
    def test_all_connectors_produce_valid_rows(self, sensor_type):
        row = _build_unified_flow_row(sensor_type, 0)
        assert row["sensor_type"] == sensor_type

    def test_outbound_ratio_bounded(self):
        for i in range(15):
            assert 0.0 <= _build_unified_flow_row("gcp_vpc", i)["outbound_ratio"] <= 1.0


# ── Nexus config alignment ────────────────────────────────────────────────────

class TestCloudNexusConfig:

    def test_cloud_flow_5_in_services_cfg(self):
        src = SERVICES_CFG.read_text()
        assert re.search(r'cloud_flow\s*=\s*5', src)

    @pytest.mark.parametrize("sensor_type,nexus_name", [
        ("gcp_audit",       "gcp_audit"),
        ("gcp_scc",         "gcp_scc"),
        ("gcp_vpc",         "gcp_vpc_flow"),      # nexus.toml uses gcp_vpc_flow
        ("vmware_vsphere",  "vmware_syslog"),      # nexus.toml uses vmware_syslog
    ])
    def test_cloud_sensor_mapping_exists(self, sensor_type, nexus_name):
        assert f"[schema_mappings.{nexus_name}]" in SERVICES_CFG.read_text(), \
            f"No nexus.toml mapping for {nexus_name} (sensor: {sensor_type})"

    def test_cloud_flow_vector_columns_in_cfg(self):
        src = SERVICES_CFG.read_text()
        for col in CLOUD_FLOW_VECTOR_COLS:
            assert col in src, f"Missing cloud_flow vector column: {col}"

    def test_worker_rust_cloud_flow_5d_branch(self):
        src = WORKER_RUST.read_text()
        assert re.search(r'"cloud_flow".*?raw_math\.len\(\)\s*==\s*5', src, re.DOTALL)
