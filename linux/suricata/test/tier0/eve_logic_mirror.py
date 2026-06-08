"""
Python-side mirror of the suricata_transmitter's contract-relevant logic.

The transmitter is a single Rust binary crate with no Python component, so
(unlike c2_sensor where we import the real engine) the algorithm itself is
exercised directly via `cargo test` (see test/tier1). This module instead
re-derives the two pieces of the contract that *must* match byte-for-byte
across the Rust/Python boundary -- the Parquet column layout and the HMAC
integrity formula -- so tier0 can independently cross-check them against the
central `nexus.toml` contract and a live mock ingress, without a Rust runtime.

Every constant below is annotated with its Rust source of truth so a future
change to main.rs that isn't mirrored here fails loudly.
"""
import hashlib
import hmac
import struct

# src: linux/suricata/transmitter/src/main.rs eve_schema() (lines ~180-231)
# Full ordered Parquet column layout emitted by events_to_parquet().
EVE_SCHEMA_COLUMNS = [
    "timestamp", "flow_id", "event_type", "src_ip", "src_port",
    "dest_ip", "dest_port", "proto", "community_id", "in_iface",
    "alert_action", "signature", "signature_id", "severity", "category",
    "mitre_tactic", "mitre_technique",
    "flow_pkts_toserver", "flow_pkts_toclient", "flow_bytes_toserver",
    "flow_bytes_toclient", "flow_state",
    "dns_type", "dns_rrname", "dns_rcode", "dns_rrtype",
    "http_hostname", "http_url", "http_method", "http_user_agent", "http_status",
    "tls_version", "tls_subject", "tls_issuer", "tls_ja3_hash", "tls_ja3s_hash",
    "file_filename", "file_size", "file_sha256",
    "sensor_id", "sensor_type",
]

# src: linux/suricata/transmitter/src/main.rs Config::from_env() (default gateway_url)
DEFAULT_GATEWAY_URL = "https://nexus-edge:8080/api/v1/telemetry"

# src: linux/suricata/transmitter/src/main.rs events_to_parquet() -- stype_b.append_value(...)
SENSOR_TYPE = "suricata_eve"

# src: linux/suricata/transmitter/src/main.rs transmit() header set
REQUIRED_HEADERS = (
    "Content-Type",
    "X-Sensor-Type",
    "X-Sensor-Id",
    "X-Batch-Sequence",
    "X-Batch-Timestamp",
    "X-Batch-HMAC",
)
CONTENT_TYPE = "application/vnd.apache.parquet"

def compute_hmac(secret: bytes, payload: bytes, sequence: int, sensor_id: str, timestamp: int) -> str:
    """src: Stamper::stamp() -- HMAC-SHA256(payload || seq.BE64 || sensor_id || ts.BE64).

    Byte-identical to the central core_ingress contract
    (project_empros/middleware/src/core_ingress) and to Stamper::stamp in main.rs:
        mac.update(payload);
        mac.update(&self.sequence.to_be_bytes());
        mac.update(self.sensor_id.as_bytes());
        mac.update(&ts.to_be_bytes());
    """
    mac = hmac.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()