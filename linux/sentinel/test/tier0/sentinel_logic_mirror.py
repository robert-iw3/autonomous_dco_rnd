"""
Python-side mirror of linux-sentinel's contract-relevant transmission logic.

linux-sentinel is a single Rust binary crate (eBPF + YARA + ML telemetry agent)
with no Python component, so the algorithm itself is exercised directly via
`cargo test` (see test/tier1, particularly test_sensor_pipeline.rs's real
events_to_parquet()/Arrow round-trip coverage). This module instead re-derives
the pieces of the wire contract that *must* match byte-for-byte across the
Rust/Python boundary -- the Parquet column layout, the X-Sensor-Type string,
the HMAC integrity formula (shared with every other Nexus sensor via the
nexus_integrity crate), and the required header set -- so tier0 can
independently cross-check them against the central nexus.toml contract and a
live mock ingress, without a Rust runtime.

Every constant below is annotated with its Rust source of truth so a future
change to parquet_transmitter.rs / nexus_integrity that isn't mirrored here
fails loudly.
"""
import hashlib
import hmac
import struct

# src: linux/sentinel/src/siem/parquet_transmitter.rs:333-358
# Arrow Schema for Nexus transmission, emitted by the Parquet-forwarder task.
# (Distinct from flush_to_disk()'s local 72h cache schema at lines ~689-717,
# which uses "endpoint_id" instead of "sensor_id" and is not subject to the
# wire contract.)
EXPECTED_SENTINEL_PARQUET_COLUMNS = [
    "event_id", "sensor_id", "timestamp",
    "level", "mitre_tactic", "mitre_technique",
    "pid", "ppid", "uid", "container_name",
    "comm", "command_line", "parent_comm", "user_name",
    "target_file", "dest_ip", "dest_port",
    "shannon_entropy", "execution_velocity", "tuple_rarity", "path_depth", "anomaly_score",
    "message", "in_memory_capture", "ml_vector",
]

# src: linux/sentinel/src/siem/parquet_transmitter.rs:151
# headers.insert("X-Sensor-Type", header::HeaderValue::from_static("Linux-Sentinel"));
#
# NOTE: this PascalCase-hyphen wire value intentionally differs from the
# lowercase [schema_mappings.linux_sentinel] table key in nexus.toml -- the
# table key is used only for worker_qdrant/worker_rules duck-typed routing,
# while "Linux-Sentinel" is the literal value declared in
# sensor_profiles/linux_sentinel.toml and exact-matched by worker_splunk /
# worker_elastic, and is now also the corrected key in core_ingress's
# build_os_exclusion_rules() cross-OS collision map (see test_schema_contract).
WIRE_SENSOR_TYPE = "Linux-Sentinel"

# src: linux/sentinel/src/siem/parquet_transmitter.rs:152
CONTENT_TYPE = "application/vnd.apache.parquet"

# src: linux/sentinel/master.toml:84 -- middleware_gateway_url default
DEFAULT_GATEWAY_URL = "https://nexus-edge.local:443/api/v1/telemetry"

# src: linux/sentinel/src/siem/parquet_transmitter.rs:114-117
#   sensor_id = format!("{}-sentinel", env(SENTINEL_SENSOR_ID) || env(HOSTNAME) || "unknown")
SENSOR_ID_SUFFIX = "-sentinel"

# src: windows/windows_xdr_dev/nexus_integrity/src/lib.rs -- HDR_* constants,
# shared verbatim by every Nexus sensor that links nexus_integrity (sentinel,
# windows xdr_agent, transmission crate). HTTP header names are
# case-insensitive on the wire, so "X-Batch-Hmac" here and suricata's literal
# "X-Batch-HMAC" canonicalize identically -- the *set* must match, not casing.
HDR_SENSOR_ID = "X-Sensor-Id"
HDR_BATCH_SEQUENCE = "X-Batch-Sequence"
HDR_BATCH_TIMESTAMP = "X-Batch-Timestamp"
HDR_BATCH_HMAC = "X-Batch-Hmac"

# src: linux/sentinel/src/siem/parquet_transmitter.rs:517-522 (.bearer_auth + 4 .header() calls)
# plus the two default client headers inserted at lines 151-152.
REQUIRED_HEADERS = (
    "Authorization",
    "Content-Type",
    "X-Sensor-Type",
    HDR_SENSOR_ID,
    HDR_BATCH_SEQUENCE,
    HDR_BATCH_TIMESTAMP,
    HDR_BATCH_HMAC,
)

def compute_hmac(secret: bytes, payload: bytes, sequence: int, sensor_id: str, timestamp: int) -> str:
    """src: windows/windows_xdr_dev/nexus_integrity/src/stamper.rs LineageStamper::stamp()

    Byte-identical to the central core_ingress contract
    (project_empros/services/core_ingress/src/integrity.rs compute_hmac) and to
    every other Nexus sensor (e.g. suricata's Stamper::stamp):
        mac.update(data);                            // 1. parquet payload
        mac.update(&self.sequence.to_be_bytes());    // 2. big-endian u64
        mac.update(self.sensor_id.as_bytes());       // 3. sensor_id UTF-8
        mac.update(&timestamp.to_be_bytes());        // 4. big-endian u64

    The stamper.rs docstring records that a prior LE/wrong-field-order version
    of this exact formula caused every batch to be rejected with 400 and the
    sensor banned -- this mirror exists so that regression can never recur
    silently on the Python validation side either.
    """
    mac = hmac.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()