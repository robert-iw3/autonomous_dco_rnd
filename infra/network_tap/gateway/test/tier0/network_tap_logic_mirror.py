"""
Python-side mirror of the network_tap gateway's contract-relevant transmission
logic.
"""
import hashlib
import hmac
import struct

# src: infra/network_tap/gateway/src/transmit/nexus.rs:30-94 flow_schema()
# Arrow Schema for Nexus transmission, emitted by transmit_loop()'s
# Parquet-forwarder. Order matches the Field::new(...) declarations exactly --
# it is also the order the RecordBatch column Vec is built in (lines 443-492),
# so a reorder here without a matching reorder there would silently scramble
# the wire data while still "type-checking".
EXPECTED_NETWORK_TAP_PARQUET_COLUMNS = [
    "session_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "protocol_name",
    "timestamp_start", "timestamp_end", "session_duration_ms",
    "bytes_src", "bytes_dst", "data_bytes_src", "data_bytes_dst", "packets_src", "packets_dst",
    "byte_ratio", "avg_inter_arrival", "variance_inter_arrival",
    "ratio_small_packets", "ratio_large_packets", "payload_entropy",
    "tcp_syn", "tcp_rst", "tcp_fin",
    "dns_query", "dns_status",
    "http_method", "http_uri", "http_useragent", "http_status_code",
    "tls_ja3", "tls_ja3s", "tls_version", "tls_cipher",
    "cert_cn", "cert_issuer_cn", "cert_self_signed", "cert_valid_days",
    "hostname", "src_geo_country", "dst_geo_country", "dst_asn_org",
    "sensor_name", "sensor_type",
    "is_internal_dst", "port_class", "schema_version",
]

# src: infra/network_tap/gateway/src/transmit/nexus.rs:28
SCHEMA_VERSION = "v2"

# src: infra/network_tap/gateway/config.toml [global] sensor_type
# (read at runtime as cfg.global.sensor_type and stamped verbatim into both
# the X-Sensor-Type header (nexus.rs:126-128) and the "sensor_type" Parquet
# column (nexus.rs:431) -- unlike linux_sentinel's hardcoded
# header::HeaderValue::from_static("Linux-Sentinel"), network_tap's wire
# sensor type is config-driven, so the deployed config.toml *is* the contract.)
WIRE_SENSOR_TYPE = "network_tap"

# src: infra/network_tap/gateway/src/transmit/nexus.rs:174
#   let sensor_id = format!("{}-{}", cfg.global.sensor_name, cfg.global.sensor_type);
# i.e. "network-tap-alpha-network_tap" for the shipped config.toml.
def sensor_id_for(sensor_name: str, sensor_type: str) -> str:
    return f"{sensor_name}-{sensor_type}"

# src: infra/network_tap/gateway/src/transmit/nexus.rs:122-124
CONTENT_TYPE = "application/vnd.apache.parquet"

# src: infra/network_tap/gateway/config.toml [nexus] gateway_url default
DEFAULT_GATEWAY_URL = "https://nexus-edge.local:443/api/v1/telemetry"

# src: infra/network_tap/gateway/src/integrity/mod.rs
# Shared verbatim with every other Nexus sensor (sentinel, suricata, sysmon,
# c2_sensor, etc) -- HTTP header names are case-insensitive on the wire.
HDR_SENSOR_ID = "X-Sensor-Id"
HDR_BATCH_SEQUENCE = "X-Batch-Sequence"
HDR_BATCH_TIMESTAMP = "X-Batch-Timestamp"
HDR_BATCH_HMAC = "X-Batch-Hmac"

# src: infra/network_tap/gateway/src/transmit/nexus.rs:542-551
#   client.post(&cfg.nexus.gateway_url)
#       .bearer_auth(&cfg.nexus.auth_token)               -> Authorization
#       .header(HDR_BATCH_SEQUENCE, ...)
#       .header(HDR_BATCH_TIMESTAMP, ...)
#       .header(HDR_SENSOR_ID, ...)
#       .header(HDR_BATCH_HMAC, ...)
#       .header("X-Partition-Date", ...)                  -- gateway-computed, not part of the integrity contract
#       .header("X-Partition-Hour", ...)
# plus the two default client headers (Content-Type, X-Sensor-Type) set at
# lines 121-128 via .default_headers(headers).
REQUIRED_HEADERS = (
    "Authorization",
    "Content-Type",
    "X-Sensor-Type",
    HDR_SENSOR_ID,
    HDR_BATCH_SEQUENCE,
    HDR_BATCH_TIMESTAMP,
    HDR_BATCH_HMAC,
)

# src: infra/network_tap/gateway/src/transmit/nexus.rs:549-550 -- computed
# server-side from the verified batch's partition hints (extract_partition_hints,
# lines 96-111), NOT part of the sensor-authenticity/integrity contract.
GATEWAY_COMPUTED_HEADERS = ("X-Partition-Date", "X-Partition-Hour")


def compute_hmac(secret: bytes, payload: bytes, sequence: int, sensor_id: str, timestamp: int) -> str:
    """src: infra/network_tap/gateway/src/integrity/stamper.rs LineageStamper::stamp()

    Byte-identical to the central core_ingress contract
    (project_empros/services/core_ingress/src/integrity.rs compute_hmac) and to
    every other Nexus sensor (sentinel's nexus_integrity::LineageStamper,
    sysmon's ParquetShipper._compute_hmac, c2_sensor's batch_integrity):
        mac.update(data);                            // 1. parquet payload
        mac.update(&self.sequence.to_be_bytes());    // 2. big-endian u64
        mac.update(self.sensor_id.as_bytes());       // 3. sensor_id UTF-8
        mac.update(&timestamp.to_be_bytes());        // 4. big-endian u64

    stamper.rs's own docstring records that an earlier LE / wrong-field-order
    version of this exact formula (seq_LE || ts_LE || sensor_id || parquet) got
    every network_tap batch rejected with 400 and the sensor banned -- this
    mirror exists so that regression can never recur silently on the Python
    validation side either.
    """
    mac = hmac.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()
