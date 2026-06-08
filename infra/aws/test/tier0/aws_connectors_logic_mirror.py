"""
Python-side mirror of the wire-contract pieces shared by all three Nexus AWS
connectors (nexus-aws-vpc-connector, nexus-aws-cloudtrail-connector,
nexus-aws-guardduty-connector).

`diff` confirms transmitter.rs and config.rs are byte-identical across all
three crates except for two per-connector string literals (`sensor_type` and
the default `sensor_id`) -- so the HMAC formula, the 31-column Parquet schema,
and the 7-header wire contract below apply verbatim to all three.
"""
import hashlib
import hmac
import struct

# src: infra/aws/{vpc,cloudtrail,guardduty}/src/transmitter.rs:78-110 to_parquet()
# Order matches the Field::new(...) declarations exactly, which is also the
# order the RecordBatch column Vec is built in immediately below them -- a
# reorder here without a matching reorder there would silently scramble the
# wire data while still "type-checking" (UnifiedFlowRecord has the same field
# order in transformer.rs, but Arrow doesn't enforce that at compile time).
EXPECTED_AWS_PARQUET_COLUMNS = [
    "timestamp", "process_name", "dst_ip", "dst_port",
    "interval", "cv", "outbound_ratio", "entropy",
    "packet_size_mean", "packet_size_std", "packet_size_min", "packet_size_max", "packet_count",
    "mitre_tactic", "cmd_entropy", "suppressed", "score",
    "cmd_snippet", "process_tree", "masquerade_detected", "reasons",
    "mitre_technique", "mitre_name", "description", "ml_result",
    "process_hash", "dns_query", "event_type", "dns_flags", "ja3_hash",
    "sensor_id",
]

# src: infra/aws/{vpc,cloudtrail,guardduty}/src/transmitter.rs:97 -- the lone
# nullable column (Field::new("ml_result", DataType::Utf8, true)); every other
# field is declared non-nullable (`false`).
NULLABLE_COLUMNS = ("ml_result",)

# src: infra/aws/{vpc,cloudtrail,guardduty}/src/config.rs -- sensor_type is a
# hardcoded string literal (NOT env-configurable, unlike network_tap's
# config.toml-driven sensor_type), so the deployed binary *is* the contract.
WIRE_SENSOR_TYPE = {
    "vpc": "aws-vpc-flow-connector",
    "cloudtrail": "aws-cloudtrail-connector",
    "guardduty": "aws-guardduty-connector",
}

# src: infra/aws/{vpc,cloudtrail,guardduty}/src/config.rs -- default sensor_id
# (overridable via SENSOR_ID env var; these are the `unwrap_or_else` fallbacks).
DEFAULT_SENSOR_ID = {
    "vpc": "aws-vpc-connector-default",
    "cloudtrail": "cloudtrail-connector-default",
    "guardduty": "aws-guardduty-connector-default",
}

# src: infra/aws/{vpc,cloudtrail,guardduty}/src/transformer.rs
#   let sensor_id = format!("{}|{}|{}", account_id, environment, region);
# i.e. pipe-delimited account|environment|region triple -- identical formula
# across all three connectors (vpc keys it as vpc_id|environment|region in its
# own transform, but cloudtrail/guardduty both use account_id|environment|region).
def sensor_id_for(a: str, b: str, c: str) -> str:
    return f"{a}|{b}|{c}"

# src: infra/aws/{vpc,cloudtrail,guardduty}/src/transmitter.rs:280-285
CONTENT_TYPE = "application/vnd.apache.parquet"

# src: infra/aws/{vpc,cloudtrail,guardduty}/src/integrity headers (literal
# strings at the .header() call sites -- there is no shared integrity module
# import here, unlike network_tap/sentinel which use HDR_* constants).
HDR_SENSOR_ID = "X-Sensor-Id"
HDR_SENSOR_TYPE = "X-Sensor-Type"
HDR_BATCH_SEQUENCE = "X-Batch-Sequence"
HDR_BATCH_TIMESTAMP = "X-Batch-Timestamp"
HDR_BATCH_HMAC = "X-Batch-HMAC"

# src: infra/aws/{vpc,cloudtrail,guardduty}/src/transmitter.rs transmit_bytes()
#   client.post(&self.config.gateway_url)
#       .bearer_auth(&self.config.auth_token)        -> Authorization
#       .header("Content-Type", ...)
#       .header("X-Batch-Sequence", ...)
#       .header("X-Batch-Timestamp", ...)
#       .header("X-Sensor-Id", ...)
#       .header("X-Sensor-Type", ...)
#       .header("X-Batch-HMAC", ...)
REQUIRED_HEADERS = (
    "Authorization",
    "Content-Type",
    HDR_BATCH_SEQUENCE,
    HDR_BATCH_TIMESTAMP,
    HDR_SENSOR_ID,
    HDR_SENSOR_TYPE,
    HDR_BATCH_HMAC,
)

# AWS connectors do not send X-Partition-* hints (unlike network_tap) -- they
# are pure pull-connectors with no equivalent server-side partition logic to
# mirror, so there is no GATEWAY_COMPUTED_HEADERS set here.

def compute_hmac(secret: bytes, payload: bytes, sequence: int, sensor_id: str, timestamp: int) -> str:
    """src: infra/aws/{vpc,cloudtrail,guardduty}/src/transmitter.rs:64-75 compute_hmac()

    Byte-identical to the central core_ingress contract
    (project_empros/services/core_ingress/src/integrity.rs) and to every other
    Nexus sensor (network_tap, sentinel, sysmon, c2_sensor, k8s, suricata):
        msg.extend_from_slice(payload);                     // 1. parquet payload
        msg.extend_from_slice(&sequence.to_be_bytes());     // 2. big-endian u64
        msg.extend_from_slice(sensor_id.as_bytes());        // 3. sensor_id UTF-8
        msg.extend_from_slice(&timestamp.to_be_bytes());    // 4. big-endian u64
    """
    mac = hmac.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()