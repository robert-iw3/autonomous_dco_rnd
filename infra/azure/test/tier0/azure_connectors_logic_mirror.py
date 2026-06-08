"""
Python-side mirror of the wire-contract pieces shared by all three Nexus Azure
connectors (nexus-azure-nsg-connector, nexus-azure-activity-connector,
nexus-azure-entraid-connector).

`diff` confirms transmitter.rs is byte-identical across all three crates, and
config.rs/cache.rs differ only in per-connector fields and string literals
(nsg additionally carries storage_account_url/storage_container/table_storage_url
and spool-bound fields that activity/entraid lack or vary) -- so the HMAC
formula, the 31-column Parquet schema, and the (now 7-header, see REQUIRED_HEADERS
below) wire contract apply verbatim to all three.
"""
import hashlib
import hmac
import struct

# src: infra/azure/{nsg,activity,entraid}/src/transmitter.rs to_parquet()
# Order matches the Field::new(...) declarations exactly, which is also the
# order the RecordBatch column Vec is built in immediately below them -- a
# reorder here without a matching reorder there would silently scramble the
# wire data while still "type-checking" (UnifiedFlowRecord has the same field
# order in transformer.rs, but Arrow doesn't enforce that at compile time).
# This is the SAME 31-column schema as infra/aws -- both emit UnifiedFlowRecord
# onto the shared `cloud_flow` named vector.
EXPECTED_AZURE_PARQUET_COLUMNS = [
    "timestamp", "process_name", "dst_ip", "dst_port",
    "interval", "cv", "outbound_ratio", "entropy",
    "packet_size_mean", "packet_size_std", "packet_size_min", "packet_size_max", "packet_count",
    "mitre_tactic", "cmd_entropy", "suppressed", "score",
    "cmd_snippet", "process_tree", "masquerade_detected", "reasons",
    "mitre_technique", "mitre_name", "description", "ml_result",
    "process_hash", "dns_query", "event_type", "dns_flags", "ja3_hash",
    "sensor_id",
]

# src: infra/azure/{nsg,activity,entraid}/src/transmitter.rs -- the lone
# nullable column (Field::new("ml_result", DataType::Utf8, true)); every other
# field is declared non-nullable (`false`).
NULLABLE_COLUMNS = ("ml_result",)

# src: infra/azure/{nsg,activity,entraid}/src/config.rs -- sensor_type is a
# hardcoded string literal (NOT env-configurable), so the deployed binary *is*
# the contract.
WIRE_SENSOR_TYPE = {
    "nsg": "azure-nsg-flow-connector",
    "activity": "azure-activity-connector",
    "entraid": "azure-entraid-connector",
}

# src: infra/azure/{nsg,activity,entraid}/src/config.rs -- default sensor_id
# (overridable via SENSOR_ID env var; these are the `unwrap_or_else` fallbacks).
DEFAULT_SENSOR_ID = {
    "nsg": "azure-nsg-connector-default",
    "activity": "azure-activity-connector-default",
    "entraid": "azure-entraid-connector-default",
}

# src: infra/azure/{nsg,activity}/src/transformer.rs
#   let sensor_id = format!("{}|{}|{}", subscription_id, environment, region);
# Same pipe-delimited-triple *shape* as infra/aws's account|environment|region
# (and thus the same wire shape core_ingress parses/keys on), but the semantic
# components differ: Azure keys on subscription_id rather than account/vpc_id.
def sensor_id_for_flow(subscription_id: str, environment: str, region: str) -> str:
    return f"{subscription_id}|{environment}|{region}"

# src: infra/azure/entraid/src/transformer.rs (transform_signin / transform_audit)
#   let sensor_id = format!("{}|entraid|signin", tenant_id);
#   let sensor_id = format!("{}|entraid|audit", tenant_id);
# entraid's sensor_id formula is STRUCTURALLY DIFFERENT from nsg/activity's:
# the last two pipe-delimited components are fixed literals ("entraid"/category)
# rather than semantic environment/region lookups -- entraid carries no
# subscription/environment/region context (Entra ID is tenant-scoped, not
# subscription-scoped), so it encodes category instead. NOT a bug: confirmed by
# reading transform_signin/transform_audit -- there is no metadata map or
# environment/region lookup anywhere in entraid's transformer.
def sensor_id_for_entraid(tenant_id: str, category: str) -> str:
    assert category in ("signin", "audit")
    return f"{tenant_id}|entraid|{category}"

# src: infra/azure/{nsg,activity,entraid}/src/transmitter.rs:280-285
CONTENT_TYPE = "application/vnd.apache.parquet"

# src: infra/azure/{nsg,activity,entraid}/src/transmitter.rs transmit_bytes()
# header literal strings at the .header() call sites (no shared integrity
# module import here, same pattern as infra/aws).
HDR_SENSOR_ID = "X-Sensor-Id"
HDR_SENSOR_TYPE = "X-Sensor-Type"
HDR_BATCH_SEQUENCE = "X-Batch-Sequence"
HDR_BATCH_TIMESTAMP = "X-Batch-Timestamp"
HDR_BATCH_HMAC = "X-Batch-HMAC"

# src: infra/azure/{nsg,activity,entraid}/src/transmitter.rs transmit_bytes()
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

# Azure connectors do not send X-Partition-* hints (unlike network_tap) -- they
# are pure pull-connectors (Event Hub consumers) with no equivalent server-side
# partition logic to mirror, so there is no GATEWAY_COMPUTED_HEADERS set here.

def compute_hmac(secret: bytes, payload: bytes, sequence: int, sensor_id: str, timestamp: int) -> str:
    """src: infra/azure/{nsg,activity,entraid}/src/transmitter.rs compute_hmac()

    Byte-identical to the central core_ingress contract
    (project_empros/services/core_ingress/src/integrity.rs) and to every other
    Nexus sensor (network_tap, sentinel, sysmon, c2_sensor, k8s, suricata, aws):
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