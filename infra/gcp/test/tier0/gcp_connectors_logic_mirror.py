"""
Python-side mirror of the wire-contract pieces shared by all three Nexus GCP
connectors (nexus-gcp-audit-connector, nexus-gcp-scc-connector,
nexus-gcp-vpc-connector).
"""
import hashlib
import hmac
import struct

# src: infra/gcp/{audit,scc,vpc}/src/transmitter.rs to_parquet()
# Order matches Field::new() declarations exactly; same 31-column schema as AWS/Azure.
EXPECTED_GCP_PARQUET_COLUMNS = [
    "timestamp", "process_name", "dst_ip", "dst_port",
    "interval", "cv", "outbound_ratio", "entropy",
    "packet_size_mean", "packet_size_std", "packet_size_min", "packet_size_max", "packet_count",
    "mitre_tactic", "cmd_entropy", "suppressed", "score",
    "cmd_snippet", "process_tree", "masquerade_detected", "reasons",
    "mitre_technique", "mitre_name", "description", "ml_result",
    "process_hash", "dns_query", "event_type", "dns_flags", "ja3_hash",
    "sensor_id",
]

# The lone nullable column (Field::new("ml_result", DataType::Utf8, true)).
NULLABLE_COLUMNS = ("ml_result",)

# src: infra/gcp/{audit,scc,vpc}/src/config.rs -- sensor_type is hardcoded.
WIRE_SENSOR_TYPE = {
    "audit": "gcp_audit",
    "scc":   "gcp_scc",
    "vpc":   "gcp_vpc_flow",
}

# src: infra/gcp/{audit,scc,vpc}/src/config.rs -- default sensor_id fallbacks.
DEFAULT_SENSOR_ID = {
    "audit": "gcp-audit-connector-default",
    "scc":   "gcp-scc-connector-default",
    "vpc":   "gcp-vpc-connector-default",
}

# src: infra/gcp/{audit,scc,vpc}/src/transformer.rs -- event_type stamped per connector.
WIRE_EVENT_TYPE = {
    "audit": "gcp_audit_log",
    "scc":   "gcp_scc_finding",
    "vpc":   "gcp_vpc_flow",
}

# src: infra/gcp/vpc/src/transformer.rs
#   let sensor_id = format!("{}|{}|{}|{}", project_id, environment, region, subnetwork);
# Four-component pipe-delimited identity (richer than AWS 3-tuple because GCP
# VPC flow logs carry subnetwork context inline).
def sensor_id_for_vpc(project_id: str, environment: str, region: str, subnetwork: str) -> str:
    return f"{project_id}|{environment}|{region}|{subnetwork}"

# src: infra/gcp/{audit,scc}/src/config.rs -- sensor_id from env (no runtime derivation).
# audit/scc both use a flat sensor_id from the SENSOR_ID env var.

# src: infra/gcp/{audit,scc,vpc}/src/transmitter.rs
CONTENT_TYPE = "application/vnd.apache.parquet"

# src: infra/gcp/{audit,scc,vpc}/src/transmitter.rs transmit_bytes()
HDR_SENSOR_ID       = "X-Sensor-Id"
HDR_SENSOR_TYPE     = "X-Sensor-Type"
HDR_BATCH_SEQUENCE  = "X-Batch-Sequence"
HDR_BATCH_TIMESTAMP = "X-Batch-Timestamp"
HDR_BATCH_HMAC      = "X-Batch-HMAC"

# 7 required headers including Authorization (bearer_auth) added to match
# the core_ingress validate_token expectation shared by all Nexus connectors.
REQUIRED_HEADERS = (
    "Authorization",
    "Content-Type",
    HDR_BATCH_SEQUENCE,
    HDR_BATCH_TIMESTAMP,
    HDR_SENSOR_ID,
    HDR_SENSOR_TYPE,
    HDR_BATCH_HMAC,
)

# src: infra/gcp/{audit,scc,vpc}/src/config.rs -- spool_replay must stay false
# for all queue-backed (Pub/Sub) transports. Pub/Sub redelivers nacked messages,
# so replaying the spool on boot would duplicate data.
SPOOL_REPLAY = False

def compute_hmac(secret: bytes, payload: bytes, sequence: int, sensor_id: str, timestamp: int) -> str:
    """src: infra/gcp/{audit,scc,vpc}/src/transmitter.rs compute_hmac()

    Same byte-layout as all other Nexus sensors (aws, azure, network_tap, etc.)
    and core_ingress/src/integrity.rs:
        msg.extend_from_slice(payload);
        msg.extend_from_slice(&sequence.to_be_bytes());
        msg.extend_from_slice(sensor_id.as_bytes());
        msg.extend_from_slice(&timestamp.to_be_bytes());
    """
    mac = hmac.new(secret, digestmod=hashlib.sha256)
    mac.update(payload)
    mac.update(struct.pack(">Q", sequence))
    mac.update(sensor_id.encode("utf-8"))
    mac.update(struct.pack(">Q", timestamp))
    return mac.hexdigest()