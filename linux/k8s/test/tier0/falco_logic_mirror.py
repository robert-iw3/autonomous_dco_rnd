"""
Python-side mirror of the falco_transmitter's contract-relevant logic.

The transmitter is a single Rust binary crate with no Python component and no
embedded #[cfg(test)] suite (see test/tier1 -- it's pure build/compile/link
validation here), so this module independently re-derives the two pieces of
the contract that *must* match byte-for-byte across the Rust/Python boundary --
the Parquet column layout and the HMAC integrity formula -- so tier0 can
cross-check them against the central `nexus.toml` contract and a live mock
ingress, without a Rust runtime.

Every constant below is annotated with its Rust source of truth so a future
change to main.rs that isn't mirrored here fails loudly.
"""
import hashlib
import hmac
import struct

# src: linux/k8s/transmitter/src/main.rs falco_schema() (lines ~104-150)
# Full ordered Parquet column layout emitted by events_to_parquet(). Includes
# the derived `event_id` + 4D `falco_math` feature columns (priority_score,
# container_scope_score, network_activity_score, privileged_score) computed
# in-sensor by compute_falco_math_features() -- added to close the central
# registration gap (see readme.md "Findings fixed").
FALCO_SCHEMA_COLUMNS = [
    "timestamp", "priority", "rule", "source", "output", "hostname", "tags",
    "container_id", "container_name", "container_image",
    "proc_name", "proc_cmdline", "proc_pname", "proc_ppid", "proc_exepath",
    "user_name", "user_uid",
    "evt_type",
    "fd_name", "fd_sip", "fd_dip", "fd_sport", "fd_dport", "fd_l4proto",
    "raw_fields",
    "event_id",
    "priority_score", "container_scope_score", "network_activity_score", "privileged_score",
    "sensor_id", "sensor_type",
]

# src: linux/k8s/transmitter/src/main.rs Config::from_env() (NEXUS_GATEWAY_URL fallback)
DEFAULT_GATEWAY_URL = "https://nexus-edge:8080/api/v1/telemetry"

# src: linux/k8s/transmitter/src/main.rs events_to_parquet() -- stype_b.append_value("falco_runtime")
# and transmit_parquet()'s X-Sensor-Type header literal.
SENSOR_TYPE = "falco_runtime"

# src: linux/k8s/transmitter/src/main.rs transmit_parquet() header set.
# Note: unlike linux_sentinel (where X-Partition-Date/Hour are gateway-injected),
# falco_transmitter sends its own X-Partition-Date/X-Partition-Hour -- core_ingress
# forwards them downstream verbatim if present (main.rs:334-339, "Forward Hive
# partition hints if present"), it doesn't require or overwrite them.
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
    (project_empros/services/core_ingress/src/integrity.rs compute_hmac) and to
    Stamper::stamp in main.rs:
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