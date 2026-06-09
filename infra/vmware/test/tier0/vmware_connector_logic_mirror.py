"""
Python mirror of the VMware connector wire contract.

Used by tier0 tests to verify Rust source matches the expected protocol
without running the connector binary.
"""
import hashlib
import hmac as _hmac
import struct

# ---------------------------------------------------------------------------
# Parquet schema
# ---------------------------------------------------------------------------
EXPECTED_PARQUET_COLUMNS = [
    "timestamp", "process_name", "dst_ip", "dst_port", "interval", "cv",
    "outbound_ratio", "entropy", "packet_size_mean", "packet_size_std",
    "packet_size_min", "packet_size_max", "packet_count", "mitre_tactic",
    "cmd_entropy", "suppressed", "score", "cmd_snippet", "process_tree",
    "masquerade_detected", "reasons", "mitre_technique", "mitre_name",
    "description", "ml_result", "process_hash", "dns_query", "event_type",
    "dns_flags", "ja3_hash", "sensor_id",
]
NULLABLE_COLUMNS = ("ml_result",)

# ---------------------------------------------------------------------------
# Wire contract
# ---------------------------------------------------------------------------
WIRE_SENSOR_TYPE  = "vmware_syslog"
DEFAULT_SENSOR_ID = "vmware-connector-default"
CONTENT_TYPE      = "application/vnd.apache.parquet"

# VMware syslog is not queue-backed — the connector spools locally and
# replays on restart so batches are not lost between crashes.
SPOOL_REPLAY = True

REQUIRED_HEADERS = (
    "Authorization",       # Bearer <auth_token>  -- gateway rejects without this
    "Content-Type",
    "X-Batch-Sequence",
    "X-Batch-Timestamp",
    "X-Sensor-Id",
    "X-Sensor-Type",
    "X-Batch-HMAC",
)

# ---------------------------------------------------------------------------
# Event types emitted by the single VMware connector
# ---------------------------------------------------------------------------
EVENT_TYPES = frozenset({"vmware_nsx_flow", "vmware_vcenter_event", "vmware_syslog"})

# Per-event sensor_id subsystem suffixes appended by the transformer.
# The HTTP header X-Sensor-Id uses the BASE sensor_id (no suffix);
# the Parquet column uses the suffixed form.
SENSOR_ID_SUBSYSTEM_NSX     = "|nsx"
SENSOR_ID_SUBSYSTEM_VCENTER = "|vcenter"
SENSOR_ID_SUBSYSTEM_ESXI    = "|esxi"

# Cache key separator for TemporalCache beaconing detection.
TEMPORAL_CACHE_KEY_FORMAT = "{src_ip}|{dst_ip}"

# ---------------------------------------------------------------------------
# NSX-T firewall verdict → score / MITRE tactic
# ---------------------------------------------------------------------------
NSX_DENY_VERDICTS = frozenset({"DROP", "REJECT", "DENY", "BLOCK"})
NSX_ALLOW_VERDICTS = frozenset({"PASS", "ALLOW", "ACCEPT"})
NSX_DENY_SCORE    = 25
NSX_ALLOW_SCORE   = 0
NSX_DENY_TACTIC   = "Network_Deny"
NSX_ALLOW_TACTIC  = "Network_Flow"

# ---------------------------------------------------------------------------
# vCenter / ESXi event classification
# (score, tactic, technique) tuples indexed by canonical event tag
# ---------------------------------------------------------------------------
VCENTER_MITRE_MAPPINGS = {
    "permission_added":   (35, "Privilege_Escalation", "T1098"),
    "role_added":         (35, "Privilege_Escalation", "T1098"),
    "vm_destroyed":       (30, "Impact",                "T1485"),
    "snapshot":           (20, "Exfiltration",          "T1006"),
    "vm_migration":       (15, "Lateral_Movement",      "T1021"),
    "vm_created":         (15, "Persistence",           "T1578.002"),
    "failed_login":       (40, "Credential_Access",     "T1110"),
    "login":              (10, "Initial_Access",        "T1078"),
    "logging_disabled":   (40, "Defense_Evasion",       "T1562"),
    "default":            (0,  "Virtualization_Event",  ""),
}

# ---------------------------------------------------------------------------
# HMAC formula (mirrors compute_hmac in transmitter.rs)
# msg = payload || BE64(sequence) || sensor_id_utf8 || BE64(timestamp)
# ---------------------------------------------------------------------------
def compute_hmac(secret: str, payload: bytes, sequence: int, sensor_id: str,
                 timestamp: int) -> str:
    msg = (
        payload
        + struct.pack(">Q", sequence)
        + sensor_id.encode("utf-8")
        + struct.pack(">Q", timestamp)
    )
    return _hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()