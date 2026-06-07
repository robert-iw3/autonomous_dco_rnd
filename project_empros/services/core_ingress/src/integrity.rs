// =============================================================================
// Integrity Verification Engine -- core_ingress
// =============================================================================

use bytes::Bytes;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use sha2::Sha256;
use std::collections::{HashSet, VecDeque};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

// --- Constants ---------------------------------------------------------------

pub const MAX_CLOCK_SKEW_SECS: u64 = 120;
const REPLAY_WINDOW_SIZE: usize = 4096;

pub const HDR_BATCH_SEQUENCE: &str = "X-Batch-Sequence";
pub const HDR_BATCH_HMAC: &str = "X-Batch-HMAC";
pub const HDR_BATCH_TIMESTAMP: &str = "X-Batch-Timestamp";
pub const HDR_SENSOR_ID: &str = "X-Sensor-Id";
pub const HDR_SENSOR_TYPE: &str = "X-Sensor-Type";

// --- HMAC Protocol -----------------------------------------------------------

fn compute_hmac(
    secret: &[u8],
    parquet_bytes: &[u8],
    sequence: u64,
    sensor_id: &str,
    timestamp: u64,
) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(parquet_bytes);
    mac.update(&sequence.to_be_bytes());
    mac.update(sensor_id.as_bytes());
    mac.update(&timestamp.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time comparison on raw bytes.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- Parquet Column Extraction -----------------------------------------------

pub fn extract_parquet_column_names(parquet_bytes: &[u8]) -> Result<Vec<String>, String> {
    let bytes = Bytes::copy_from_slice(parquet_bytes);
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes)
        .map_err(|e| format!("Failed to read Parquet metadata: {}", e))?;
    let schema = builder.schema();
    Ok(schema
        .fields()
        .iter()
        .map(|f| f.name().to_string())
        .collect())
}

// --- Violation Taxonomy ------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityViolation {
    HmacMismatch,
    HmacDecodeError,
    SequenceGap { expected_min: u64, received: u64 },
    SequenceReplay { sequence: u64 },
    TemporalDrift { batch_ts: u64, server_ts: u64, delta_secs: u64 },
    CrossOsCollision { sensor_type: String, offending_columns: Vec<String> },
    SensorBanned { sensor_id: String },
    MissingHeaders,
}

impl std::fmt::Display for IntegrityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HmacMismatch => write!(f, "HMAC verification failed"),
            Self::HmacDecodeError => write!(f, "HMAC hex decode failed"),
            Self::SequenceGap { expected_min, received } => {
                write!(f, "Sequence gap: expected > {expected_min}, got {received}")
            }
            Self::SequenceReplay { sequence } => {
                write!(f, "Replay detected: sequence {sequence}")
            }
            Self::TemporalDrift { delta_secs, .. } => {
                write!(f, "Temporal drift: {delta_secs}s exceeds {MAX_CLOCK_SKEW_SECS}s limit")
            }
            Self::CrossOsCollision { sensor_type, offending_columns } => {
                write!(f, "Cross-OS collision on '{sensor_type}': {offending_columns:?}")
            }
            Self::SensorBanned { sensor_id } => write!(f, "Sensor '{sensor_id}' is banned"),
            Self::MissingHeaders => write!(f, "Required integrity headers missing"),
        }
    }
}

// --- Per-Sensor Tracking -----------------------------------------------------

struct SensorState {
    last_sequence: u64,
    seen_sequences: HashSet<u64>,
    seen_order: VecDeque<u64>,
    consecutive_failures: u32,
}

impl SensorState {
    fn new() -> Self {
        Self {
            last_sequence: 0,
            seen_sequences: HashSet::with_capacity(REPLAY_WINDOW_SIZE),
            seen_order: VecDeque::with_capacity(REPLAY_WINDOW_SIZE), // ← Fixed: was Vec
            consecutive_failures: 0,
        }
    }

    fn record_sequence(&mut self, seq: u64) {
        if self.seen_order.len() >= REPLAY_WINDOW_SIZE {
            if let Some(old) = self.seen_order.pop_front() {
                // O(1) -- VecDeque ring buffer, not Vec::remove(0)
                self.seen_sequences.remove(&old);
            }
        }
        self.seen_sequences.insert(seq);
        self.seen_order.push_back(seq);
        self.last_sequence = seq;
    }
}

// --- Verification Engine -----------------------------------------------------

// --- Ban list persistence helpers --------------------------------------------
// H-R4 fix: banned_sensors was an in-memory HashSet -- cleared on ingress restart,
// allowing previously banned (compromised/replaying) sensors to reconnect immediately.
// Now persisted to a file on every ban update and loaded on startup.

fn ban_list_path() -> std::path::PathBuf {
    let dir = std::env::var("NEXUS_BAN_LIST_DIR")
        .unwrap_or_else(|_| "/var/lib/nexus-ingress".to_string());
    std::path::Path::new(&dir).join("banned_sensors.txt")
}

fn load_ban_list() -> HashSet<String> {
    let path = ban_list_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => content.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
        Err(_) => HashSet::new(),
    }
}

fn persist_ban_list(banned: &HashSet<String>) {
    let path = ban_list_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let content: String = std::iter::once("# Nexus sensor ban list -- auto-managed, do not edit manually\n".to_string())
        .chain(banned.iter().cloned())
        .collect::<Vec<_>>()
        .join("\n");
    // Atomic write via temp file to avoid partial state
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, content).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

pub struct IntegrityVerifier {
    shared_secret: Vec<u8>,
    /// Per-sensor state with DashMap for lock-free per-shard concurrency.
    /// Sensors in different DashMap shards don't contend at all.
    sensor_states: DashMap<String, SensorState>,
    /// Persistent ban list -- loaded from disk on startup, saved on every ban update.
    /// H-R4: was in-memory only; restart cleared all bans.
    banned_sensors: RwLock<HashSet<String>>,
    os_exclusion_rules: std::collections::HashMap<String, HashSet<String>>,
    ban_threshold: u32,
}

impl IntegrityVerifier {
    pub fn new(shared_secret: &[u8], ban_threshold: u32) -> Self {
        let persisted_bans = load_ban_list();
        if !persisted_bans.is_empty() {
            tracing::info!(
                count = persisted_bans.len(),
                "Restored {} banned sensor(s) from disk",
                persisted_bans.len()
            );
        }
        Self {
            shared_secret: shared_secret.to_vec(),
            sensor_states: DashMap::new(),
            banned_sensors: RwLock::new(persisted_bans),
            os_exclusion_rules: build_os_exclusion_rules(),
            ban_threshold,
        }
    }

    pub fn verify_batch(
        &self,
        parquet_bytes: &[u8],
        sequence: u64,
        timestamp: u64,
        sensor_id: &str,
        sensor_type: &str,
        claimed_hmac_hex: &str,
        parquet_columns: &[String],
    ) -> Result<(), IntegrityViolation> {
        // 0. Ban check (read lock -- uncontended fast path)
        {
            let banned = self.banned_sensors.read().unwrap_or_else(|e| e.into_inner());
            if banned.contains(sensor_id) {
                return Err(IntegrityViolation::SensorBanned {
                    sensor_id: sensor_id.into(),
                });
            }
        }

        // 1. HMAC -- compare raw bytes, not hex strings (halves comparison work,
        //    eliminates hex::encode allocation on the hot path)
        let expected_bytes = compute_hmac(
            &self.shared_secret,
            parquet_bytes,
            sequence,
            sensor_id,
            timestamp,
        );

        let claimed_bytes = hex::decode(claimed_hmac_hex)
            .map_err(|_| IntegrityViolation::HmacDecodeError)?;

        if !constant_time_eq(&expected_bytes, &claimed_bytes) {
            self.record_failure(sensor_id);
            return Err(IntegrityViolation::HmacMismatch);
        }

        // 2. Temporal drift
        let server_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let delta = if timestamp > server_ts {
            timestamp - server_ts
        } else {
            server_ts - timestamp
        };
        if delta > MAX_CLOCK_SKEW_SECS {
            self.record_failure(sensor_id);
            return Err(IntegrityViolation::TemporalDrift {
                batch_ts: timestamp,
                server_ts,
                delta_secs: delta,
            });
        }

        // 3. Sequence -- DashMap entry lock (only this sensor is locked)
        {
            let mut state = self
                .sensor_states
                .entry(sensor_id.to_string())
                .or_insert_with(SensorState::new);

            if state.seen_sequences.contains(&sequence) {
                state.consecutive_failures += 1;
                if state.consecutive_failures >= self.ban_threshold {
                    drop(state);
                    self.ban_sensor(sensor_id);
                }
                return Err(IntegrityViolation::SequenceReplay { sequence });
            }
            if sequence <= state.last_sequence {
                state.consecutive_failures += 1;
                let expected_min = state.last_sequence; // copy before potential drop
                if state.consecutive_failures >= self.ban_threshold {
                    drop(state);
                    self.ban_sensor(sensor_id);
                }
                return Err(IntegrityViolation::SequenceGap {
                    expected_min,
                    received: sequence,
                });
            }
            state.record_sequence(sequence);
            state.consecutive_failures = 0;
        }

        // 4. Cross-OS column collision
        if let Some(forbidden) = self.os_exclusion_rules.get(sensor_type) {
            let offenders: Vec<String> = parquet_columns
                .iter()
                .filter(|col| forbidden.contains(col.as_str()))
                .cloned()
                .collect();
            if !offenders.is_empty() {
                self.ban_sensor(sensor_id);
                return Err(IntegrityViolation::CrossOsCollision {
                    sensor_type: sensor_type.into(),
                    offending_columns: offenders,
                });
            }
        }

        Ok(())
    }

    pub fn ban_sensor(&self, sensor_id: &str) {
        if let Ok(mut banned) = self.banned_sensors.write() {
            let is_new = banned.insert(sensor_id.to_string());
            if is_new {
                // H-R4 fix: persist immediately so restart doesn't clear the ban
                persist_ban_list(&banned);
                tracing::warn!(sensor_id, "Sensor banned and persisted to disk");
            }
        }
    }

    fn record_failure(&self, sensor_id: &str) {
        let mut state = self
            .sensor_states
            .entry(sensor_id.to_string())
            .or_insert_with(SensorState::new);
        state.consecutive_failures += 1;
        if state.consecutive_failures >= self.ban_threshold {
            drop(state);
            self.ban_sensor(sensor_id);
        }
    }
}

// --- Cross-OS Exclusion Rules ------------------------------------------------
// Keys MUST match the X-Sensor-Type header values used in production.
// These are defined in nexus.toml [schema_mappings.*] and sent by every sensor.

fn build_os_exclusion_rules() -> std::collections::HashMap<String, HashSet<String>> {
    let mut rules = std::collections::HashMap::new();

    // linux_sentinel: pid, ppid, uid, container_name, comm, command_line,
    // parent_comm, shannon_entropy, execution_velocity, tuple_rarity, etc.
    // Must NOT contain Windows or network_tap fields.
    rules.insert(
        "linux_sentinel".into(),
        HashSet::from([
            "Image".into(), "parent_image".into(), "signature_name".into(),
            "CommandLine".into(), "DestIp".into(), "Port".into(),
            "avg_entropy".into(), "max_velocity".into(), "event_count".into(),
            // network_tap exclusive fields
            "session_id".into(), "src_ip".into(), "byte_ratio".into(),
            "tls_ja3".into(), "is_internal_dst".into(), "port_class".into(),
        ]),
    );

    // linux_c2: process_name, pid, uid, dst_ip, outbound_ratio,
    // packet_size_mean/std, interval, cv, entropy, cmd_entropy, score
    rules.insert(
        "linux_c2".into(),
        HashSet::from([
            "Image".into(), "parent_image".into(), "signature_name".into(),
            "CommandLine".into(), "DestIp".into(),
            "container_name".into(), "tuple_rarity".into(),
            // network_tap exclusive fields
            "session_id".into(), "src_ip".into(), "byte_ratio".into(),
            "tls_ja3".into(), "is_internal_dst".into(), "port_class".into(),
        ]),
    );

    // windows_c2: host, Image, CommandLine, DestIp, Port,
    // outbound_ratio, packet_size_mean/std, interval, cv, entropy, score
    rules.insert(
        "windows_c2".into(),
        HashSet::from([
            "uid".into(), "ppid".into(), "comm".into(), "parent_comm".into(),
            "container_name".into(), "tuple_rarity".into(), "shannon_entropy".into(),
            "execution_velocity".into(), "path_depth".into(),
            // network_tap exclusive fields
            "session_id".into(), "src_ip".into(), "byte_ratio".into(),
            "tls_ja3".into(), "is_internal_dst".into(), "port_class".into(),
        ]),
    );

    // windows_deepsensor: event_id, timestamp, category, event_type, pid,
    // parent_pid, tid, path, parent_image, command_line, event_user,
    // destination_ip, port, signature_name, tactic, technique, severity,
    // score, avg_entropy, max_velocity, event_count
    rules.insert(
        "windows_deepsensor".into(),
        HashSet::from([
            "uid".into(), "ppid".into(), "comm".into(), "parent_comm".into(),
            "container_name".into(), "tuple_rarity".into(), "shannon_entropy".into(),
            "execution_velocity".into(), "path_depth".into(),
            // network_tap exclusive fields
            "session_id".into(), "src_ip".into(), "byte_ratio".into(),
            "tls_ja3".into(), "is_internal_dst".into(), "port_class".into(),
        ]),
    );

    // network_tap (Arkime): session_id, src_ip, dst_ip, byte_ratio,
    // avg_inter_arrival, tls_ja3, cert_self_signed, is_internal_dst, port_class
    // Must NOT contain any endpoint process fields.
    rules.insert(
        "network_tap".into(),
        HashSet::from([
            "pid".into(), "ppid".into(), "uid".into(), "comm".into(),
            "parent_comm".into(), "command_line".into(), "CommandLine".into(),
            "Image".into(), "parent_image".into(), "container_name".into(),
            "shannon_entropy".into(), "execution_velocity".into(),
            "tuple_rarity".into(), "path_depth".into(), "anomaly_score".into(),
            "signature_name".into(), "avg_entropy".into(), "max_velocity".into(),
        ]),
    );

    // cloud_flow: AWS CloudTrail / Azure AD / VPC Flow
    // Must NOT contain endpoint or network_tap fields.
    rules.insert(
        "cloud_flow".into(),
        HashSet::from([
            "pid".into(), "ppid".into(), "uid".into(), "comm".into(),
            "parent_comm".into(), "command_line".into(), "CommandLine".into(),
            "Image".into(), "parent_image".into(), "container_name".into(),
            "shannon_entropy".into(), "signature_name".into(),
            // network_tap exclusive fields
            "session_id".into(), "tls_ja3".into(), "is_internal_dst".into(),
            "port_class".into(), "cert_self_signed".into(),
        ]),
    );

    // suricata_eve: Suricata IDS network sensor. Uses its own column names
    // (flow_id not session_id, tls_ja3_hash not tls_ja3). Must not carry
    // endpoint/host columns or another network schema's exclusive names.
    rules.insert(
        "suricata_eve".into(),
        HashSet::from([
            "pid".into(), "ppid".into(), "uid".into(), "comm".into(),
            "parent_comm".into(), "command_line".into(), "CommandLine".into(),
            "Image".into(), "parent_image".into(), "container_name".into(),
            "shannon_entropy".into(), "execution_velocity".into(),
            "tuple_rarity".into(), "path_depth".into(), "anomaly_score".into(),
            "signature_name".into(), "avg_entropy".into(), "max_velocity".into(),
            "event_count".into(),
            // network_tap (Arkime) exclusive names
            "session_id".into(), "byte_ratio".into(), "tls_ja3".into(),
            "is_internal_dst".into(), "port_class".into(),
        ]),
    );

    // gcp_audit / gcp_scc / gcp_vpc_flow / vmware_syslog: all emit
    // UnifiedFlowRecord which carries pid/uid as sentinel values (-1..-5).
    // Rule = cloud_flow's set MINUS pid/uid so they don't get auto-banned.
    let unified_cloud_forbidden = || HashSet::from([
        "ppid".into(), "comm".into(), "parent_comm".into(),
        "command_line".into(), "CommandLine".into(),
        "Image".into(), "parent_image".into(), "container_name".into(),
        "shannon_entropy".into(), "signature_name".into(),
        // network_tap exclusive
        "session_id".into(), "tls_ja3".into(), "is_internal_dst".into(),
        "port_class".into(), "cert_self_signed".into(),
    ]);
    for sensor_type in [
        "gcp_audit", "gcp_scc", "gcp_vpc_flow", "vmware_syslog",
    ] {
        rules.insert(sensor_type.into(), unified_cloud_forbidden());
    }

    rules
}