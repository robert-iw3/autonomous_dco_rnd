use bytes::Bytes;
use hmac::{Hmac, Mac};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use sha2::Sha256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_CLOCK_SKEW_SECS: u64 = 120;
const REPLAY_WINDOW_SIZE: usize = 4096;

pub const HDR_BATCH_SEQUENCE: &str = "X-Batch-Sequence";
pub const HDR_BATCH_HMAC: &str = "X-Batch-HMAC";
pub const HDR_BATCH_TIMESTAMP: &str = "X-Batch-Timestamp";
pub const HDR_SENSOR_ID: &str = "X-Sensor-Id";
pub const HDR_SENSOR_TYPE: &str = "X-Sensor-Type";

fn compute_hmac(secret: &[u8], payload: &[u8], seq: u64, sensor_id: &str, ts: u64) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(payload);
    mac.update(&seq.to_be_bytes());
    mac.update(sensor_id.as_bytes());
    mac.update(&ts.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn extract_parquet_column_names(data: &[u8]) -> Result<Vec<String>, String> {
    let bytes = Bytes::copy_from_slice(data);
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes)
        .map_err(|e| format!("Parquet metadata error: {}", e))?;
    Ok(builder.schema().fields().iter().map(|f| f.name().clone()).collect())
}

#[derive(Debug, Clone)]
pub enum IntegrityViolation {
    HmacMismatch,
    SequenceGap { expected_min: u64, received: u64 },
    SequenceReplay { sequence: u64 },
    TemporalDrift { delta_secs: u64 },
    CrossOsCollision { sensor_type: String, offending_columns: Vec<String> },
    SensorBanned { sensor_id: String },
}

impl std::fmt::Display for IntegrityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HmacMismatch => write!(f, "HMAC mismatch"),
            Self::SequenceGap { expected_min, received } => write!(f, "Seq gap: expected>{} got={}", expected_min, received),
            Self::SequenceReplay { sequence } => write!(f, "Replay: seq={}", sequence),
            Self::TemporalDrift { delta_secs } => write!(f, "Drift: {}s", delta_secs),
            Self::CrossOsCollision { sensor_type, offending_columns } => write!(f, "Cross-schema '{}': {:?}", sensor_type, offending_columns),
            Self::SensorBanned { sensor_id } => write!(f, "Banned: {}", sensor_id),
        }
    }
}

struct SensorState { last_sequence: u64, seen: HashSet<u64>, order: VecDeque<u64>, failures: u32 }
impl SensorState {
    fn new() -> Self { Self { last_sequence: 0, seen: HashSet::with_capacity(REPLAY_WINDOW_SIZE), order: VecDeque::with_capacity(REPLAY_WINDOW_SIZE), failures: 0 } }
    fn record(&mut self, seq: u64) {
        if self.order.len() >= REPLAY_WINDOW_SIZE { if let Some(old) = self.order.pop_front() { self.seen.remove(&old); } }
        self.seen.insert(seq); self.order.push_back(seq); self.last_sequence = seq;
    }
}

pub struct IntegrityVerifier {
    secret: Vec<u8>,
    states: RwLock<HashMap<String, SensorState>>,
    banned: RwLock<HashSet<String>>,
    exclusions: HashMap<String, HashSet<String>>,
    ban_threshold: u32,
}

impl IntegrityVerifier {
    pub fn new(secret: &[u8], ban_threshold: u32) -> Self {
        Self { secret: secret.to_vec(), states: RwLock::new(HashMap::new()), banned: RwLock::new(HashSet::new()), exclusions: build_exclusion_rules(), ban_threshold }
    }

    pub fn verify_batch(&self, data: &[u8], seq: u64, ts: u64, sensor_id: &str, sensor_type: &str, claimed_hmac: &str, columns: &[String]) -> Result<(), IntegrityViolation> {
        if self.banned.read().unwrap().contains(sensor_id) { return Err(IntegrityViolation::SensorBanned { sensor_id: sensor_id.into() }); }
        let expected = hex::encode(compute_hmac(&self.secret, data, seq, sensor_id, ts));
        if !constant_time_eq(expected.as_bytes(), claimed_hmac.as_bytes()) { self.record_failure(sensor_id); return Err(IntegrityViolation::HmacMismatch); }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let delta = if ts > now { ts - now } else { now - ts };
        if delta > MAX_CLOCK_SKEW_SECS { self.record_failure(sensor_id); return Err(IntegrityViolation::TemporalDrift { delta_secs: delta }); }
        { let mut states = self.states.write().unwrap();
          let state = states.entry(sensor_id.to_string()).or_insert_with(SensorState::new);
          if state.seen.contains(&seq) { self.record_failure(sensor_id); return Err(IntegrityViolation::SequenceReplay { sequence: seq }); }
          if seq <= state.last_sequence { self.record_failure(sensor_id); return Err(IntegrityViolation::SequenceGap { expected_min: state.last_sequence, received: seq }); }
          state.record(seq); state.failures = 0;
        }
        if let Some(forbidden) = self.exclusions.get(sensor_type) {
            let offenders: Vec<String> = columns.iter().filter(|c| forbidden.contains(c.as_str())).cloned().collect();
            if !offenders.is_empty() { self.banned.write().unwrap().insert(sensor_id.into()); return Err(IntegrityViolation::CrossOsCollision { sensor_type: sensor_type.into(), offending_columns: offenders }); }
        }
        Ok(())
    }

    fn record_failure(&self, sensor_id: &str) {
        let mut states = self.states.write().unwrap();
        let state = states.entry(sensor_id.to_string()).or_insert_with(SensorState::new);
        state.failures += 1;
        if state.failures >= self.ban_threshold { drop(states); self.banned.write().unwrap().insert(sensor_id.into()); }
    }
}

fn build_exclusion_rules() -> HashMap<String, HashSet<String>> {
    let endpoint_forbidden: HashSet<String> = ["pid","uid","comm","command_line","parent_comm","parent_image","shannon_entropy","container_name","signature_name","tls_ja3","session_id","byte_ratio"].iter().map(|s| s.to_string()).collect();
    let nettap_forbidden: HashSet<String> = ["pid","ppid","uid","command_line","parent_image","parent_comm","mitre_tactic","mitre_technique","anomaly_score","container_name","signature_name","alert_reason","comm","outbound_ratio","ml_result"].iter().map(|s| s.to_string()).collect();
    let mut rules = HashMap::new();
    for key in &["aws-vpc-flow-connector","aws-cloudtrail-connector","aws-guardduty-connector","azure-nsg-flow-connector","azure-activity-connector","azure-entraid-connector"] {
        rules.insert(key.to_string(), endpoint_forbidden.clone());
    }
    rules.insert("network_tap".into(), nettap_forbidden);
    rules
}
