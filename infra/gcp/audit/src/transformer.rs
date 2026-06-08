use crate::cache::TemporalCache;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnifiedFlowRecord {
    pub timestamp: f64,
    pub process_name: String,
    pub dst_ip: String,
    pub dst_port: i32,
    pub interval: f64,
    pub cv: f64,
    pub outbound_ratio: f64,
    pub entropy: f64,
    pub packet_size_mean: f64,
    pub packet_size_std: f64,
    pub packet_size_min: i32,
    pub packet_size_max: i32,
    pub packet_count: i64,
    pub mitre_tactic: String,
    pub cmd_entropy: f64,
    pub suppressed: i32,
    pub score: i32,
    pub cmd_snippet: String,
    pub process_tree: String,
    pub masquerade_detected: i32,
    pub reasons: String,
    pub mitre_technique: String,
    pub mitre_name: String,
    pub description: String,
    pub ml_result: Option<String>,
    pub process_hash: String,
    pub dns_query: String,
    pub event_type: String,
    pub dns_flags: i32,
    pub ja3_hash: String,
    pub sensor_id: String,
}

pub struct Transformer {
    cache: TemporalCache,
    sensor_id: String,
}

impl Transformer {
    pub fn new(cache: TemporalCache, sensor_id: String) -> Self {
        Self { cache, sensor_id }
    }

    pub fn transform_message(&self, payload: &[u8]) -> Option<UnifiedFlowRecord> {
        let entry: serde_json::Value = serde_json::from_slice(payload).ok()?;
        let proto = entry.get("protoPayload")?;

        let method_name = proto.get("methodName")?.as_str()?.to_string();
        let principal = proto.get("authenticationInfo")
            .and_then(|a| a.get("principalEmail"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown_identity")
            .to_string();

        let caller_ip = proto.get("requestMetadata")
            .and_then(|rm| rm.get("callerIp"))
            .and_then(|ip| ip.as_str())
            .unwrap_or("0.0.0.0")
            .to_string();

        let ts_str = entry.get("timestamp")?.as_str()?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(ts_str)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or_else(|_| chrono::Utc::now().timestamp() as f64);

        // Track API polling velocity per identity + source IP
        let state_key = format!("{}|{}", principal, caller_ip);
        let (interval, cv) = self.cache.observe(&state_key, timestamp);

        let mitre_tactic = if method_name.contains("Delete") || method_name.contains("Disable") {
            "Defense_Evasion"
        } else {
            "Control_Plane_API"
        };

        Some(UnifiedFlowRecord {
            timestamp,
            process_name: method_name,
            dst_ip: caller_ip,
            dst_port: 443,
            interval,
            cv,
            outbound_ratio: 1.0,
            entropy: 0.0,
            packet_size_mean: 1.0,
            packet_size_std: 0.0,
            packet_size_min: 1,
            packet_size_max: 1,
            packet_count: 1,
            mitre_tactic: mitre_tactic.to_string(),
            cmd_entropy: 0.0,
            suppressed: 0,
            score: 0,
            cmd_snippet: String::new(),
            process_tree: String::new(),
            masquerade_detected: 0,
            reasons: "[]".to_string(),
            mitre_technique: String::new(),
            mitre_name: String::new(),
            description: String::new(),
            ml_result: None,
            process_hash: principal, // UEBA identity tracking anchor
            dns_query: String::new(),
            event_type: "gcp_audit_log".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id: self.sensor_id.clone(),
        })
    }
}