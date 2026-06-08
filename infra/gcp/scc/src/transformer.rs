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
    sensor_id: String,
}

impl Transformer {
    pub fn new(sensor_id: String) -> Self {
        Self { sensor_id }
    }

    pub fn transform_message(&self, payload: &[u8]) -> Option<UnifiedFlowRecord> {
        let entry: serde_json::Value = serde_json::from_slice(payload).ok()?;

        let finding = entry.get("finding")?;
        let category = finding.get("category")?.as_str()?.to_string();
        let severity = finding.get("severity").and_then(|s| s.as_str()).unwrap_or("LOW");

        let resource_name = finding
            .get("resourceName")
            .and_then(|r| r.as_str())
            .unwrap_or("unknown_resource")
            .to_string();

        let ts_str = finding
            .get("eventTime")
            .or_else(|| finding.get("createTime"))?
            .as_str()?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(ts_str)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or_else(|_| chrono::Utc::now().timestamp() as f64);

        // Scale severity to the 0-100 baseline range.
        let score = match severity {
            "CRITICAL" => 95,
            "HIGH" => 75,
            "MEDIUM" => 50,
            "LOW" => 25,
            _ => 10,
        };

        let reasons = serde_json::json!([format!("SCC Alert: {}", category)]).to_string();

        Some(UnifiedFlowRecord {
            timestamp,
            process_name: category.clone(),
            dst_ip: "0.0.0.0".to_string(),
            dst_port: 0,
            interval: 0.0,
            cv: 0.0,
            outbound_ratio: 1.0,
            entropy: 0.0,
            packet_size_mean: 1.0,
            packet_size_std: 0.0,
            packet_size_min: 1,
            packet_size_max: 1,
            packet_count: 1,
            mitre_tactic: category.split('_').next().unwrap_or("Threat_Intel").to_string(),
            cmd_entropy: 0.0,
            suppressed: 0,
            score,
            cmd_snippet: String::new(),
            process_tree: String::new(),
            masquerade_detected: 0,
            reasons,
            mitre_technique: String::new(),
            mitre_name: String::new(),
            description: String::new(),
            ml_result: None,
            process_hash: resource_name, // affected infrastructure unit
            dns_query: String::new(),
            event_type: "gcp_scc_finding".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id: self.sensor_id.clone(),
        })
    }
}