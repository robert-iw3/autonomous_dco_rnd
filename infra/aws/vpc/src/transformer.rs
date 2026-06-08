use crate::cache::TemporalCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
}

impl Transformer {
    pub fn new(cache: TemporalCache) -> Self {
        Self { cache }
    }

    /// Transform one VPC flow log row (column names normalized to hyphens).
    pub fn transform_row(
        &self,
        raw_row: &HashMap<String, String>,
        metadata: &HashMap<String, String>,
    ) -> Option<UnifiedFlowRecord> {
        let interface_id = raw_row.get("interface-id")?;
        let src_addr = raw_row.get("srcaddr")?;
        let dst_addr = raw_row.get("dstaddr")?;
        let dst_port: i32 = raw_row.get("dstport").and_then(|v| v.parse().ok()).unwrap_or(0);

        // Skip "NODATA"/"SKIPDATA" rows that carry no addresses.
        if src_addr == "-" || dst_addr == "-" {
            return None;
        }

        let packets: i64 = raw_row.get("packets").and_then(|v| v.parse().ok()).unwrap_or(0);
        let bytes: f64 = raw_row.get("bytes").and_then(|v| v.parse().ok()).unwrap_or(0.0);
        let start_ts: f64 = raw_row.get("start").and_then(|v| v.parse().ok()).unwrap_or(0.0);
        let action = raw_row.get("action").map(|s| s.as_str()).unwrap_or("");

        let vpc_id = raw_row.get("vpc-id").map(|s| s.as_str()).unwrap_or("vpc-unknown");

        let packet_size_mean = if packets > 0 { bytes / packets as f64 } else { 0.0 };

        // Temporal + beaconing per ENI -> destination conversation.
        let state_key = format!("{}|{}", interface_id, dst_addr);
        let (interval, cv) = self.cache.observe(&state_key, start_ts);

        let environment = metadata.get("environment").cloned().unwrap_or_else(|| "unknown".to_string());
        let region = metadata.get("region").cloned().unwrap_or_else(|| "unknown".to_string());
        let sensor_id = format!("{}|{}|{}", vpc_id, environment, region);

        let (score, mitre_tactic) = if action == "REJECT" {
            (15, "Network_Deny".to_string())
        } else {
            (0, "Cloud_Network_Flow".to_string())
        };

        Some(UnifiedFlowRecord {
            timestamp: start_ts,
            process_name: interface_id.clone(),
            dst_ip: dst_addr.clone(),
            dst_port,
            interval,
            cv,
            outbound_ratio: 1.0,
            entropy: 0.0,
            packet_size_mean,
            packet_size_std: 0.0,
            packet_size_min: 0,
            packet_size_max: 0,
            packet_count: packets,
            mitre_tactic,
            cmd_entropy: 0.0,
            suppressed: 0,
            score,
            cmd_snippet: String::new(),
            process_tree: String::new(),
            masquerade_detected: 0,
            reasons: "[]".to_string(),
            mitre_technique: String::new(),
            mitre_name: String::new(),
            description: String::new(),
            ml_result: None,
            process_hash: String::new(),
            dns_query: String::new(),
            event_type: "vpc_flow".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id,
        })
    }
}