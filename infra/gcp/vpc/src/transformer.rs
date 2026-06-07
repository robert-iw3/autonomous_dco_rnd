// GCP VPC Flow Logs -> UnifiedFlowRecord.
//
// Source shape: a Cloud Logging `LogEntry` whose `jsonPayload` is a GCP VPC
// flow record (log name `.../logs/compute.googleapis.com%2Fvpc_flows`). The
// record carries a full 5-tuple, byte/packet counts, and rich resource
// identity (project, region, subnetwork, VM name) -- richer than AWS, so we
// derive most context directly from the entry and treat external metadata
// enrichment as optional.

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
    pub pid: i32,
    pub uid: i32,
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

    /// `metadata` is reserved for optional enrichment from a centralized store
    /// (Firestore/Bigtable) keyed by project or subnetwork; empty by default.
    pub fn transform_entry(
        &self,
        entry: &serde_json::Value,
        metadata: &HashMap<String, String>,
    ) -> Option<UnifiedFlowRecord> {
        let payload = entry.get("jsonPayload")?;
        let conn = payload.get("connection")?;

        let src_ip = conn.get("src_ip").and_then(|v| v.as_str()).unwrap_or("0.0.0.0");
        let dst_ip = conn.get("dest_ip").and_then(|v| v.as_str())?.to_string();
        let dst_port: i32 = conn.get("dest_port").and_then(json_i64).unwrap_or(0) as i32;

        // GCP emits int64 counters as JSON strings.
        let bytes: f64 = payload.get("bytes_sent").and_then(json_i64).unwrap_or(0) as f64;
        let packets: i64 = payload.get("packets_sent").and_then(json_i64).unwrap_or(0);

        // start_time / end_time are RFC3339. Prefer payload start_time, fall
        // back to the LogEntry timestamp.
        let start_str = payload
            .get("start_time")
            .and_then(|v| v.as_str())
            .or_else(|| entry.get("timestamp").and_then(|v| v.as_str()))?;
        let start_ts = chrono::DateTime::parse_from_rfc3339(start_str)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or(0.0);

        // Identity: prefer the source VM name; fall back to source IP. This is
        // the GCP analogue of the AWS ENI used as `process_name`.
        let src_vm = payload
            .get("src_instance")
            .and_then(|i| i.get("vm_name"))
            .and_then(|v| v.as_str());
        let process_name = src_vm.unwrap_or(src_ip).to_string();

        // Resource context.
        let labels = entry.get("resource").and_then(|r| r.get("labels"));
        let project_id = labels
            .and_then(|l| l.get("project_id"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                payload
                    .get("src_instance")
                    .and_then(|i| i.get("project_id"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("unknown");
        let region = payload
            .get("src_instance")
            .and_then(|i| i.get("region"))
            .and_then(|v| v.as_str())
            .or_else(|| labels.and_then(|l| l.get("location")).and_then(|v| v.as_str()))
            .unwrap_or("unknown");
        let subnetwork = payload
            .get("src_vpc")
            .and_then(|v| v.get("subnetwork_name"))
            .and_then(|v| v.as_str())
            .or_else(|| labels.and_then(|l| l.get("subnetwork_name")).and_then(|v| v.as_str()))
            .unwrap_or("unknown");

        let environment = metadata
            .get("environment")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        // Composite identity: project|environment|region|subnetwork.
        let sensor_id = format!("{}|{}|{}|{}", project_id, environment, region, subnetwork);

        // Temporal + beaconing features per (src identity -> dst ip) conversation.
        let state_key = format!("{}|{}", process_name, dst_ip);
        let (interval, cv) = self.cache.observe(&state_key, start_ts);

        let packet_size_mean = if packets > 0 { bytes / packets as f64 } else { 0.0 };

        // GCP VPC flow logs are flow records, not firewall verdicts (those live
        // in firewall logs), so there is no allow/deny here. Baseline score 0.
        Some(UnifiedFlowRecord {
            timestamp: start_ts,
            process_name,
            dst_ip,
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
            mitre_tactic: "Cloud_Network_Flow".to_string(),
            pid: -1,
            uid: -1,
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
            process_hash: String::new(),
            dns_query: String::new(),
            event_type: "gcp_vpc_flow".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id,
        })
    }
}

/// GCP encodes int64 fields as JSON strings; accept both string and number.
fn json_i64(v: &serde_json::Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        Some(n)
    } else {
        v.as_str().and_then(|s| s.parse::<i64>().ok())
    }
}