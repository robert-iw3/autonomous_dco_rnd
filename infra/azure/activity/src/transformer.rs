use crate::cache::TemporalCache;
use chrono::DateTime;
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

    /// Transform an Azure Activity Log event (Diagnostic Settings schema).
    pub fn transform_event(
        &self,
        event: &serde_json::Value,
        metadata: &HashMap<String, String>,
    ) -> Option<UnifiedFlowRecord> {
        let operation = event.get("operationName")?.as_str()?.to_string();
        let caller_ip = event.get("callerIpAddress").and_then(|v| v.as_str()).unwrap_or("0.0.0.0").to_string();
        let caller_id = event.get("caller").and_then(|v| v.as_str()).unwrap_or("unknown_caller").to_string();
        let subscription_id = event.get("subscriptionId").and_then(|v| v.as_str()).unwrap_or("unknown");
        let result_type = event.get("resultType").and_then(|v| v.as_str()).unwrap_or("Unknown");

        let time_str = event.get("time").and_then(|v| v.as_str())?;
        let ts = DateTime::parse_from_rfc3339(time_str)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or(0.0);

        let state_key = format!("{}|{}", caller_id, caller_ip);
        let (interval, cv) = self.cache.observe(&state_key, ts);

        let environment = metadata.get("environment").cloned().unwrap_or_else(|| "unknown".to_string());
        let region = metadata.get("region").cloned().unwrap_or_else(|| "unknown".to_string());
        let sensor_id = format!("{}|{}|{}", subscription_id, environment, region);

        let (mitre_tactic, mitre_technique, score) = classify_operation(&operation);
        // Failed operations get a bump -- attacker probing.
        let score = if result_type == "Failure" { score + 10 } else { score };

        let reasons = if result_type == "Failure" {
            serde_json::json!([format!("{}: {}", operation, result_type)]).to_string()
        } else {
            "[]".to_string()
        };

        Some(UnifiedFlowRecord {
            timestamp: ts,
            process_name: operation,
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
            mitre_tactic,
            cmd_entropy: 0.0,
            suppressed: 0,
            score,
            cmd_snippet: String::new(),
            process_tree: String::new(),
            masquerade_detected: 0,
            reasons,
            mitre_technique,
            mitre_name: String::new(),
            description: String::new(),
            ml_result: None,
            process_hash: caller_id,
            dns_query: String::new(),
            event_type: "azure_activity".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id,
        })
    }
}

fn classify_operation(op: &str) -> (String, String, i32) {
    let op_lower = op.to_lowercase();

    // Defense Evasion -- log/security disablement (highest priority).
    if (op_lower.contains("delete")
        && (op_lower.contains("diagnosticsetting") || op_lower.contains("securitysolution")))
        || op_lower.contains("microsoft.security/policies/write")
    {
        return ("Defense_Evasion".into(), "T1562".into(), 40);
    }
    // Privilege Escalation -- explicit elevation or editing role DEFINITIONS.
    // (Checked BEFORE persistence so roledefinitions/write is reachable.)
    if op_lower.contains("elevateaccess") || op_lower.contains("roledefinitions/write") {
        return ("Privilege_Escalation".into(), "T1484".into(), 35);
    }
    // Persistence -- new role ASSIGNMENTS.
    if op_lower.contains("roleassignments/write") {
        return ("Persistence".into(), "T1098".into(), 30);
    }
    // Network manipulation.
    if op_lower.contains("securityrules/write")
        || op_lower.contains("networksecuritygroups/write")
        || op_lower.contains("firewallrules/write")
    {
        return ("Defense_Evasion".into(), "T1562.007".into(), 25);
    }
    // Key Vault access -- credential harvesting.
    if op_lower.contains("vaults/secrets") || op_lower.contains("vaults/keys") {
        return ("Credential_Access".into(), "T1555".into(), 20);
    }
    // Discovery.
    if op_lower.contains("/read") && (op_lower.contains("subscription") || op_lower.contains("resourcegroups")) {
        return ("Discovery".into(), "T1580".into(), 5);
    }
    // Resource deletion -- Impact.
    if op_lower.contains("delete") {
        return ("Impact".into(), "T1485".into(), 15);
    }
    // Resource creation/modification -- neutral baseline.
    if op_lower.contains("write") {
        return ("Resource_Management".into(), String::new(), 0);
    }

    ("Control_Plane_API".into(), String::new(), 0)
}