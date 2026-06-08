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

pub struct Transformer;

impl Transformer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn transform_finding(
        &self,
        finding: &serde_json::Value,
        metadata: &HashMap<String, String>,
    ) -> Option<UnifiedFlowRecord> {
        let finding_type = finding.get("type")?.as_str()?.to_string();
        let severity: f64 = finding.get("severity")?.as_f64().unwrap_or(0.0);
        let title = finding.get("title")?.as_str().unwrap_or("GuardDuty Alert");
        let description = finding
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let updated_at_str = finding.get("updatedAt")?.as_str()?;
        let timestamp = DateTime::parse_from_rfc3339(updated_at_str)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or(0.0);

        let account_id = finding
            .get("accountId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let region = finding
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Extract the affected resource identity
        let mut process_hash = String::new();
        let mut dst_ip = String::from("0.0.0.0");
        let mut dst_port = 0i32;

        if let Some(resource) = finding.get("resource") {
            if let Some(res_type) = resource.get("resourceType").and_then(|v| v.as_str()) {
                match res_type {
                    "Instance" => {
                        process_hash = resource
                            .get("instanceDetails")
                            .and_then(|d| d.get("instanceId"))
                            .and_then(|i| i.as_str())
                            .unwrap_or("unknown_instance")
                            .to_string();
                    }
                    "AccessKey" => {
                        // Use the full IAM ARN from userIdentity, not principalId
                        process_hash = finding
                            .get("service")
                            .and_then(|s| s.get("userIdentity"))
                            .and_then(|u| u.get("arn"))
                            .and_then(|a| a.as_str())
                            .or_else(|| {
                                resource
                                    .get("accessKeyDetails")
                                    .and_then(|d| d.get("userName"))
                                    .and_then(|u| u.as_str())
                            })
                            .unwrap_or("unknown_identity")
                            .to_string();
                    }
                    "S3Bucket" => {
                        process_hash = resource
                            .get("s3BucketDetails")
                            .and_then(|d| d.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|b| b.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown_bucket")
                            .to_string();
                    }
                    _ => {}
                }
            }
        }

        // Extract remote actor IP if available
        if let Some(action) = finding.get("service").and_then(|s| s.get("action")) {
            if let Some(network) = action.get("networkConnectionAction") {
                dst_ip = network
                    .get("remoteIpDetails")
                    .and_then(|r| r.get("ipAddressV4"))
                    .and_then(|i| i.as_str())
                    .unwrap_or("0.0.0.0")
                    .to_string();
                dst_port = network
                    .get("remotePortDetails")
                    .and_then(|r| r.get("port"))
                    .and_then(|p| p.as_i64())
                    .unwrap_or(0) as i32;
            }
            // Port probe findings
            if let Some(port_probe) = action.get("portProbeAction") {
                if let Some(details) = port_probe.get("portProbeDetails").and_then(|d| d.as_array()) {
                    if let Some(first) = details.first() {
                        dst_ip = first
                            .get("remoteIpDetails")
                            .and_then(|r| r.get("ipAddressV4"))
                            .and_then(|i| i.as_str())
                            .unwrap_or("0.0.0.0")
                            .to_string();
                    }
                }
            }
        }

        let environment = metadata
            .get("environment")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let sensor_id = format!("{}|{}|{}", account_id, environment, region);

        // MITRE tactic from GuardDuty finding type prefix
        // Format: ThreatPurpose:ResourceType/ThreatName
        let mitre_tactic = finding_type
            .split(':')
            .next()
            .unwrap_or("Threat_Intel")
            .to_string();

        let reasons = serde_json::json!([title]).to_string();

        Some(UnifiedFlowRecord {
            timestamp,
            process_name: finding_type,
            dst_ip,
            dst_port,
            interval: 0.0,
            cv: 0.0,
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
            score: (severity * 10.0).min(100.0) as i32,
            cmd_snippet: String::new(),
            process_tree: String::new(),
            masquerade_detected: 0,
            reasons,
            mitre_technique: String::new(),
            mitre_name: String::new(),
            description,
            ml_result: None,
            process_hash,
            dns_query: String::new(),
            event_type: "guardduty_finding".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id,
        })
    }
}