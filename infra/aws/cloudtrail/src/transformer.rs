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

    pub fn transform_record(
        &self,
        raw: &serde_json::Value,
        metadata: &HashMap<String, String>,
    ) -> Option<UnifiedFlowRecord> {
        let event_name = raw.get("eventName")?.as_str()?.to_string();
        let src_ip = raw.get("sourceIPAddress")?.as_str()?.to_string();

        let event_time_str = raw.get("eventTime")?.as_str()?;
        let start_ts = DateTime::parse_from_rfc3339(event_time_str)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or(0.0);

        let user_identity = raw.get("userIdentity")?;
        let iam_arn = user_identity
            .get("arn")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_arn")
            .to_string();

        let account_id = raw.get("recipientAccountId").and_then(|v| v.as_str()).unwrap_or("unknown");
        let region = raw.get("awsRegion").and_then(|v| v.as_str()).unwrap_or("unknown");

        // Temporal + beaconing keyed by identity + source IP.
        let state_key = format!("{}|{}", iam_arn, src_ip);
        let (interval, cv) = self.cache.observe(&state_key, start_ts);

        let environment = metadata.get("environment").cloned().unwrap_or_else(|| "unknown".to_string());
        let sensor_id = format!("{}|{}|{}", account_id, environment, region);

        let (mitre_tactic, mitre_technique, score) = classify_api_call(&event_name);

        let error_code = raw.get("errorCode").and_then(|v| v.as_str()).unwrap_or("");
        let reasons = if !error_code.is_empty() {
            serde_json::json!([format!("{}: {}", event_name, error_code)]).to_string()
        } else {
            "[]".to_string()
        };

        Some(UnifiedFlowRecord {
            timestamp: start_ts,
            process_name: event_name,
            dst_ip: src_ip,
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
            process_hash: iam_arn,
            dns_query: String::new(),
            event_type: "cloudtrail_api".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id,
        })
    }
}

/// Maps AWS API calls to MITRE ATT&CK tactics/techniques with baseline scores.
fn classify_api_call(event_name: &str) -> (String, String, i32) {
    // Defense Evasion -- log tampering, security disablement.
    let defense_evasion = [
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
        "DeleteFlowLogs", "DeleteDetector", "DisableKey", "DisableRule",
    ];
    // Persistence -- credential/access creation. (AttachRolePolicy/PutRolePolicy
    // intentionally NOT here -- they are evaluated as Privilege_Escalation below.)
    let persistence = [
        "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
        "CreateUser", "CreateRole", "AttachUserPolicy", "PutUserPolicy",
    ];
    // Privilege Escalation.
    let priv_esc = [
        "AttachRolePolicy", "PutRolePolicy", "CreatePolicyVersion",
        "SetDefaultPolicyVersion", "AddUserToGroup",
    ];
    // Discovery / Reconnaissance.
    let discovery = [
        "DescribeInstances", "ListBuckets", "GetBucketAcl", "ListRoles",
        "ListUsers", "GetCallerIdentity", "ListAccessKeys",
    ];
    // Exfiltration / Impact.
    let exfiltration = [
        "GetObject", "CopyObject", "CreateSnapshot", "CopySnapshot",
        "ModifySnapshotAttribute", "SharedSnapshotCopyStarted",
    ];
    // Initial Access.
    let initial_access = ["ConsoleLogin", "AssumeRole", "GetSessionToken", "GetFederationToken"];
    // Network manipulation.
    let network = [
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
        "CreateSecurityGroup", "ModifyVpcAttribute",
    ];

    if defense_evasion.contains(&event_name) {
        ("Defense_Evasion".into(), "T1562".into(), 40)
    } else if priv_esc.contains(&event_name) {
        ("Privilege_Escalation".into(), "T1484".into(), 35)
    } else if persistence.contains(&event_name) {
        ("Persistence".into(), "T1098".into(), 30)
    } else if discovery.contains(&event_name) {
        ("Discovery".into(), "T1580".into(), 10)
    } else if exfiltration.contains(&event_name) {
        ("Exfiltration".into(), "T1537".into(), 20)
    } else if initial_access.contains(&event_name) {
        ("Initial_Access".into(), "T1078".into(), 15)
    } else if network.contains(&event_name) {
        ("Defense_Evasion".into(), "T1562.007".into(), 25)
    } else if event_name.starts_with("Delete") || event_name.starts_with("Remove") {
        ("Impact".into(), "T1485".into(), 15)
    } else {
        ("Control_Plane_API".into(), String::new(), 0)
    }
}