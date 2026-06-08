use crate::cache::TemporalCache;
use chrono::DateTime;
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
}

impl Transformer {
    pub fn new(cache: TemporalCache) -> Self {
        Self { cache }
    }

    /// Route Entra ID events to the appropriate sub-transformer based on category.
    pub fn transform_event(&self, event: &serde_json::Value) -> Option<UnifiedFlowRecord> {
        let category = event.get("category").and_then(|c| c.as_str()).unwrap_or("");
        match category {
            "SignInLogs" | "NonInteractiveUserSignInLogs" | "ManagedIdentitySignInLogs"
            | "ServicePrincipalSignInLogs" => self.transform_signin(event),
            "AuditLogs" => self.transform_audit(event),
            _ => self.transform_signin(event), // best-effort fallback
        }
    }

    fn transform_signin(&self, event: &serde_json::Value) -> Option<UnifiedFlowRecord> {
        let props = event.get("properties")?;

        let upn = props.get("userPrincipalName").and_then(|v| v.as_str()).unwrap_or("unknown_user");
        let ip = props.get("ipAddress").and_then(|v| v.as_str()).unwrap_or("0.0.0.0").to_string();
        let app = props.get("appDisplayName").and_then(|v| v.as_str()).unwrap_or("unknown_app");

        let time_str = event.get("time").and_then(|v| v.as_str())?;
        let ts = DateTime::parse_from_rfc3339(time_str)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or(0.0);

        let tenant_id = event.get("tenantId").and_then(|v| v.as_str()).unwrap_or("unknown");

        let error_code = props.get("status")
            .and_then(|s| s.get("errorCode"))
            .and_then(|e| e.as_i64())
            .unwrap_or(0);

        let risk_level = props.get("riskLevelDuringSignIn").and_then(|v| v.as_str()).unwrap_or("none");
        let risk_state = props.get("riskState").and_then(|v| v.as_str()).unwrap_or("none");
        let ca_status = props.get("conditionalAccessStatus").and_then(|v| v.as_str()).unwrap_or("notApplied");
        let is_interactive = props.get("isInteractive").and_then(|v| v.as_bool()).unwrap_or(true);

        let location = props.get("location");
        let city = location.and_then(|l| l.get("city")).and_then(|v| v.as_str()).unwrap_or("");
        let country = location.and_then(|l| l.get("countryOrRegion")).and_then(|v| v.as_str()).unwrap_or("");

        // Temporal + beaconing per identity + source IP.
        let state_key = format!("{}|{}", upn, ip);
        let (interval, cv) = self.cache.observe(&state_key, ts);

        let (score, mitre_tactic, mitre_technique) =
            classify_signin_risk(error_code, risk_level, ca_status, is_interactive);

        let sensor_id = format!("{}|entraid|signin", tenant_id);

        let mut reasons_list = Vec::new();
        if error_code != 0 {
            reasons_list.push(format!("Sign-in error: {}", error_code));
        }
        if risk_level != "none" && risk_level != "hidden" {
            reasons_list.push(format!("Risk: {} ({})", risk_level, risk_state));
        }
        if ca_status == "failure" {
            reasons_list.push("Conditional Access blocked".to_string());
        }
        if !city.is_empty() {
            reasons_list.push(format!("Location: {}, {}", city, country));
        }

        let reasons = serde_json::json!(reasons_list).to_string();
        let event_type = if is_interactive { "entraid_signin" } else { "entraid_signin_noninteractive" };

        Some(UnifiedFlowRecord {
            timestamp: ts,
            process_name: format!("SignIn:{}", app),
            dst_ip: ip,
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
            process_hash: upn.to_string(),
            dns_query: String::new(),
            event_type: event_type.to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id,
        })
    }

    fn transform_audit(&self, event: &serde_json::Value) -> Option<UnifiedFlowRecord> {
        let props = event.get("properties")?;

        let activity = props.get("activityDisplayName").and_then(|v| v.as_str()).unwrap_or("unknown_activity");
        let result = props.get("result").and_then(|v| v.as_str()).unwrap_or("unknown");

        let time_str = event.get("time").and_then(|v| v.as_str())?;
        let ts = DateTime::parse_from_rfc3339(time_str)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or(0.0);

        let tenant_id = event.get("tenantId").and_then(|v| v.as_str()).unwrap_or("unknown");

        let initiated_by = props.get("initiatedBy");
        let actor = initiated_by
            .and_then(|i| i.get("user"))
            .and_then(|u| u.get("userPrincipalName"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                initiated_by.and_then(|i| i.get("app"))
                    .and_then(|a| a.get("displayName"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("unknown_actor");

        let actor_ip = initiated_by
            .and_then(|i| i.get("user"))
            .and_then(|u| u.get("ipAddress"))
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0")
            .to_string();

        let state_key = format!("{}|audit", actor);
        let (interval, cv) = self.cache.observe(&state_key, ts);

        let (score, mitre_tactic, mitre_technique) = classify_audit_activity(activity);
        let score = if result == "failure" { score + 10 } else { score };

        let sensor_id = format!("{}|entraid|audit", tenant_id);
        let reasons = if result == "failure" {
            serde_json::json!([format!("{}: {}", activity, result)]).to_string()
        } else {
            "[]".to_string()
        };

        Some(UnifiedFlowRecord {
            timestamp: ts,
            process_name: format!("Audit:{}", activity),
            dst_ip: actor_ip,
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
            process_hash: actor.to_string(),
            dns_query: String::new(),
            event_type: "entraid_audit".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id,
        })
    }
}

fn classify_signin_risk(error_code: i64, risk_level: &str, ca_status: &str, _is_interactive: bool) -> (i32, String, String) {
    if risk_level == "high" {
        return (85, "Initial_Access".into(), "T1078".into());
    }
    if risk_level == "medium" {
        return (60, "Initial_Access".into(), "T1078".into());
    }
    if ca_status == "failure" {
        return (50, "Policy_Violation".into(), "T1078".into());
    }
    match error_code {
        50126 => (40, "Credential_Access".into(), "T1110".into()), // invalid password
        50053 => (55, "Credential_Access".into(), "T1110".into()), // account locked
        50057 => (30, "Credential_Access".into(), "T1110".into()), // disabled account
        50055 => (20, "Credential_Access".into(), "T1110".into()), // expired password
        53003 => (45, "Policy_Violation".into(), "T1078".into()),  // blocked by CA
        0 => (0, "Initial_Access".into(), String::new()),          // success
        _ => (15, "Initial_Access".into(), String::new()),         // other failure
    }
}

fn classify_audit_activity(activity: &str) -> (i32, String, String) {
    let lower = activity.to_lowercase();
    if lower.contains("add member to role") || lower.contains("add eligible member") {
        (35, "Privilege_Escalation".into(), "T1098".into()) // FIXED: was (String,String,i32)
    } else if lower.contains("add user") || lower.contains("invite external user") {
        (20, "Persistence".into(), "T1136".into())
    } else if lower.contains("reset password") || lower.contains("change password") {
        (25, "Credential_Access".into(), "T1098".into())
    } else if lower.contains("delete user") || lower.contains("disable account") {
        (30, "Impact".into(), "T1531".into())
    } else if lower.contains("add application") || lower.contains("add service principal") {
        (20, "Persistence".into(), "T1098.001".into())
    } else if lower.contains("consent to application") {
        (40, "Persistence".into(), "T1550".into())
    } else if lower.contains("add conditional access policy") || lower.contains("delete conditional access") {
        (35, "Defense_Evasion".into(), "T1562".into())
    } else {
        (0, "Identity_Management".into(), String::new())
    }
}