// VMware syslog -> UnifiedFlowRecord.
//
// Handles three line shapes, in priority order:
//   1. NSX-T distributed/gateway firewall logs  -> network flow record
//      (5-tuple + verdict), with temporal interval/cv per src->dst pair.
//   2. CEF lines (vCenter events forwarded as CEF) -> control-plane event.
//   3. Anything else (vCenter/ESXi plain syslog)  -> generic event record.

use crate::cache::TemporalCache;
use once_cell::sync::Lazy;
use regex::Regex;
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

// NSX-T firewall flow tuple: "10.0.0.5/52311->203.0.113.9/443"
static FLOW_TUPLE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\d{1,3}(?:\.\d{1,3}){3})/(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})/(\d+)").unwrap()
});
// Firewall verdict token.
static VERDICT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(PASS|ALLOW|ACCEPT|DROP|REJECT|DENY|BLOCK)\b").unwrap()
});
// RFC5424 leading timestamp (best-effort).
static TS5424: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})").unwrap());

pub struct Transformer {
    cache: TemporalCache,
    sensor_id: String,
}

impl Transformer {
    pub fn new(cache: TemporalCache, sensor_id: String) -> Self {
        Self { cache, sensor_id }
    }

    pub fn transform_line(&self, line: &str) -> Option<UnifiedFlowRecord> {
        if let Some(cef_start) = line.find("CEF:") {
            return self.transform_cef(&line[cef_start..], line);
        }
        if is_nsx_firewall(line) {
            if let Some(rec) = self.transform_nsx_flow(line) {
                return Some(rec);
            }
        }
        self.transform_generic(line)
    }

    fn transform_nsx_flow(&self, line: &str) -> Option<UnifiedFlowRecord> {
        let caps = FLOW_TUPLE.captures(line)?;
        let src_ip = caps.get(1)?.as_str().to_string();
        let _src_port: i32 = caps.get(2)?.as_str().parse().unwrap_or(0);
        let dst_ip = caps.get(3)?.as_str().to_string();
        let dst_port: i32 = caps.get(4)?.as_str().parse().unwrap_or(0);

        let verdict = VERDICT
            .captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_uppercase())
            .unwrap_or_else(|| "UNKNOWN".to_string());

        let ts = parse_syslog_ts(line);

        // Beaconing features per src->dst conversation.
        let state_key = format!("{}|{}", src_ip, dst_ip);
        let (interval, cv) = self.cache.observe(&state_key, ts);

        let (score, mitre_tactic) = match verdict.as_str() {
            "DROP" | "REJECT" | "DENY" | "BLOCK" => (25, "Network_Deny".to_string()),
            _ => (0, "Network_Flow".to_string()),
        };

        let reasons = serde_json::json!([format!("NSX firewall {} {}->{}:{}", verdict, src_ip, dst_ip, dst_port)])
            .to_string();

        Some(UnifiedFlowRecord {
            timestamp: ts,
            process_name: src_ip, // src endpoint as the actor, mirroring ENI/VM usage
            dst_ip,
            dst_port,
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
            mitre_technique: String::new(),
            mitre_name: String::new(),
            description: String::new(),
            ml_result: None,
            process_hash: String::new(),
            dns_query: String::new(),
            event_type: "vmware_nsx_flow".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id: format!("{}|nsx", self.sensor_id),
        })
    }

    fn transform_cef(&self, cef: &str, full_line: &str) -> Option<UnifiedFlowRecord> {
        let (header, ext) = parse_cef(cef)?;
        // header = [version, vendor, product, dev_version, sig_id, name, severity]
        let name = header.get(5).cloned().unwrap_or_default();
        let sig_id = header.get(4).cloned().unwrap_or_default();
        let severity: f64 = header.get(6).and_then(|s| s.parse().ok()).unwrap_or(0.0);

        let dst_ip = ext.get("dst").or_else(|| ext.get("dhost")).cloned().unwrap_or_else(|| "0.0.0.0".to_string());
        let dst_port: i32 = ext.get("dpt").and_then(|s| s.parse().ok()).unwrap_or(0);
        let actor = ext
            .get("suser")
            .or_else(|| ext.get("duser"))
            .or_else(|| ext.get("src"))
            .cloned()
            .unwrap_or_else(|| "unknown_actor".to_string());

        let ts = ext
            .get("rt")
            .and_then(|s| s.parse::<i64>().ok())
            .map(|ms| (ms / 1000) as f64)
            .unwrap_or_else(|| parse_syslog_ts(full_line));

        let event_name = if !name.is_empty() { name.clone() } else { sig_id.clone() };
        let (extra_score, mitre_tactic, mitre_technique) = classify_vcenter_event(&event_name);
        // CEF severity is 0..10; map to 0..100 and take the stronger of the two signals.
        let cef_score = ((severity * 10.0).round() as i32).clamp(0, 100);
        let score = cef_score.max(extra_score);

        let reasons = serde_json::json!([event_name.clone()]).to_string();

        Some(UnifiedFlowRecord {
            timestamp: ts,
            process_name: format!("vCenter:{}", event_name),
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
            score,
            cmd_snippet: String::new(),
            process_tree: String::new(),
            masquerade_detected: 0,
            reasons,
            mitre_technique,
            mitre_name: String::new(),
            description: ext.get("msg").cloned().unwrap_or_default(),
            ml_result: None,
            process_hash: actor,
            dns_query: String::new(),
            event_type: "vmware_vcenter_event".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id: format!("{}|vcenter", self.sensor_id),
        })
    }

    fn transform_generic(&self, line: &str) -> Option<UnifiedFlowRecord> {
        // Plain vCenter/ESXi syslog: keep it as a low-signal event so nothing
        // is silently dropped; the ML layer can still baseline volume/timing.
        let ts = parse_syslog_ts(line);
        let appname = extract_appname(line);
        let (score, mitre_tactic, mitre_technique) = classify_vcenter_event(line);

        Some(UnifiedFlowRecord {
            timestamp: ts,
            process_name: format!("esxi:{}", appname),
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
            mitre_tactic,
            cmd_entropy: 0.0,
            suppressed: 0,
            score,
            cmd_snippet: String::new(),
            process_tree: String::new(),
            masquerade_detected: 0,
            reasons: "[]".to_string(),
            mitre_technique,
            mitre_name: String::new(),
            description: truncate(line, 512),
            ml_result: None,
            process_hash: String::new(),
            dns_query: String::new(),
            event_type: "vmware_syslog".to_string(),
            dns_flags: 0,
            ja3_hash: String::new(),
            sensor_id: format!("{}|esxi", self.sensor_id),
        })
    }
}

fn is_nsx_firewall(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    (l.contains("firewall") || l.contains("nsx") || l.contains("dfwpktlogs"))
        && FLOW_TUPLE.is_match(line)
}

/// Best-effort syslog timestamp -> epoch seconds (f64). Falls back to now().
fn parse_syslog_ts(line: &str) -> f64 {
    if let Some(m) = TS5424.find(line) {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(m.as_str()) {
            return dt.timestamp() as f64;
        }
    }
    chrono::Utc::now().timestamp() as f64
}

fn extract_appname(line: &str) -> String {
    // Heuristic: in RFC5424 the APP-NAME is field 5; in RFC3164 it precedes ':'.
    // Grab the first ':'-terminated token after any leading PRI/timestamp/host.
    line.split_whitespace()
        .find(|t| t.ends_with(':') && t.len() > 1)
        .map(|t| t.trim_end_matches(':').to_string())
        .unwrap_or_else(|| "vmware".to_string())
}

/// Split a CEF string into its 7 header fields and an extension key/value map.
/// Handles `\|` and `\=` escapes per the CEF spec.
fn parse_cef(cef: &str) -> Option<(Vec<String>, std::collections::HashMap<String, String>)> {
    let body = cef.strip_prefix("CEF:")?;

    let mut fields: Vec<String> = Vec::with_capacity(8);
    let mut cur = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&n) = chars.peek() {
                cur.push(n);
                chars.next();
            }
        } else if c == '|' && fields.len() < 7 {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    let extension = cur; // everything after the 7th '|'
    if fields.len() < 7 {
        return None;
    }

    let mut ext = std::collections::HashMap::new();
    // Extension is "k=v k2=v2 ...". Values may contain spaces, so split on
    // " key=" boundaries by scanning for '=' and back-tracking to the key.
    let tokens: Vec<&str> = extension.split(' ').collect();
    let mut i = 0;
    while i < tokens.len() {
        if let Some(eq) = tokens[i].find('=') {
            let key = tokens[i][..eq].to_string();
            let mut val = tokens[i][eq + 1..].to_string();
            while i + 1 < tokens.len() && !tokens[i + 1].contains('=') {
                val.push(' ');
                val.push_str(tokens[i + 1]);
                i += 1;
            }
            ext.insert(key, val.replace("\\=", "=").replace("\\\\", "\\"));
        }
        i += 1;
    }
    Some((fields, ext))
}

/// Map a vCenter/ESXi event name (or raw line) to (score, tactic, technique).
fn classify_vcenter_event(text: &str) -> (i32, String, String) {
    let l = text.to_ascii_lowercase();
    if l.contains("permission") && (l.contains("added") || l.contains("updated")) {
        (35, "Privilege_Escalation".into(), "T1098".into())
    } else if l.contains("role") && l.contains("added") {
        (35, "Privilege_Escalation".into(), "T1098".into())
    } else if l.contains("vmremoved") || l.contains("vm removed") || l.contains("destroy") {
        (30, "Impact".into(), "T1485".into())
    } else if l.contains("vmcreated") || l.contains("vm created") || l.contains("clone") {
        (15, "Persistence".into(), "T1578.002".into())
    } else if l.contains("snapshot") {
        (20, "Exfiltration".into(), "T1006".into())
    } else if l.contains("migrat") || l.contains("vmotion") {
        (15, "Lateral_Movement".into(), "T1021".into())
    } else if l.contains("login") && (l.contains("fail") || l.contains("error") || l.contains("invalid")) {
        (40, "Credential_Access".into(), "T1110".into())
    } else if l.contains("loginsession") || l.contains("logged in") || l.contains("login") {
        (10, "Initial_Access".into(), "T1078".into())
    } else if l.contains("disabled") && (l.contains("logging") || l.contains("audit") || l.contains("syslog")) {
        (40, "Defense_Evasion".into(), "T1562".into())
    } else {
        (0, "Virtualization_Event".into(), String::new())
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}