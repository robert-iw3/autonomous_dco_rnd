use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlertLevel { Critical, High, Medium, Low, Info }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MitreTactic {
    #[serde(rename = "TA0001 Initial Access")] InitialAccess,
    #[serde(rename = "TA0002 Execution")] Execution,
    #[serde(rename = "TA0003 Persistence")] Persistence,
    #[serde(rename = "TA0004 Privilege Escalation")] PrivilegeEscalation,
    #[serde(rename = "TA0005 Defense Evasion")] DefenseEvasion,
    #[serde(rename = "TA0006 Credential Access")] CredentialAccess,
    #[serde(rename = "TA0007 Discovery")] Discovery,
    #[serde(rename = "TA0008 Lateral Movement")] LateralMovement,
    #[serde(rename = "TA0009 Collection")] Collection,
    #[serde(rename = "TA0011 Command and Control")] CommandAndControl,
    #[serde(rename = "TA0010 Exfiltration")] Exfiltration,
    #[serde(rename = "TA0040 Impact")] Impact,
    #[serde(rename = "Unknown")] Unknown,
}

pub struct RuleMatch {
    pub level: AlertLevel,
    pub mitre_tactic: MitreTactic,
    pub mitre_technique: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub endpoint_id: String,
    pub event_id: String,
    pub timestamp: u64,
    pub level: AlertLevel,
    pub mitre_tactic: MitreTactic,
    pub mitre_technique: String,

    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub container_id: String,
    pub container_name: String,
    pub comm: String,
    pub command_line: String,

    pub target_file: Option<String>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,
    pub source_port: Option<u16>,
    pub parent_comm: String,
    pub user_name: String,

    pub shannon_entropy: f64,
    pub execution_velocity: f64,
    pub tuple_rarity: f64,
    pub path_depth: usize,
    pub anomaly_score: f64,

    pub message: String,
    pub in_memory_capture: Option<bool>,
    pub ml_vector: Option<Vec<f64>>,
}

impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AlertLevel::Critical => write!(f, "CRITICAL"),
            AlertLevel::High => write!(f, "HIGH"),
            AlertLevel::Medium => write!(f, "MEDIUM"),
            AlertLevel::Low => write!(f, "LOW"),
            AlertLevel::Info => write!(f, "INFO"),
        }
    }
}

impl std::fmt::Display for MitreTactic {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            MitreTactic::InitialAccess => "TA0001 Initial Access",
            MitreTactic::Execution => "TA0002 Execution",
            MitreTactic::Persistence => "TA0003 Persistence",
            MitreTactic::PrivilegeEscalation => "TA0004 Privilege Escalation",
            MitreTactic::DefenseEvasion => "TA0005 Defense Evasion",
            MitreTactic::CredentialAccess => "TA0006 Credential Access",
            MitreTactic::Discovery => "TA0007 Discovery",
            MitreTactic::LateralMovement => "TA0008 Lateral Movement",
            MitreTactic::Collection => "TA0009 Collection",
            MitreTactic::Exfiltration => "TA0010 Exfiltration",
            MitreTactic::CommandAndControl => "TA0011 Command and Control",
            MitreTactic::Impact => "TA0040 Impact",
            MitreTactic::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

impl SecurityAlert {
    /// constructor 1: HIGH-FIDELITY (from_rule)
    /// Used by the ScannerEngine to achieve single-pass, zero-copy memory allocation
    /// for kernel telemetry enriched with mathematical UEBA features.
    pub fn from_rule(
        endpoint_id: String,
        rule: RuleMatch,
        pid: u32,
        ppid: u32,
        uid: u32,
        cgroup_id: u64,
        container_id: String,
        container_name: String,
        comm: String,
        command_line: String,
        parent_comm: String,
        user_name: String,
        source_port: Option<u16>,
        target_file: Option<String>,
        dest_ip: Option<String>,
        dest_port: Option<u16>,
        shannon_entropy: f64,
        execution_velocity: f64,
        tuple_rarity: f64,
        path_depth: usize,
        anomaly_score: f64,
    ) -> Self {
        Self {
            endpoint_id,
            event_id: Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            level: rule.level,
            mitre_tactic: rule.mitre_tactic,
            mitre_technique: rule.mitre_technique,
            message: rule.message,
            pid,
            ppid,
            uid,
            cgroup_id,
            container_id,
            container_name,
            comm,
            command_line,
            parent_comm,
            user_name,
            source_port,
            target_file,
            dest_ip,
            dest_port,
            shannon_entropy,
            execution_velocity,
            tuple_rarity,
            path_depth,
            anomaly_score,
            in_memory_capture: None,
            ml_vector: None,
        }
    }

    /// constructor 2: SYNTHETIC
    /// A convenience constructor for modules like Honeypots or YARA that do not
    /// originate from raw kernel syscalls and lack 5D mathematical context.
    pub fn new(
        endpoint_id: String,
        level: AlertLevel,
        message: String,
        mitre_tactic: MitreTactic,
        mitre_technique: &str
    ) -> Self {
        Self {
            endpoint_id,
            event_id: Uuid::new_v4().to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            level,
            mitre_tactic,
            mitre_technique: mitre_technique.to_string(),
            pid: 0,
            ppid: 0,
            uid: 0,
            cgroup_id: 0,
            container_id: String::new(),
            container_name: "host".to_string(),
            comm: String::new(),
            command_line: String::new(),
            parent_comm: "unknown".to_string(),
            user_name: "system".to_string(),
            source_port: None,
            target_file: None,
            dest_ip: None,
            dest_port: None,
            shannon_entropy: 0.0,
            execution_velocity: 0.0,
            tuple_rarity: 0.0,
            path_depth: 0,
            anomaly_score: 0.0,
            message,
            in_memory_capture: None,
            ml_vector: None,
        }
    }
}