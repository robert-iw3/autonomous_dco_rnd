use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub timestamp: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub process: String,
    pub cmd_snippet: String,
    pub pid: u32,
    pub uid: u32,
    pub process_tree: String,
    pub masquerade_detected: bool,
    pub avg_interval_sec: f64,
    pub cv: f64,
    pub entropy: f64,
    pub outbound_ratio: f64,
    pub ml_result: Option<String>,
    pub score: u32,
    pub reasons: Vec<String>,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub mitre_name: String,
    pub description: String,
    pub process_hash: String,
    pub event_type: String,
    pub dns_query: String,
    pub dns_flags: u16,
}