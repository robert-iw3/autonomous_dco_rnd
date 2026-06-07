use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProfile {
    pub process_hash: String,
    pub event_count: u64,
    pub mean_delta: f64,
    pub m2_delta: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleProfile {
    pub binary_name: String,
    pub instance_count: u32,
    pub max_velocity: f64,
    pub mean_entropy: f64,
}