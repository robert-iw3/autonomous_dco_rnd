use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub total_events: u64,
    pub critical_anomalies: u32,
    pub active_mitigations: u32,
    pub status: String,
    pub hourly_distribution: Vec<HourlyMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyMetric {
    pub hour: String,
    pub count: u32,
}