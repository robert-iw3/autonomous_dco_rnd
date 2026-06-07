use serde::{Deserialize, Serialize};

// =============================================================================
// KernelEvent -- Per-event data parsed from the eBPF ring buffer
// =============================================================================
// Intermediate representation between the raw C struct (RawEvent) and the
// aggregated FlowEvent written to SQLite. Carries parsed strings and computed
// fields (entropy, dns_query) but has NOT been aggregated yet.
//
// Data flow: eBPF event_t → RawEvent (repr(C)) → KernelEvent → FlowEvent → SQLite
// =============================================================================
#[derive(Debug, Clone)]
pub struct KernelEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub hash: String,
    pub event_type: String,
    pub packet_size: u32,
    pub is_outbound: u8,
    pub dst_ip: String,
    pub dst_port: u16,
    pub interval_ns: u64,
    pub entropy: f64,
    pub dns_query: String,
    pub dns_flags: u16,
    pub ja3_hash: String,
    pub sensor_id: String,
}

// =============================================================================
// FlowEvent -- Aggregated flow record for SQLite batch insertion
// =============================================================================
// Represents one or more KernelEvents grouped by (pid, dst_ip, dst_port)
// within a single batch window. Packet size statistics are computed via
// Welford's online algorithm during aggregation.
//
// Maps 1:1 to the INSERT INTO flows(...) column list.
// =============================================================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    pub timestamp: f64,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub hash: String,
    pub event_type: String,
    pub is_outbound: u8,
    pub dst_ip: String,
    pub dst_port: u16,

    // Timing & payload metrics
    pub interval_sec: f64,
    pub entropy: f64,
    pub cmd_entropy: f64,

    // Welford's packet size statistics
    pub packet_count: u32,
    pub packet_size_mean: f64,
    pub packet_size_std: f64,      // Running M2, finalized to std_dev before INSERT
    pub packet_size_min: u32,
    pub packet_size_max: u32,
    pub cv: f64,                   // Coefficient of variation (std / mean)

    // Intelligence fields
    pub dns_query: String,
    pub dns_flags: u16,
    pub ja3_hash: String,
    pub sensor_id: String,
}