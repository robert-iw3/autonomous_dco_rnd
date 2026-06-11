// =================================================================================
// File:        config.rs
// Component:   Linux Sentinel -- State & Configuration Manager
// Description: Handles the parsing and validation of the master.toml file.
// Role:        Deserializes configuration parameters into thread-safe Rust structs,
//              resolves environment variables (e.g., Auth Tokens, TLS certs), and
//              provides the shared Arc<RwLock> state used by all pipeline workers.
// Author:      Robert Weber
// =================================================================================

use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, Clone)]
pub struct MasterConfig {
    pub engine: EngineConfig,
    pub api: ApiConfig,
    pub honeypot: HoneypotConfig,
    pub monitoring: MonitoringConfig,
    pub storage: StorageConfig,
    pub siem: SiemConfig,
    pub network: NetworkConfig,
    pub process: ProcessConfig,
    pub files: FilesConfig,
    #[serde(default)]
    pub exceptions: Vec<ProcessException>,
    #[serde(default)]
    pub clamav: ClamavConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct EngineConfig {
    pub enable_ebpf: bool,
    pub enable_yara: bool,
    pub enable_honeypots: bool,
    pub enable_anti_evasion: bool,
    #[serde(default = "default_true")]
    pub enable_fim: bool,
    #[serde(default)]
    pub enable_active_mitigation: bool,
    #[serde(default)]
    pub performance_mode: bool,
    #[serde(default = "default_true")]
    pub enable_api_server: bool,
    #[serde(default = "default_feature_dim")]
    #[allow(dead_code)]
    pub ml_feature_dimensions: usize,
    #[serde(default = "default_adaptive_thresh")]
    pub ml_adaptive_thresholds: bool,
    #[serde(default = "default_dedup_window")]
    pub ml_deduplication_window_sec: u64,
    #[serde(default = "default_forest_timeout")]
    pub ml_forest_training_timeout_sec: u64,
    #[serde(default = "default_baseline_path")]
    pub ml_persistent_store_path: String,
    #[serde(default = "default_yara_path")]
    pub yara_rules_path: String,
    #[serde(default = "default_sigma_path")]
    pub sigma_rules_path: String,
    #[serde(default = "default_ips_path")]
    pub malicious_ips_path: String,
}
fn default_true() -> bool { true }
fn default_feature_dim() -> usize { 19 }
fn default_adaptive_thresh() -> bool { true }
fn default_dedup_window() -> u64 { 60 }
fn default_forest_timeout() -> u64 { 60 }
fn default_baseline_path() -> String { "/var/log/linux-sentinel/baselines.db".to_string() }
fn default_yara_path() -> String { "/etc/linux-sentinel/rules/yara".to_string() }
fn default_sigma_path() -> String { "/etc/linux-sentinel/rules/sigma".to_string() }
fn default_ips_path() -> String { "/etc/linux-sentinel/rules/ips.txt".to_string() }

#[derive(Deserialize, Debug, Clone)]
pub struct ApiConfig {
    #[serde(default = "default_api_bind")]
    pub bind_addr: String,
    #[serde(default = "default_api_port")]
    pub port: u16,
    #[serde(default)]
    pub tls_cert: String,
    #[serde(default)]
    pub tls_key: String,
}
fn default_api_bind() -> String { "0.0.0.0".to_string() }
fn default_api_port() -> u16 { 8080 }

#[derive(Deserialize, Debug, Clone)]
pub struct HoneypotConfig {
    #[serde(default = "default_honeypot_bind")]
    pub honeypot_bind_addr: String,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_per_port: usize,
    #[serde(default = "default_max_per_min")]
    pub max_connections_per_minute: usize,
}
fn default_honeypot_bind() -> String { "127.0.0.1".to_string() }
fn default_max_concurrent() -> usize { 10 }
fn default_max_per_min() -> usize { 100 }

#[derive(Deserialize, Debug, Clone)]
pub struct MonitoringConfig {
    pub monitor_network: bool,
    pub monitor_processes: bool,
    pub monitor_files: bool,
    pub monitor_users: bool,
    pub monitor_rootkits: bool,
    pub monitor_memory: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct StorageConfig {
    pub central_log_dir: String,
    pub output_dir: String,
    pub sqlite_db_path: String,
    #[serde(default = "default_true")]
    pub enable_parquet: bool,
    #[serde(default = "default_parquet_dir")]
    pub parquet_directory: String,
}

fn default_parquet_dir() -> String {
    "/var/backups/linux-sentinel/parquet".to_string()
}

#[derive(Deserialize, Debug, Clone)]
pub struct SiemConfig {
    pub middleware_gateway_url: String,
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
    pub auth_token: String,
    pub batch_size: usize,
    pub integrity_secret: Option<String>,
    #[serde(default = "default_batch_size")]
    pub parquet_batch_size: usize,
    #[serde(default = "default_flush_interval")]
    pub parquet_flush_interval_sec: u64,
    #[serde(default = "default_compression")]
    pub parquet_compression: String,
}
fn default_batch_size() -> usize { 500 }
fn default_flush_interval() -> u64 { 15 }
fn default_compression() -> String { "zstd".to_string() }

#[derive(Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub whitelist_connections: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProcessException {
    pub comm: String,
    pub technique: String,
    pub targets: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProcessConfig {
    pub whitelist_processes: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FilesConfig {
    pub exclude_paths: Vec<String>,
    pub critical_paths: Vec<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct ClamavConfig {
    #[serde(default = "default_true")]
    pub enable_clamav: bool,
    #[serde(default = "default_true")]
    pub enable_freshclam_sync: bool,
    #[serde(default = "default_scan_interval")]
    pub scan_interval_sec: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_sec: u64,
    #[serde(default = "default_true")]
    pub armed_mode_only: bool,
    #[serde(default = "default_clamav_targets")]
    pub target_paths: Vec<String>,
}

fn default_scan_interval() -> u64 { 86400 }
fn default_sync_interval() -> u64 { 43200 }
fn default_clamav_targets() -> Vec<String> {
    vec![
        "/tmp/".to_string(),
        "/var/tmp/".to_string(),
        "/dev/shm/".to_string(),
        "/opt/linux-sentinel/intel_staging/".to_string()
    ]
}

pub fn resolve_auth_token(config_value: &str) -> anyhow::Result<String> {
    let token = if config_value.starts_with("${") && config_value.ends_with("}") {
        let var_name = &config_value[2..config_value.len() - 1];
        std::env::var(var_name).map_err(|_| {
            anyhow::anyhow!("Auth token references env var '{}' which is not set.", var_name)
        })?
    } else {
        config_value.to_string()
    };

    if token.len() < 16 {
        tracing::warn!("Auth token is shorter than 16 characters. Consider using a stronger token.");
    }
    Ok(token)
}

pub fn load_master_config(path: &str) -> anyhow::Result<MasterConfig> {
    let config_content = fs::read_to_string(path)?;
    let mut config: MasterConfig = toml::from_str(&config_content)?;

    config.siem.auth_token = resolve_auth_token(&config.siem.auth_token)?;

    // Environment overrides for TLS (Supports Kubernetes Secret mounting)
    if let Ok(cert) = std::env::var("SENTINEL_API_TLS_CERT") {
        config.api.tls_cert = cert;
    }
    if let Ok(key) = std::env::var("SENTINEL_API_TLS_KEY") {
        config.api.tls_key = key;
    }

    Ok(config)
}