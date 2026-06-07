use serde::Deserialize;
use std::fs;
use once_cell::sync::Lazy;

#[derive(Debug, Deserialize)]
pub struct SensorConfig {
    pub global: GlobalConfig,
    pub ebpf: EbpfConfig,
    pub api_dashboard: ApiConfig,
    pub mitigation: MitigationConfig,
    pub nexus: NexusConfig,
}

#[derive(Debug, Deserialize)]
pub struct GlobalConfig {
    pub sensor_name: String,
    pub mode: String,
    pub db_path: String,
    pub auth_db_path: Option<String>,
    pub log_level: String,
}

#[derive(Debug, Deserialize)]
pub struct EbpfConfig {
    pub bpf_object_path: String,
    pub target_interface: String,
    pub ring_buffer_max_entries: u32,
    pub capture_loopback: bool,
}

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub bind_address: String,
    pub port: u16,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub static_ui_path: String,
    pub jwt_secret: String,
    pub default_admin_password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MitigationConfig {
    pub enabled: bool,
    pub dry_run: bool,
    pub containment_threshold: u32,
}

#[derive(Debug, Deserialize)]
pub struct NexusConfig {
    pub enabled: bool,
    pub nats_url: String,
    pub stream_name: String,
    pub subject_prefix: String,
    pub spool_dir: String,
    pub max_backoff_sec: f64,
    pub publish_delay_sec: f64,
}

pub static CONFIG: Lazy<SensorConfig> = Lazy::new(|| {
    let config_path = std::env::var("SENSOR_CONFIG_PATH")
        .unwrap_or_else(|_| "/app/config.toml".to_string());

    let file_content = fs::read_to_string(&config_path)
        .unwrap_or_else(|_| panic!("[-] FATAL: Could not read configuration file at {}", config_path));

    let mut config: SensorConfig = toml::from_str(&file_content)
        .expect("[-] FATAL: Failed to parse config.toml syntax");

    // JWT_SECRET env takes precedence over config file value
    if let Ok(secret) = std::env::var("JWT_SECRET") {
        if !secret.is_empty() {
            config.api_dashboard.jwt_secret = secret;
        }
    }

    // C2_ADMIN_PASSWORD env takes precedence
    if let Ok(pass) = std::env::var("C2_ADMIN_PASSWORD") {
        if !pass.is_empty() {
            config.api_dashboard.default_admin_password = Some(pass);
        }
    }

    // Validate: reject the sentinel value at runtime -- run.sh must have rotated it
    if config.api_dashboard.jwt_secret == "CHANGE_ME_IN_PRODUCTION" {
        panic!(
            "[-] FATAL: jwt_secret is still the default sentinel. \
             Run ./run.sh to auto-generate, or set JWT_SECRET env var."
        );
    }

    config
});