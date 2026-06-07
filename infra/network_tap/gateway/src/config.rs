use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Debug, Deserialize)]
pub struct GatewayConfig {
    pub global:     GlobalConfig,
    pub redpanda:   RedpandaConfig,
    pub redis:      RedisConfig,
    pub extraction: ExtractionConfig,
    pub storage:    StorageConfig,
    pub nexus:      NexusConfig,
    pub metrics:    MetricsConfig,
    pub runtime:    RuntimeConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GlobalConfig {
    pub sensor_name: String,
    pub sensor_type: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RedpandaConfig {
    pub brokers:  String,
    pub topic:    String,
    pub group_id: String,
    // Optional mTLS for multi-VM deployments
    pub ssl_ca_location:          Option<String>,
    pub ssl_certificate_location: Option<String>,
    pub ssl_key_location:         Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExtractionConfig {
    #[serde(default = "default_small")]
    pub small_packet_bytes: u64,
    #[serde(default = "default_large")]
    pub large_packet_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StorageConfig {
    pub spool_db_path: String,
    #[serde(default = "default_batch")]
    pub batch_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_sec: u64,
    /// Maximum spool size in bytes; oldest untransmitted rows are dropped when exceeded.
    /// Default: 50 GB. Set to 0 to disable (not recommended).
    #[serde(default = "default_max_spool_bytes")]
    pub max_spool_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NexusConfig {
    pub gateway_url:    String,
    pub auth_token:     String,
    /// Required -- must not be empty or left as the placeholder value.
    pub integrity_secret: Option<String>,
    #[serde(default = "default_transmit_batch")]
    pub transmit_batch_size: u32,
    #[serde(default = "default_poll")]
    pub poll_interval_sec: u64,
    #[serde(default = "default_max_backoff")]
    pub max_backoff_sec: u64,
    #[serde(default = "default_cache_retention")]
    pub cache_retention_sec: u64,
    /// Parquet row group size. Larger groups improve DuckDB range-query pushdown.
    #[serde(default = "default_row_group_size")]
    pub parquet_row_group_size: usize,
    /// Sort rows by timestamp_start before serialization for DuckDB predicate pushdown.
    #[serde(default = "default_sort_enabled")]
    pub transmit_sort_by_timestamp: bool,
    #[serde(default)]
    pub tls: NexusTlsConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct NexusTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub ca_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_workers")]
    pub tokio_worker_threads: usize,
}

impl GatewayConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        let cfg: GatewayConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML config: {}", path))?;

        if !cfg.nexus.gateway_url.starts_with("https://") {
            anyhow::bail!(
                "TLS Enforcement: nexus.gateway_url must use HTTPS. Got: {}",
                cfg.nexus.gateway_url
            );
        }

        match cfg.nexus.integrity_secret.as_deref() {
            None | Some("") | Some("CHANGE_ME_IN_PRODUCTION") => {
                anyhow::bail!(
                    "nexus.integrity_secret must be set to a strong random secret before deployment"
                );
            }
            _ => {}
        }

        if cfg.nexus.transmit_batch_size == 0 {
            anyhow::bail!("nexus.transmit_batch_size must be greater than 0");
        }

        if let Some(parent) = Path::new(&cfg.storage.spool_db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(cfg)
    }
}

fn default_log_level() -> String       { "info".into() }
fn default_small() -> u64              { 128 }
fn default_large() -> u64              { 1400 }
fn default_batch() -> usize            { 5000 }
fn default_flush_interval() -> u64     { 2 }
fn default_transmit_batch() -> u32     { 50_000 }
fn default_poll() -> u64               { 5 }
fn default_max_backoff() -> u64        { 300 }
fn default_cache_retention() -> u64    { 259_200 }
fn default_metrics_port() -> u16       { 9090 }
fn default_workers() -> usize          { 4 }
fn default_max_spool_bytes() -> u64    { 53_687_091_200 }
fn default_row_group_size() -> usize   { 50_000 }
fn default_sort_enabled() -> bool      { true }
