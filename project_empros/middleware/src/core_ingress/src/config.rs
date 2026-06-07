use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Clone)]
pub struct MiddlewareConfig {
    pub global: GlobalConf,
    pub ingress: IngressConf,
    pub destinations: DestinationFlags,
    pub nexus: NexusConf,
    pub splunk: SplunkConf,
    pub elastic: ElasticConf,
    pub sql: SqlConf,
    pub schemas: SchemasConf,
}

#[derive(Deserialize, Clone)]
pub struct GlobalConf {
    pub nats_url: String,
    pub stream_name: String,
    pub telemetry_subject: String,
    pub dlq_subject_prefix: String,
}

#[derive(Deserialize, Clone)]
pub struct IngressConf {
    pub bind_addr: String,
    pub auth_token: String,
    #[serde(default = "default_max_payload")]
    pub max_payload_bytes: usize,
    #[serde(default)]
    pub tls_enabled: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub integrity_secret: String,
    #[serde(default = "default_ban_threshold")]
    pub integrity_ban_threshold: u32,
}

#[derive(Deserialize, Clone)]
pub struct DestinationFlags {
    #[serde(default)] pub nexus_enabled: bool,
    #[serde(default)] pub splunk_enabled: bool,
    #[serde(default)] pub elastic_enabled: bool,
    #[serde(default)] pub sql_enabled: bool,
}

#[derive(Deserialize, Clone)]
pub struct NexusConf {
    pub gateway_url: String,
    pub auth_token: String,
    pub integrity_secret: String,
    #[serde(default)] pub verify_tls: bool,
    #[serde(default = "default_backoff")] pub max_backoff_sec: u64,
}

#[derive(Deserialize, Clone)]
pub struct SplunkConf {
    pub hec_url: String,
    pub hec_token: String,
    pub index_endpoint: String,
    pub index_cloud: String,
    pub index_network: String,
    pub index_alerts: String,
    #[serde(default)] pub index_default: String,
    #[serde(default)] pub alert_score_threshold: i64,
    pub target_sourcetype: String,
    #[serde(default = "default_splunk_batch")] pub batch_size: usize,
    #[serde(default = "default_timeout")] pub timeout_seconds: u64,
    #[serde(default)] pub verify_tls: bool,
}

#[derive(Deserialize, Clone)]
pub struct ElasticConf {
    pub host: String,
    pub index_endpoint: String,
    pub index_cloud: String,
    pub index_network: String,
    #[serde(default)] pub index_default: String,
    pub auth: Option<String>,
    #[serde(default)] pub pipeline: Option<String>,
    #[serde(default = "default_elastic_batch")] pub batch_size: usize,
    #[serde(default = "default_timeout")] pub timeout_seconds: u64,
    #[serde(default)] pub verify_tls: bool,
}

#[derive(Deserialize, Clone)]
pub struct SqlConf {
    pub host: String,
    #[serde(default = "default_sql_port")] pub port: u16,
    pub database: String,
    #[serde(default)] pub use_sspi: bool,
    pub user: Option<String>,
    pub pass: Option<String>,
    #[serde(default = "default_encryption")] pub encryption: String,
    #[serde(default)] pub trust_server_cert: bool,
    pub sproc: String,
    #[serde(default = "default_sql_batch")] pub batch_size: usize,
    #[serde(default = "default_pool_size")] pub pool_size: u32,
    #[serde(default = "default_connect_timeout")] pub connect_timeout_sec: u64,
    pub test_webhook_url: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct SchemasConf {
    pub cim_mappings_file: String,
    pub ecs_mappings_file: String,
}

fn default_max_payload() -> usize { 10_485_760 }
fn default_ban_threshold() -> u32 { 5 }
fn default_backoff() -> u64 { 60 }
fn default_splunk_batch() -> usize { 500 }
fn default_elastic_batch() -> usize { 1000 }
fn default_sql_batch() -> usize { 2000 }
fn default_timeout() -> u64 { 15 }
fn default_sql_port() -> u16 { 1433 }
fn default_pool_size() -> u32 { 4 }
fn default_connect_timeout() -> u64 { 10 }
fn default_encryption() -> String { "Required".into() }

impl MiddlewareConfig {
    pub fn load(path: &str) -> Self {
        let raw = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
        toml::from_str(&raw)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path, e))
    }
}