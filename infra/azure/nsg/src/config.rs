use std::env;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub eventhub_namespace: String,
    pub eventhub_name: String,
    pub consumer_group: String,
    pub storage_account_url: String,
    pub storage_container: String,
    pub table_storage_url: String,
    pub gateway_url: String,
    pub auth_token: String,
    pub integrity_secret: String,
    pub sensor_id: String,
    pub sensor_type: String,
    pub spool_dir: PathBuf,
    pub max_spool_bytes: u64,
    pub max_spool_files: usize,
    pub spool_replay: bool,
    pub max_backoff_sec: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            eventhub_namespace: env::var("EVENTHUB_NAMESPACE").expect("EVENTHUB_NAMESPACE required"),
            eventhub_name: env::var("EVENTHUB_NAME").expect("EVENTHUB_NAME required"),
            consumer_group: env::var("CONSUMER_GROUP").unwrap_or_else(|_| "$Default".to_string()),
            storage_account_url: env::var("STORAGE_ACCOUNT_URL").expect("STORAGE_ACCOUNT_URL required"),
            storage_container: env::var("STORAGE_CONTAINER")
                .unwrap_or_else(|_| "insights-logs-networksecuritygroupflowevent".to_string()),
            table_storage_url: env::var("TABLE_STORAGE_URL").expect("TABLE_STORAGE_URL required"),
            gateway_url: env::var("GATEWAY_URL").expect("GATEWAY_URL required"),
            auth_token: env::var("AUTH_TOKEN").expect("AUTH_TOKEN must be set"),
            integrity_secret: env::var("INTEGRITY_SECRET").expect("INTEGRITY_SECRET required"),
            sensor_id: env::var("SENSOR_ID").unwrap_or_else(|_| "azure-nsg-connector-default".to_string()),
            sensor_type: "azure-nsg-flow-connector".to_string(),
            spool_dir: PathBuf::from(env::var("SPOOL_DIR").unwrap_or_else(|_| "/app/data/spool".to_string())),
            max_spool_bytes: env::var("MAX_SPOOL_BYTES")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(524_288_000),
            max_spool_files: env::var("MAX_SPOOL_FILES")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(2000),
            spool_replay: false,
            max_backoff_sec: env::var("MAX_BACKOFF_SEC")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(60),
        }
    }
}