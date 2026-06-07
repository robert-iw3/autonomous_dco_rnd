use std::env;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub eventhub_connection_str: String,
    pub eventhub_name: String,
    pub consumer_group: String,
    pub gateway_url: String,
    pub integrity_secret: String,
    pub sensor_id: String,
    pub sensor_type: String,
    pub spool_dir: PathBuf,
    pub max_spool_bytes: u64,
    pub max_spool_files: usize,
    pub spool_replay: bool,
    pub max_backoff_sec: u64,
    pub batch_size: usize,
    pub batch_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            eventhub_connection_str: env::var("EVENTHUB_CONNECTION_STRING").expect("EVENTHUB_CONNECTION_STRING required"),
            eventhub_name: env::var("EVENTHUB_NAME").expect("EVENTHUB_NAME required"),
            consumer_group: env::var("CONSUMER_GROUP").unwrap_or_else(|_| "$Default".to_string()),
            gateway_url: env::var("GATEWAY_URL").expect("GATEWAY_URL required"),
            integrity_secret: env::var("INTEGRITY_SECRET").expect("INTEGRITY_SECRET required"),
            sensor_id: env::var("SENSOR_ID").unwrap_or_else(|_| "azure-activity-connector-default".to_string()),
            sensor_type: "azure-activity-connector".to_string(),
            spool_dir: PathBuf::from(env::var("SPOOL_DIR").unwrap_or_else(|_| "/app/data/spool".to_string())),
            max_spool_bytes: env::var("MAX_SPOOL_BYTES")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(524_288_000),
            max_spool_files: env::var("MAX_SPOOL_FILES")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(2000),
            spool_replay: false,
            max_backoff_sec: env::var("MAX_BACKOFF_SEC")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(60),
            batch_size: env::var("BATCH_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(500),
            batch_timeout_secs: env::var("BATCH_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30),
        }
    }
}