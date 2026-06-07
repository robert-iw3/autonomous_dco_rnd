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
            sensor_id: env::var("SENSOR_ID").unwrap_or_else(|_| "azure-entraid-connector-default".to_string()),
            sensor_type: "azure-entraid-connector".to_string(),
            spool_dir: PathBuf::from(env::var("SPOOL_DIR").unwrap_or_else(|_| "/app/data/spool".to_string())),
            max_backoff_sec: env::var("MAX_BACKOFF_SEC").unwrap_or_else(|_| "60".to_string()).parse().unwrap_or(60),
            batch_size: env::var("BATCH_SIZE").unwrap_or_else(|_| "500".to_string()).parse().unwrap_or(500),
            batch_timeout_secs: env::var("BATCH_TIMEOUT_SECS").unwrap_or_else(|_| "30".to_string()).parse().unwrap_or(30),
        }
    }
}
