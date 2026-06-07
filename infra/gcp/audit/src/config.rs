use std::env;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub gcp_project_id: String,
    pub subscription_id: String,
    pub gateway_url: String,
    pub integrity_secret: String,
    pub sensor_id: String,
    pub sensor_type: String,
    pub spool_dir: PathBuf,
    pub max_spool_bytes: u64,
    pub max_spool_files: usize,
    pub max_backoff_sec: u64,
    /// Queue-backed transport: Pub/Sub redelivers nacked messages, so the
    /// spool must NOT be replayed on boot (would duplicate). Keep false.
    pub spool_replay: bool,
    pub batch_size: usize,
    pub batch_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            gcp_project_id: env::var("GCP_PROJECT_ID").expect("GCP_PROJECT_ID must be set"),
            subscription_id: env::var("PUBSUB_SUBSCRIPTION").expect("PUBSUB_SUBSCRIPTION must be set"),
            gateway_url: env::var("GATEWAY_URL").expect("GATEWAY_URL must be set"),
            integrity_secret: env::var("INTEGRITY_SECRET").expect("INTEGRITY_SECRET must be set"),
            sensor_id: env::var("SENSOR_ID").unwrap_or_else(|_| "gcp-audit-connector-default".to_string()),
            sensor_type: "gcp_audit".to_string(),
            spool_dir: PathBuf::from(env::var("SPOOL_DIR").unwrap_or_else(|_| "/app/data/spool".to_string())),
            max_spool_bytes: env::var("MAX_SPOOL_BYTES")
                .unwrap_or_else(|_| "524288000".to_string())
                .parse()
                .unwrap_or(524_288_000),
            max_spool_files: env::var("MAX_SPOOL_FILES")
                .unwrap_or_else(|_| "2000".to_string())
                .parse()
                .unwrap_or(2000),
            max_backoff_sec: env::var("MAX_BACKOFF_SEC")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            spool_replay: false,
            batch_size: env::var("BATCH_SIZE").unwrap_or_else(|_| "500".to_string()).parse().unwrap_or(500),
            batch_timeout_secs: env::var("BATCH_TIMEOUT_SECS").unwrap_or_else(|_| "10".to_string()).parse().unwrap_or(10),
        }
    }
}