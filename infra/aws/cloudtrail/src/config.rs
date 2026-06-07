use std::env;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub sqs_queue_url: String,
    pub gateway_url: String,
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
            sqs_queue_url: env::var("SQS_QUEUE_URL").expect("SQS_QUEUE_URL must be set"),
            gateway_url: env::var("GATEWAY_URL").expect("GATEWAY_URL must be set"),
            integrity_secret: env::var("INTEGRITY_SECRET").expect("INTEGRITY_SECRET must be set"),
            sensor_id: env::var("SENSOR_ID").unwrap_or_else(|_| "cloudtrail-connector-default".to_string()),
            sensor_type: "aws-cloudtrail-connector".to_string(),
            spool_dir: PathBuf::from(env::var("SPOOL_DIR").unwrap_or_else(|_| "/app/data/spool".to_string())),
            max_spool_bytes: env::var("MAX_SPOOL_BYTES")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(524_288_000),
            max_spool_files: env::var("MAX_SPOOL_FILES")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(2000),
            spool_replay: false,
            max_backoff_sec: env::var("MAX_BACKOFF_SEC")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
        }
    }
}