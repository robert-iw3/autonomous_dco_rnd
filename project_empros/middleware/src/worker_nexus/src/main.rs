use bytes::Bytes;
use hmac::{Hmac, Mac};
use lib_middleware::ParquetWorker;
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::{header, Client};
use sha2::Sha256;
use serde::Deserialize;
use std::{fs, io::Write, path::Path, sync::Mutex, time::{Duration, SystemTime, UNIX_EPOCH}};
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
struct Config { global: GlobalConf, nexus: NexusConf }
#[derive(Deserialize)]
struct GlobalConf { nats_url: String, stream_name: String, telemetry_subject: String, dlq_subject_prefix: String }
#[derive(Deserialize)]
struct NexusConf { gateway_url: String, auth_token: String, integrity_secret: String,
    #[serde(default)] verify_tls: bool,
    #[serde(default = "default_backoff")] max_backoff_sec: u64,
    #[serde(default = "default_batch")] batch_size: usize }
fn default_backoff() -> u64 { 60 }
fn default_batch() -> usize { 100 }

// #7: persistent sequence counter (same pattern as sensor transmitters)
struct SequenceCounter { current: u64, path: std::path::PathBuf }
impl SequenceCounter {
    fn load(dir: &str) -> Self {
        let path = Path::new(dir).join(".nexus_forward_sequence");
        let current = fs::read_to_string(&path).ok()
            .and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
        Self { current, path }
    }
    fn next(&mut self) -> u64 {
        self.current += 1;
        let tmp = self.path.with_extension("tmp");
        if let Ok(mut f) = fs::File::create(&tmp) {
            let _ = write!(f, "{}", self.current);
            let _ = fs::rename(&tmp, &self.path);
        }
        self.current
    }
}

fn compute_hmac(secret: &[u8], payload: &[u8], seq: u64, sensor_id: &str, ts: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(payload); mac.update(&seq.to_be_bytes()); mac.update(sensor_id.as_bytes()); mac.update(&ts.to_be_bytes());
    hex::encode(mac.finalize().into_bytes())
}

struct NexusWorker {
    client: Client,
    gateway_url: String,
    auth_token: String,
    integrity_secret: Vec<u8>,
    sensor_id: String,
    sequence: Mutex<SequenceCounter>,
    max_backoff_sec: u64,
    batch_size: usize,
}

impl ParquetWorker for NexusWorker {
    fn batch_size(&self) -> usize { self.batch_size }

    // #8: retry with ceiling -- framework handles DLQ after 5 failures
    async fn transmit_batch(&self, payloads: Vec<(Bytes, Option<async_nats::HeaderMap>)>) -> Result<(), String> {
        for (payload, headers) in &payloads {
            let seq = self.sequence.lock().unwrap().next();
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let hmac = compute_hmac(&self.integrity_secret, payload, seq, &self.sensor_id, ts);

            let sensor_type = headers.as_ref()
                .and_then(|h| h.get("X-Sensor-Type").map(|v| v.to_string()))
                .unwrap_or_else(|| "middleware-forwarded".to_string());

            // Single attempt per payload -- framework retries the whole batch
            let res = self.client.post(&self.gateway_url)
                .bearer_auth(&self.auth_token)
                .header(header::CONTENT_TYPE, "application/vnd.apache.parquet")
                .header("X-Batch-Sequence", seq.to_string())
                .header("X-Batch-Timestamp", ts.to_string())
                .header("X-Sensor-Id", &self.sensor_id)
                .header("X-Sensor-Type", &sensor_type)
                .header("X-Batch-HMAC", &hmac)
                .body(payload.to_vec())
                .send().await;

            match res {
                Ok(r) if r.status().is_success() => {
                    counter!("middleware_nexus_forwarded_total").increment(1);
                }
                Ok(r) if r.status().as_u16() == 403 => {
                    error!("[INTEGRITY] Nexus gateway 403 -- sensor may be banned");
                    return Err("Nexus 403 FORBIDDEN".into());
                }
                Ok(r) => return Err(format!("Nexus HTTP {}", r.status())),
                Err(e) => return Err(format!("Nexus transport: {}", e)),
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into())).with_target(false).init();
    let metrics_port: u16 = std::env::var("METRICS_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(9012);
    PrometheusBuilder::new().with_http_listener(([0, 0, 0, 0], metrics_port)).install().unwrap();

    let config_path = std::env::var("MIDDLEWARE_CONFIG").unwrap_or_else(|_| "/config/middleware.toml".to_string());
    let raw = fs::read_to_string(&config_path).unwrap();
    let conf: Config = toml::from_str(&raw).unwrap();

    // Use POD_NAME (set by Kubernetes downward API) for a stable identity that survives
    // pod restarts with the same name. Fall back to hostname for non-k8s deployments.
    let sensor_id = std::env::var("POD_NAME")
        .unwrap_or_else(|_| format!("middleware-nexus-{}", gethostname::gethostname().to_string_lossy()));

    // STATE_DIR must be a persistent volume mount -- NOT /tmp (H-R3 fix).
    // /tmp is ephemeral in containers: restart resets counter to 0, causing
    // the nexus gateway to reject all subsequent batches as sequence gaps until
    // the sensor is manually unbanned. Set STATE_DIR in the Quadlet/systemd env.
    let seq_dir = std::env::var("STATE_DIR")
        .unwrap_or_else(|_| "/var/lib/nexus-middleware".to_string());

    // Ensure state directory exists (idempotent -- no-op if already present)
    if let Err(e) = std::fs::create_dir_all(&seq_dir) {
        warn!("STATE_DIR '{}' could not be created: {} -- sequence counter will be reset on restart if volume is not mounted", seq_dir, e);
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(!conf.nexus.verify_tls)
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .build().unwrap();

    let worker = NexusWorker {
        client, gateway_url: conf.nexus.gateway_url.clone(), auth_token: conf.nexus.auth_token.clone(),
        integrity_secret: conf.nexus.integrity_secret.as_bytes().to_vec(),
        sensor_id, sequence: Mutex::new(SequenceCounter::load(&seq_dir)),
        max_backoff_sec: conf.nexus.max_backoff_sec, batch_size: conf.nexus.batch_size,
    };

    info!("Nexus passthrough worker starting | Metrics :{}", metrics_port);
    let subject_filter = format!("{}.*", conf.global.telemetry_subject);
    lib_middleware::start_worker(worker, &conf.global.nats_url, &conf.global.stream_name,
        &subject_filter, "Middleware_Nexus_Forward_Group", &conf.global.dlq_subject_prefix).await;
}
