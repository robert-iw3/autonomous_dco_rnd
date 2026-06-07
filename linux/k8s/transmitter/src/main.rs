// =============================================================================
// Falco Transmitter
//
// Tails /logs/falco-events.log (Falco's file_output), parses JSON events,
// batches into Arrow RecordBatches, serializes to Parquet (ZSTD), and POSTs
// to the Nexus Axum gateway with integrity headers.
//
// When the gateway is unreachable, Parquet files are spooled to a local
// directory. On reconnect, the spool is drained oldest-first before live data.
// =============================================================================

use arrow::array::{Int32Builder, StringBuilder, UInt16Builder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use bytes::Bytes;
use chrono::Utc;
use hmac::{Hmac, Mac};
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use reqwest::Client;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tracing::{error, info, warn, Level};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

type HmacSha256 = Hmac<Sha256>;

// -- Configuration ------------------------------------------------------------

struct Config {
    log_path: PathBuf,
    gateway_url: String,
    auth_token: String,
    integrity_secret: String,
    sensor_id: String,
    spool_dir: PathBuf,
    batch_size: usize,
    batch_timeout_secs: u64,
    max_backoff_secs: u64,
    metrics_port: u16,
}

impl Config {
    fn from_env() -> Self {
        Self {
            log_path: PathBuf::from(
                std::env::var("FALCO_LOG_PATH").unwrap_or_else(|_| "/logs/falco-events.log".into()),
            ),
            gateway_url: std::env::var("NEXUS_GATEWAY_URL")
                .unwrap_or_else(|_| "https://nexus-edge:8080/api/v1/telemetry".into()),
            auth_token: std::env::var("NEXUS_AUTH_TOKEN")
                .expect("NEXUS_AUTH_TOKEN required"),
            integrity_secret: std::env::var("NEXUS_INTEGRITY_SECRET")
                .expect("NEXUS_INTEGRITY_SECRET required"),
            sensor_id: std::env::var("SENSOR_ID")
                .unwrap_or_else(|_| "falco-runtime-01".into()),
            spool_dir: PathBuf::from(
                std::env::var("SPOOL_DIR").unwrap_or_else(|_| "/var/spool/falco_transmitter".into()),
            ),
            batch_size: std::env::var("BATCH_SIZE")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(500),
            batch_timeout_secs: std::env::var("BATCH_TIMEOUT_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(10),
            max_backoff_secs: std::env::var("MAX_BACKOFF_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(300),
            metrics_port: std::env::var("METRICS_PORT")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(9010),
        }
    }
}

// -- Falco Event Schema -------------------------------------------------------

#[derive(Deserialize, Debug)]
struct FalcoEvent {
    output: Option<String>,
    priority: Option<String>,
    rule: Option<String>,
    time: Option<String>,
    source: Option<String>,
    hostname: Option<String>,
    tags: Option<Vec<String>>,
    #[serde(default)]
    output_fields: HashMap<String, serde_json::Value>,
}

fn falco_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("timestamp", DataType::Utf8, false),
        Field::new("priority", DataType::Utf8, false),
        Field::new("rule", DataType::Utf8, false),
        Field::new("source", DataType::Utf8, true),
        Field::new("output", DataType::Utf8, true),
        Field::new("hostname", DataType::Utf8, true),
        Field::new("tags", DataType::Utf8, true),
        Field::new("container_id", DataType::Utf8, true),
        Field::new("container_name", DataType::Utf8, true),
        Field::new("container_image", DataType::Utf8, true),
        Field::new("proc_name", DataType::Utf8, true),
        Field::new("proc_cmdline", DataType::Utf8, true),
        Field::new("proc_pname", DataType::Utf8, true),
        Field::new("proc_ppid", DataType::Int32, true),
        Field::new("proc_exepath", DataType::Utf8, true),
        Field::new("user_name", DataType::Utf8, true),
        Field::new("user_uid", DataType::Int32, true),
        Field::new("evt_type", DataType::Utf8, true),
        Field::new("fd_name", DataType::Utf8, true),
        Field::new("fd_sip", DataType::Utf8, true),
        Field::new("fd_dip", DataType::Utf8, true),
        Field::new("fd_sport", DataType::UInt16, true),
        Field::new("fd_dport", DataType::UInt16, true),
        Field::new("fd_l4proto", DataType::Utf8, true),
        Field::new("raw_fields", DataType::Utf8, true),
        Field::new("sensor_id", DataType::Utf8, false),
        Field::new("sensor_type", DataType::Utf8, false),
    ]))
}

// -- Parquet Serialization ----------------------------------------------------

fn events_to_parquet(events: &[FalcoEvent], sensor_id: &str) -> Result<Vec<u8>, String> {
    let schema = falco_schema();
    let cap = events.len();

    let mut ts_b = StringBuilder::with_capacity(cap, cap * 30);
    let mut pri_b = StringBuilder::with_capacity(cap, cap * 10);
    let mut rule_b = StringBuilder::with_capacity(cap, cap * 40);
    let mut src_b = StringBuilder::new();
    let mut out_b = StringBuilder::new();
    let mut host_b = StringBuilder::new();
    let mut tags_b = StringBuilder::new();
    let mut cid_b = StringBuilder::new();
    let mut cname_b = StringBuilder::new();
    let mut cimg_b = StringBuilder::new();
    let mut pname_b = StringBuilder::new();
    let mut pcmd_b = StringBuilder::new();
    let mut ppname_b = StringBuilder::new();
    let mut pppid_b = Int32Builder::with_capacity(cap);
    let mut pexe_b = StringBuilder::new();
    let mut uname_b = StringBuilder::new();
    let mut uuid_b = Int32Builder::with_capacity(cap);
    let mut etype_b = StringBuilder::new();
    let mut fdname_b = StringBuilder::new();
    let mut fdsip_b = StringBuilder::new();
    let mut fddip_b = StringBuilder::new();
    let mut fdsport_b = UInt16Builder::with_capacity(cap);
    let mut fddport_b = UInt16Builder::with_capacity(cap);
    let mut fdproto_b = StringBuilder::new();
    let mut raw_b = StringBuilder::new();
    let mut sid_b = StringBuilder::with_capacity(cap, cap * 20);
    let mut stype_b = StringBuilder::with_capacity(cap, cap * 14);

    for e in events {
        ts_b.append_value(e.time.as_deref().unwrap_or(""));
        pri_b.append_value(e.priority.as_deref().unwrap_or("Unknown"));
        rule_b.append_value(e.rule.as_deref().unwrap_or(""));
        append_opt(&mut src_b, e.source.as_deref());
        append_opt(&mut out_b, e.output.as_deref());
        append_opt(&mut host_b, e.hostname.as_deref());
        append_opt(&mut tags_b, e.tags.as_ref().map(|t| t.join(",")).as_deref());

        let f = &e.output_fields;
        append_opt(&mut cid_b, str_field(f, "container.id"));
        append_opt(&mut cname_b, str_field(f, "container.name"));
        append_opt(&mut cimg_b, str_field(f, "container.image.repository"));
        append_opt(&mut pname_b, str_field(f, "proc.name"));
        append_opt(&mut pcmd_b, str_field(f, "proc.cmdline"));
        append_opt(&mut ppname_b, str_field(f, "proc.pname"));
        int_field(&mut pppid_b, f, "proc.ppid");
        append_opt(&mut pexe_b, str_field(f, "proc.exepath"));
        append_opt(&mut uname_b, str_field(f, "user.name"));
        int_field(&mut uuid_b, f, "user.uid");
        append_opt(&mut etype_b, str_field(f, "evt.type"));
        append_opt(&mut fdname_b, str_field(f, "fd.name"));
        append_opt(&mut fdsip_b, str_field(f, "fd.sip"));
        append_opt(&mut fddip_b, str_field(f, "fd.dip"));
        u16_field(&mut fdsport_b, f, "fd.sport");
        u16_field(&mut fddport_b, f, "fd.dport");
        append_opt(&mut fdproto_b, str_field(f, "fd.l4proto"));

        // Preserve all output_fields as raw JSON for downstream enrichment
        raw_b.append_value(serde_json::to_string(f).unwrap_or_default());
        sid_b.append_value(sensor_id);
        stype_b.append_value("falco_runtime");
    }

    let batch = RecordBatch::try_new(schema.clone(), vec![
        Arc::new(ts_b.finish()), Arc::new(pri_b.finish()), Arc::new(rule_b.finish()),
        Arc::new(src_b.finish()), Arc::new(out_b.finish()), Arc::new(host_b.finish()),
        Arc::new(tags_b.finish()),
        Arc::new(cid_b.finish()), Arc::new(cname_b.finish()), Arc::new(cimg_b.finish()),
        Arc::new(pname_b.finish()), Arc::new(pcmd_b.finish()), Arc::new(ppname_b.finish()),
        Arc::new(pppid_b.finish()), Arc::new(pexe_b.finish()),
        Arc::new(uname_b.finish()), Arc::new(uuid_b.finish()),
        Arc::new(etype_b.finish()),
        Arc::new(fdname_b.finish()), Arc::new(fdsip_b.finish()), Arc::new(fddip_b.finish()),
        Arc::new(fdsport_b.finish()), Arc::new(fddport_b.finish()), Arc::new(fdproto_b.finish()),
        Arc::new(raw_b.finish()), Arc::new(sid_b.finish()), Arc::new(stype_b.finish()),
    ]).map_err(|e| format!("RecordBatch build failed: {e}"))?;

    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(Default::default()))
        .build();
    let mut buf = Vec::with_capacity(cap * 256);
    let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))
        .map_err(|e| format!("Parquet writer init failed: {e}"))?;
    writer.write(&batch).map_err(|e| format!("Parquet write failed: {e}"))?;
    writer.close().map_err(|e| format!("Parquet close failed: {e}"))?;

    Ok(buf)
}

fn append_opt(b: &mut StringBuilder, v: Option<&str>) {
    match v {
        Some(s) if !s.is_empty() => b.append_value(s),
        _ => b.append_null(),
    }
}

fn str_field<'a>(f: &'a HashMap<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    f.get(key).and_then(|v| v.as_str())
}

fn int_field(b: &mut Int32Builder, f: &HashMap<String, serde_json::Value>, key: &str) {
    match f.get(key).and_then(|v| v.as_i64()) {
        Some(n) => b.append_value(n as i32),
        None => b.append_null(),
    }
}

fn u16_field(b: &mut UInt16Builder, f: &HashMap<String, serde_json::Value>, key: &str) {
    match f.get(key).and_then(|v| v.as_u64()) {
        Some(n) => b.append_value(n as u16),
        None => b.append_null(),
    }
}

// -- Integrity Stamping -------------------------------------------------------

struct Stamper {
    sensor_id: String,
    secret: Vec<u8>,
    sequence: u64,
}

impl Stamper {
    fn stamp(&mut self, payload: &[u8]) -> (u64, u64, String) {
        self.sequence += 1;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut mac = HmacSha256::new_from_slice(&self.secret).unwrap();
        mac.update(payload);
        mac.update(&self.sequence.to_be_bytes());
        mac.update(self.sensor_id.as_bytes());
        mac.update(&ts.to_be_bytes());
        let hmac_hex = hex::encode(mac.finalize().into_bytes());
        (self.sequence, ts, hmac_hex)
    }
}

// -- Gateway Transmitter ------------------------------------------------------

async fn transmit_parquet(
    client: &Client,
    url: &str,
    auth_token: &str,
    parquet_bytes: &[u8],
    stamper: &mut Stamper,
) -> bool {
    let (seq, ts, hmac) = stamper.stamp(parquet_bytes);

    let resp = client
        .post(url)
        .bearer_auth(auth_token)
        .header("Content-Type", "application/vnd.apache.parquet")
        .header("X-Sensor-Type", "falco_runtime")
        .header("X-Sensor-Id", &stamper.sensor_id)
        .header("X-Batch-Sequence", seq.to_string())
        .header("X-Batch-Timestamp", ts.to_string())
        .header("X-Batch-HMAC", &hmac)
        .header("X-Partition-Date", Utc::now().format("%Y-%m-%d").to_string())
        .header("X-Partition-Hour", Utc::now().format("%H").to_string())
        .body(parquet_bytes.to_vec())
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            counter!("falco_tx_batches_sent_total").increment(1);
            true
        }
        Ok(r) => {
            warn!(status = %r.status(), "Gateway rejected payload");
            counter!("falco_tx_gateway_rejections_total").increment(1);
            false
        }
        Err(e) => {
            warn!(error = %e, "Gateway unreachable");
            counter!("falco_tx_gateway_errors_total").increment(1);
            false
        }
    }
}

fn spool_to_disk(spool_dir: &Path, parquet_bytes: &[u8]) {
    let fname = format!("spool_{}.parquet", uuid::Uuid::new_v4());
    let path = spool_dir.join(&fname);
    if let Err(e) = std::fs::write(&path, parquet_bytes) {
        error!(error = %e, path = %path.display(), "Failed to spool Parquet to disk");
    } else {
        counter!("falco_tx_spool_writes_total").increment(1);
        info!(file = %fname, bytes = parquet_bytes.len(), "Spooled Parquet to disk (gateway unavailable)");
    }
}

async fn drain_spool(
    spool_dir: &Path,
    client: &Client,
    url: &str,
    auth_token: &str,
    stamper: &mut Stamper,
) -> u64 {
    let mut drained = 0u64;
    let mut entries: Vec<_> = std::fs::read_dir(spool_dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "parquet").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        match std::fs::read(&path) {
            Ok(data) => {
                if transmit_parquet(client, url, auth_token, &data, stamper).await {
                    let _ = std::fs::remove_file(&path);
                    drained += 1;
                } else {
                    break; // Gateway down again, stop draining
                }
            }
            Err(e) => {
                error!(error = %e, path = %path.display(), "Failed to read spool file");
            }
        }
    }

    if drained > 0 {
        info!(count = drained, "Drained spool files to gateway");
        counter!("falco_tx_spool_drained_total").increment(drained);
    }
    drained
}

// -- Log Tailer ---------------------------------------------------------------

async fn tail_log(log_path: PathBuf, tx: mpsc::Sender<FalcoEvent>) {
    // Wait for log file to exist
    while !log_path.exists() {
        info!(path = %log_path.display(), "Waiting for Falco log file...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let mut file = std::fs::File::open(&log_path).expect("Failed to open Falco log");
    file.seek(SeekFrom::End(0)).expect("Failed to seek to end");
    let mut reader = BufReader::new(file);
    let mut line_buf = String::new();

    // Set up inotify watcher
    let (notify_tx, mut notify_rx) = mpsc::channel::<()>(64);
    let log_dir = log_path.parent().unwrap().to_path_buf();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                let _ = notify_tx.blocking_send(());
            }
        }
    }).expect("Failed to create file watcher");

    watcher.watch(&log_dir, RecursiveMode::NonRecursive).expect("Failed to watch log directory");

    info!(path = %log_path.display(), "Tailing Falco log");

    loop {
        tokio::select! {
            _ = notify_rx.recv() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }

        loop {
            line_buf.clear();
            match reader.read_line(&mut line_buf) {
                Ok(0) => break, // No more data
                Ok(_) => {
                    let trimmed = line_buf.trim();
                    if trimmed.is_empty() { continue; }

                    match serde_json::from_str::<FalcoEvent>(trimmed) {
                        Ok(event) => {
                            if tx.send(event).await.is_err() {
                                return; // Channel closed
                            }
                            counter!("falco_tx_events_parsed_total").increment(1);
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to parse Falco JSON line");
                            counter!("falco_tx_parse_errors_total").increment(1);
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Log read error");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    break;
                }
            }
        }
    }
}

// -- Main ---------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).with_target(false).init();

    let cfg = Config::from_env();

    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], cfg.metrics_port))
        .install()
        .expect("Failed to install Prometheus exporter");

    std::fs::create_dir_all(&cfg.spool_dir).expect("Failed to create spool directory");

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(false)
        .build()
        .expect("Failed to build HTTP client");

    let mut stamper = Stamper {
        sensor_id: cfg.sensor_id.clone(),
        secret: cfg.integrity_secret.as_bytes().to_vec(),
        sequence: 0,
    };

    // Event channel from tailer → batcher
    let (tx, mut rx) = mpsc::channel::<FalcoEvent>(10_000);

    // Start log tailer in background
    let log_path = cfg.log_path.clone();
    tokio::spawn(async move { tail_log(log_path, tx).await });

    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM");
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT");

    let mut batch: Vec<FalcoEvent> = Vec::with_capacity(cfg.batch_size);
    let mut last_flush = Instant::now();
    let mut current_backoff = Duration::from_secs(1);
    let batch_timeout = Duration::from_secs(cfg.batch_timeout_secs);
    let max_backoff = Duration::from_secs(cfg.max_backoff_secs);
    let mut gateway_online = false;

    info!(
        gateway = %cfg.gateway_url,
        sensor = %cfg.sensor_id,
        batch_size = cfg.batch_size,
        batch_timeout = cfg.batch_timeout_secs,
        "Falco Transmitter Online"
    );

    loop {
        tokio::select! {
            biased;
            _ = sigterm.recv() => { info!("SIGTERM received"); break; }
            _ = sigint.recv()  => { info!("SIGINT received"); break; }
            event = rx.recv() => {
                match event {
                    Some(e) => {
                        batch.push(e);
                        if batch.len() < cfg.batch_size && last_flush.elapsed() < batch_timeout {
                            continue;
                        }
                    }
                    None => break, // Tailer channel closed
                }
            }
            _ = tokio::time::sleep(batch_timeout) => {}
        }

        // Flush if we have data and either batch is full or timeout elapsed
        if batch.is_empty() { continue; }
        if batch.len() < cfg.batch_size && last_flush.elapsed() < batch_timeout { continue; }

        gauge!("falco_tx_batch_size").set(batch.len() as f64);

        match events_to_parquet(&batch, &cfg.sensor_id) {
            Ok(parquet_bytes) => {
                if gateway_online {
                    drain_spool(&cfg.spool_dir, &client, &cfg.gateway_url, &cfg.auth_token, &mut stamper).await;
                }

                if transmit_parquet(&client, &cfg.gateway_url, &cfg.auth_token, &parquet_bytes, &mut stamper).await {
                    info!(events = batch.len(), bytes = parquet_bytes.len(), "Transmitted to gateway");
                    current_backoff = Duration::from_secs(1);
                    gateway_online = true;
                } else {
                    spool_to_disk(&cfg.spool_dir, &parquet_bytes);
                    gateway_online = false;
                    current_backoff = std::cmp::min(current_backoff * 2, max_backoff);
                    warn!(backoff_secs = current_backoff.as_secs(), "Gateway unavailable, spooling");
                }
            }
            Err(e) => {
                error!(error = %e, "Parquet serialization failed, dropping batch");
                counter!("falco_tx_serialization_errors_total").increment(1);
            }
        }

        batch.clear();
        last_flush = Instant::now();
    }

    // Flush remaining batch on shutdown
    if !batch.is_empty() {
        info!(remaining = batch.len(), "Flushing remaining batch on shutdown");
        if let Ok(parquet_bytes) = events_to_parquet(&batch, &cfg.sensor_id) {
            if !transmit_parquet(&client, &cfg.gateway_url, &cfg.auth_token, &parquet_bytes, &mut stamper).await {
                spool_to_disk(&cfg.spool_dir, &parquet_bytes);
            }
        }
    }

    info!("Falco Transmitter shutdown complete.");
}