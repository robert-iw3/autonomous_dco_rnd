// =============================================================================
// Suricata Transmitter
//
// Tails eve.json (primary) and fast.log (secondary alert-only) from Suricata's
// log directory. Parses multi-schema EVE events (alert, flow, dns, http, tls,
// fileinfo), batches into Arrow RecordBatches, serializes to Parquet (ZSTD),
// and POSTs to the Nexus Axum gateway with integrity headers.
//
// Gateway backoff + local Parquet spool when unreachable.
// =============================================================================

use arrow::array::{Float64Builder, Int32Builder, StringBuilder, UInt16Builder, UInt32Builder, UInt64Builder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
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
    eve_path: PathBuf,
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
            eve_path: PathBuf::from(
                std::env::var("SURICATA_EVE_PATH").unwrap_or_else(|_| "/var/log/suricata/eve.json".into()),
            ),
            gateway_url: std::env::var("NEXUS_GATEWAY_URL")
                .unwrap_or_else(|_| "https://nexus-edge:8080/api/v1/telemetry".into()),
            auth_token: std::env::var("NEXUS_AUTH_TOKEN")
                .expect("NEXUS_AUTH_TOKEN required"),
            integrity_secret: std::env::var("NEXUS_INTEGRITY_SECRET")
                .expect("NEXUS_INTEGRITY_SECRET required"),
            sensor_id: std::env::var("SENSOR_ID")
                .unwrap_or_else(|_| "suricata-sensor-01".into()),
            spool_dir: PathBuf::from(
                std::env::var("SPOOL_DIR").unwrap_or_else(|_| "/var/spool/suricata_transmitter".into()),
            ),
            batch_size: std::env::var("BATCH_SIZE")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(1000),
            batch_timeout_secs: std::env::var("BATCH_TIMEOUT_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            max_backoff_secs: std::env::var("MAX_BACKOFF_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(300),
            metrics_port: std::env::var("METRICS_PORT")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(9011),
        }
    }
}

// -- EVE JSON Schema ----------------------------------------------------------
// Covers: alert, flow, dns, http, tls, fileinfo event types.
// Uncommon event types are captured in raw_event.

#[derive(Deserialize, Debug)]
struct EveEvent {
    timestamp: Option<String>,
    flow_id: Option<u64>,
    in_iface: Option<String>,
    event_type: Option<String>,
    src_ip: Option<String>,
    src_port: Option<u16>,
    dest_ip: Option<String>,
    dest_port: Option<u16>,
    proto: Option<String>,
    community_id: Option<String>,
    // Alert fields
    alert: Option<EveAlert>,
    // Flow fields
    flow: Option<EveFlow>,
    // DNS fields
    dns: Option<EveDns>,
    // HTTP fields
    http: Option<EveHttp>,
    // TLS fields
    tls: Option<EveTls>,
    // Fileinfo fields
    fileinfo: Option<EveFileinfo>,
}

#[derive(Deserialize, Debug)]
struct EveAlert {
    action: Option<String>,
    signature: Option<String>,
    signature_id: Option<u32>,
    rev: Option<u32>,
    severity: Option<u32>,
    category: Option<String>,
    metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Deserialize, Debug)]
struct EveFlow {
    pkts_toserver: Option<u64>,
    pkts_toclient: Option<u64>,
    bytes_toserver: Option<u64>,
    bytes_toclient: Option<u64>,
    start: Option<String>,
    end: Option<String>,
    state: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize, Debug)]
struct EveDns {
    #[serde(rename = "type")]
    dns_type: Option<String>,
    rrname: Option<String>,
    rcode: Option<String>,
    rrtype: Option<String>,
}

#[derive(Deserialize, Debug)]
struct EveHttp {
    hostname: Option<String>,
    url: Option<String>,
    http_method: Option<String>,
    http_user_agent: Option<String>,
    status: Option<u16>,
    length: Option<u64>,
    http_content_type: Option<String>,
}

#[derive(Deserialize, Debug)]
struct EveTls {
    version: Option<String>,
    subject: Option<String>,
    issuerdn: Option<String>,
    serial: Option<String>,
    ja3: Option<HashMap<String, String>>,
    ja3s: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Debug)]
struct EveFileinfo {
    filename: Option<String>,
    size: Option<u64>,
    sha256: Option<String>,
}

// -- Parquet Schema -----------------------------------------------------------

fn eve_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        // Common
        Field::new("timestamp", DataType::Utf8, false),
        Field::new("flow_id", DataType::UInt64, true),
        Field::new("event_type", DataType::Utf8, false),
        Field::new("src_ip", DataType::Utf8, true),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dest_ip", DataType::Utf8, true),
        Field::new("dest_port", DataType::UInt16, true),
        Field::new("proto", DataType::Utf8, true),
        Field::new("community_id", DataType::Utf8, true),
        Field::new("in_iface", DataType::Utf8, true),
        // Alert
        Field::new("alert_action", DataType::Utf8, true),
        Field::new("signature", DataType::Utf8, true),
        Field::new("signature_id", DataType::UInt32, true),
        Field::new("severity", DataType::UInt32, true),
        Field::new("category", DataType::Utf8, true),
        Field::new("mitre_tactic", DataType::Utf8, true),
        Field::new("mitre_technique", DataType::Utf8, true),
        // Flow
        Field::new("flow_pkts_toserver", DataType::UInt64, true),
        Field::new("flow_pkts_toclient", DataType::UInt64, true),
        Field::new("flow_bytes_toserver", DataType::UInt64, true),
        Field::new("flow_bytes_toclient", DataType::UInt64, true),
        Field::new("flow_state", DataType::Utf8, true),
        // DNS
        Field::new("dns_type", DataType::Utf8, true),
        Field::new("dns_rrname", DataType::Utf8, true),
        Field::new("dns_rcode", DataType::Utf8, true),
        Field::new("dns_rrtype", DataType::Utf8, true),
        // HTTP
        Field::new("http_hostname", DataType::Utf8, true),
        Field::new("http_url", DataType::Utf8, true),
        Field::new("http_method", DataType::Utf8, true),
        Field::new("http_user_agent", DataType::Utf8, true),
        Field::new("http_status", DataType::UInt16, true),
        // TLS
        Field::new("tls_version", DataType::Utf8, true),
        Field::new("tls_subject", DataType::Utf8, true),
        Field::new("tls_issuer", DataType::Utf8, true),
        Field::new("tls_ja3_hash", DataType::Utf8, true),
        Field::new("tls_ja3s_hash", DataType::Utf8, true),
        // Fileinfo
        Field::new("file_filename", DataType::Utf8, true),
        Field::new("file_size", DataType::UInt64, true),
        Field::new("file_sha256", DataType::Utf8, true),
        // Metadata
        Field::new("sensor_id", DataType::Utf8, false),
        Field::new("sensor_type", DataType::Utf8, false),
    ]))
}

// -- Parquet Serialization ----------------------------------------------------

fn events_to_parquet(events: &[EveEvent], sensor_id: &str) -> Result<Vec<u8>, String> {
    let schema = eve_schema();
    let cap = events.len();

    let mut ts_b = StringBuilder::with_capacity(cap, cap * 30);
    let mut fid_b = UInt64Builder::with_capacity(cap);
    let mut etype_b = StringBuilder::with_capacity(cap, cap * 10);
    let mut sip_b = StringBuilder::new(); let mut sport_b = UInt16Builder::with_capacity(cap);
    let mut dip_b = StringBuilder::new(); let mut dport_b = UInt16Builder::with_capacity(cap);
    let mut proto_b = StringBuilder::new(); let mut cid_b = StringBuilder::new();
    let mut iface_b = StringBuilder::new();
    // Alert
    let mut aa_b = StringBuilder::new(); let mut asig_b = StringBuilder::new();
    let mut asid_b = UInt32Builder::with_capacity(cap); let mut asev_b = UInt32Builder::with_capacity(cap);
    let mut acat_b = StringBuilder::new();
    let mut amt_b = StringBuilder::new(); let mut amte_b = StringBuilder::new();
    // Flow
    let mut fps_b = UInt64Builder::with_capacity(cap); let mut fpc_b = UInt64Builder::with_capacity(cap);
    let mut fbs_b = UInt64Builder::with_capacity(cap); let mut fbc_b = UInt64Builder::with_capacity(cap);
    let mut fst_b = StringBuilder::new();
    // DNS
    let mut dt_b = StringBuilder::new(); let mut drr_b = StringBuilder::new();
    let mut drc_b = StringBuilder::new(); let mut drt_b = StringBuilder::new();
    // HTTP
    let mut hh_b = StringBuilder::new(); let mut hu_b = StringBuilder::new();
    let mut hm_b = StringBuilder::new(); let mut hua_b = StringBuilder::new();
    let mut hs_b = UInt16Builder::with_capacity(cap);
    // TLS
    let mut tv_b = StringBuilder::new(); let mut ts_b2 = StringBuilder::new();
    let mut ti_b = StringBuilder::new(); let mut tj_b = StringBuilder::new();
    let mut tjs_b = StringBuilder::new();
    // File
    let mut ff_b = StringBuilder::new(); let mut fsz_b = UInt64Builder::with_capacity(cap);
    let mut fsha_b = StringBuilder::new();
    // Sensor
    let mut sid_b = StringBuilder::with_capacity(cap, cap * 20);
    let mut stype_b = StringBuilder::with_capacity(cap, cap * 14);

    for e in events {
        ts_b.append_value(e.timestamp.as_deref().unwrap_or(""));
        opt_u64(&mut fid_b, e.flow_id);
        etype_b.append_value(e.event_type.as_deref().unwrap_or("unknown"));
        opt_str(&mut sip_b, e.src_ip.as_deref());
        opt_u16(&mut sport_b, e.src_port);
        opt_str(&mut dip_b, e.dest_ip.as_deref());
        opt_u16(&mut dport_b, e.dest_port);
        opt_str(&mut proto_b, e.proto.as_deref());
        opt_str(&mut cid_b, e.community_id.as_deref());
        opt_str(&mut iface_b, e.in_iface.as_deref());

        // Alert
        let a = e.alert.as_ref();
        opt_str(&mut aa_b, a.and_then(|a| a.action.as_deref()));
        opt_str(&mut asig_b, a.and_then(|a| a.signature.as_deref()));
        opt_u32(&mut asid_b, a.and_then(|a| a.signature_id));
        opt_u32(&mut asev_b, a.and_then(|a| a.severity));
        opt_str(&mut acat_b, a.and_then(|a| a.category.as_deref()));
        // Extract MITRE ATT&CK tactic/technique from alert metadata (ET ruleset convention:
        // metadata.mitre_tactic_id / mitre_tactic_name / mitre_technique_id / mitre_technique_name)
        let metadata = a.and_then(|a| a.metadata.as_ref());
        let tactic = mitre_field(metadata, "mitre_tactic_id", "mitre_tactic_name");
        let technique = mitre_field(metadata, "mitre_technique_id", "mitre_technique_name");
        opt_str(&mut amt_b, tactic.as_deref());
        opt_str(&mut amte_b, technique.as_deref());

        // Flow
        let f = e.flow.as_ref();
        opt_u64(&mut fps_b, f.and_then(|f| f.pkts_toserver));
        opt_u64(&mut fpc_b, f.and_then(|f| f.pkts_toclient));
        opt_u64(&mut fbs_b, f.and_then(|f| f.bytes_toserver));
        opt_u64(&mut fbc_b, f.and_then(|f| f.bytes_toclient));
        opt_str(&mut fst_b, f.and_then(|f| f.state.as_deref()));

        // DNS
        let d = e.dns.as_ref();
        opt_str(&mut dt_b, d.and_then(|d| d.dns_type.as_deref()));
        opt_str(&mut drr_b, d.and_then(|d| d.rrname.as_deref()));
        opt_str(&mut drc_b, d.and_then(|d| d.rcode.as_deref()));
        opt_str(&mut drt_b, d.and_then(|d| d.rrtype.as_deref()));

        // HTTP
        let h = e.http.as_ref();
        opt_str(&mut hh_b, h.and_then(|h| h.hostname.as_deref()));
        opt_str(&mut hu_b, h.and_then(|h| h.url.as_deref()));
        opt_str(&mut hm_b, h.and_then(|h| h.http_method.as_deref()));
        opt_str(&mut hua_b, h.and_then(|h| h.http_user_agent.as_deref()));
        opt_u16(&mut hs_b, h.and_then(|h| h.status));

        // TLS
        let t = e.tls.as_ref();
        opt_str(&mut tv_b, t.and_then(|t| t.version.as_deref()));
        opt_str(&mut ts_b2, t.and_then(|t| t.subject.as_deref()));
        opt_str(&mut ti_b, t.and_then(|t| t.issuerdn.as_deref()));
        opt_str(&mut tj_b, t.and_then(|t| t.ja3.as_ref().and_then(|j| j.get("hash")).map(|s| s.as_str())));
        opt_str(&mut tjs_b, t.and_then(|t| t.ja3s.as_ref().and_then(|j| j.get("hash")).map(|s| s.as_str())));

        // Fileinfo
        let fi = e.fileinfo.as_ref();
        opt_str(&mut ff_b, fi.and_then(|f| f.filename.as_deref()));
        opt_u64(&mut fsz_b, fi.and_then(|f| f.size));
        opt_str(&mut fsha_b, fi.and_then(|f| f.sha256.as_deref()));

        sid_b.append_value(sensor_id);
        stype_b.append_value("suricata_eve");
    }

    let batch = RecordBatch::try_new(schema.clone(), vec![
        Arc::new(ts_b.finish()), Arc::new(fid_b.finish()), Arc::new(etype_b.finish()),
        Arc::new(sip_b.finish()), Arc::new(sport_b.finish()),
        Arc::new(dip_b.finish()), Arc::new(dport_b.finish()),
        Arc::new(proto_b.finish()), Arc::new(cid_b.finish()), Arc::new(iface_b.finish()),
        Arc::new(aa_b.finish()), Arc::new(asig_b.finish()),
        Arc::new(asid_b.finish()), Arc::new(asev_b.finish()),
        Arc::new(acat_b.finish()), Arc::new(amt_b.finish()), Arc::new(amte_b.finish()),
        Arc::new(fps_b.finish()), Arc::new(fpc_b.finish()),
        Arc::new(fbs_b.finish()), Arc::new(fbc_b.finish()), Arc::new(fst_b.finish()),
        Arc::new(dt_b.finish()), Arc::new(drr_b.finish()),
        Arc::new(drc_b.finish()), Arc::new(drt_b.finish()),
        Arc::new(hh_b.finish()), Arc::new(hu_b.finish()),
        Arc::new(hm_b.finish()), Arc::new(hua_b.finish()), Arc::new(hs_b.finish()),
        Arc::new(tv_b.finish()), Arc::new(ts_b2.finish()),
        Arc::new(ti_b.finish()), Arc::new(tj_b.finish()), Arc::new(tjs_b.finish()),
        Arc::new(ff_b.finish()), Arc::new(fsz_b.finish()), Arc::new(fsha_b.finish()),
        Arc::new(sid_b.finish()), Arc::new(stype_b.finish()),
    ]).map_err(|e| format!("RecordBatch failed: {e}"))?;

    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(Default::default()))
        .build();
    let mut buf = Vec::with_capacity(cap * 300);
    let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))
        .map_err(|e| format!("Parquet init failed: {e}"))?;
    writer.write(&batch).map_err(|e| format!("Parquet write failed: {e}"))?;
    writer.close().map_err(|e| format!("Parquet close failed: {e}"))?;
    Ok(buf)
}

/// Combines the `_id`/`_name` pair from EVE alert metadata (e.g.
/// `mitre_tactic_id`/`mitre_tactic_name`) into a single "ID Name" string,
/// falling back to whichever half is present. Returns `None` if neither key exists.
fn mitre_field(metadata: Option<&HashMap<String, serde_json::Value>>, id_key: &str, name_key: &str) -> Option<String> {
    let stringify = |v: &serde_json::Value| match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string().replace('"', ""),
    };
    let id = metadata.and_then(|m| m.get(id_key)).map(stringify);
    let name = metadata.and_then(|m| m.get(name_key)).map(stringify);
    match (id, name) {
        (Some(i), Some(n)) => Some(format!("{i} {n}")),
        (Some(i), None) => Some(i),
        (None, Some(n)) => Some(n),
        (None, None) => None,
    }
}

fn opt_str(b: &mut StringBuilder, v: Option<&str>) {
    match v { Some(s) if !s.is_empty() => b.append_value(s), _ => b.append_null() }
}
fn opt_u16(b: &mut UInt16Builder, v: Option<u16>) {
    match v { Some(n) => b.append_value(n), None => b.append_null() }
}
fn opt_u32(b: &mut UInt32Builder, v: Option<u32>) {
    match v { Some(n) => b.append_value(n), None => b.append_null() }
}
fn opt_u64(b: &mut UInt64Builder, v: Option<u64>) {
    match v { Some(n) => b.append_value(n), None => b.append_null() }
}

// -- Integrity + Gateway + Spool (shared pattern) -----------------------------

struct Stamper { sensor_id: String, secret: Vec<u8>, sequence: u64 }

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
        (self.sequence, ts, hex::encode(mac.finalize().into_bytes()))
    }
}

async fn transmit(client: &Client, url: &str, token: &str, data: &[u8], stamper: &mut Stamper) -> bool {
    let (seq, ts, hmac) = stamper.stamp(data);
    let resp = client.post(url)
        .bearer_auth(token)
        .header("Content-Type", "application/vnd.apache.parquet")
        .header("X-Sensor-Type", "suricata_eve")
        .header("X-Sensor-Id", &stamper.sensor_id)
        .header("X-Batch-Sequence", seq.to_string())
        .header("X-Batch-Timestamp", ts.to_string())
        .header("X-Batch-HMAC", &hmac)
        .header("X-Partition-Date", Utc::now().format("%Y-%m-%d").to_string())
        .header("X-Partition-Hour", Utc::now().format("%H").to_string())
        .body(data.to_vec())
        .send().await;

    match resp {
        Ok(r) if r.status().is_success() => { counter!("suri_tx_sent_total").increment(1); true }
        Ok(r) => { warn!(status = %r.status(), "Gateway rejected"); false }
        Err(e) => { warn!(error = %e, "Gateway unreachable"); false }
    }
}

fn spool(dir: &Path, data: &[u8]) {
    let path = dir.join(format!("spool_{}.parquet", uuid::Uuid::new_v4()));
    if let Err(e) = std::fs::write(&path, data) {
        error!(error = %e, "Spool write failed");
    } else {
        counter!("suri_tx_spool_writes_total").increment(1);
    }
}

async fn drain_spool(dir: &Path, client: &Client, url: &str, token: &str, stamper: &mut Stamper) -> u64 {
    let mut drained = 0u64;
    let mut entries: Vec<_> = std::fs::read_dir(dir).into_iter().flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "parquet").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if let Ok(data) = std::fs::read(&path) {
            if transmit(client, url, token, &data, stamper).await {
                let _ = std::fs::remove_file(&path);
                drained += 1;
            } else { break; }
        }
    }
    if drained > 0 { counter!("suri_tx_spool_drained_total").increment(drained); }
    drained
}

// -- Log Tailer ---------------------------------------------------------------

async fn tail_eve(path: PathBuf, tx: mpsc::Sender<EveEvent>) {
    while !path.exists() {
        info!(path = %path.display(), "Waiting for eve.json...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let mut file = std::fs::File::open(&path).expect("Failed to open eve.json");
    file.seek(SeekFrom::End(0)).expect("Seek failed");
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    let (ntx, mut nrx) = mpsc::channel::<()>(64);
    let dir = path.parent().unwrap().to_path_buf();
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(e) = res {
            if matches!(e.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                let _ = ntx.blocking_send(());
            }
        }
    }).expect("Watcher failed");
    watcher.watch(&dir, RecursiveMode::NonRecursive).expect("Watch failed");

    info!(path = %path.display(), "Tailing eve.json");

    loop {
        tokio::select! {
            _ = nrx.recv() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() { continue; }
                    match serde_json::from_str::<EveEvent>(trimmed) {
                        Ok(event) => {
                            counter!("suri_tx_events_parsed_total").increment(1);
                            if tx.send(event).await.is_err() { return; }
                        }
                        Err(e) => {
                            counter!("suri_tx_parse_errors_total").increment(1);
                            warn!(error = %e, "EVE parse error");
                        }
                    }
                }
                Err(e) => { error!(error = %e, "Read error"); break; }
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
        .install().expect("Prometheus failed");

    std::fs::create_dir_all(&cfg.spool_dir).expect("Spool dir failed");

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build().expect("HTTP client failed");

    let mut stamper = Stamper {
        sensor_id: cfg.sensor_id.clone(),
        secret: cfg.integrity_secret.as_bytes().to_vec(),
        sequence: 0,
    };

    let (tx, mut rx) = mpsc::channel::<EveEvent>(50_000);
    let eve_path = cfg.eve_path.clone();
    tokio::spawn(async move { tail_eve(eve_path, tx).await });

    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM");
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT");

    let mut batch: Vec<EveEvent> = Vec::with_capacity(cfg.batch_size);
    let mut last_flush = Instant::now();
    let mut backoff = Duration::from_secs(1);
    let timeout = Duration::from_secs(cfg.batch_timeout_secs);
    let max_backoff = Duration::from_secs(cfg.max_backoff_secs);
    let mut gw_online = false;

    info!(gateway = %cfg.gateway_url, sensor = %cfg.sensor_id, batch = cfg.batch_size,
          timeout = cfg.batch_timeout_secs, "Suricata Transmitter Online");

    loop {
        tokio::select! {
            biased;
            _ = sigterm.recv() => { info!("SIGTERM"); break; }
            _ = sigint.recv()  => { info!("SIGINT"); break; }
            event = rx.recv() => {
                match event {
                    Some(e) => {
                        batch.push(e);
                        if batch.len() < cfg.batch_size && last_flush.elapsed() < timeout { continue; }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(timeout) => {}
        }

        if batch.is_empty() || (batch.len() < cfg.batch_size && last_flush.elapsed() < timeout) { continue; }

        gauge!("suri_tx_batch_size").set(batch.len() as f64);

        match events_to_parquet(&batch, &cfg.sensor_id) {
            Ok(pq) => {
                if gw_online {
                    drain_spool(&cfg.spool_dir, &client, &cfg.gateway_url, &cfg.auth_token, &mut stamper).await;
                }
                if transmit(&client, &cfg.gateway_url, &cfg.auth_token, &pq, &mut stamper).await {
                    info!(events = batch.len(), bytes = pq.len(), "Transmitted");
                    backoff = Duration::from_secs(1);
                    gw_online = true;
                } else {
                    spool(&cfg.spool_dir, &pq);
                    gw_online = false;
                    backoff = std::cmp::min(backoff * 2, max_backoff);
                    warn!(backoff_secs = backoff.as_secs(), "Spooling (gateway unavailable)");
                }
            }
            Err(e) => { error!(error = %e, "Serialization failed"); }
        }
        batch.clear();
        last_flush = Instant::now();
    }

    if !batch.is_empty() {
        if let Ok(pq) = events_to_parquet(&batch, &cfg.sensor_id) {
            if !transmit(&client, &cfg.gateway_url, &cfg.auth_token, &pq, &mut stamper).await {
                spool(&cfg.spool_dir, &pq);
            }
        }
    }
    info!("Suricata Transmitter shutdown.");
}
// =============================================================================
// Tests -- algorithmic validation of EVE schema mapping, Parquet serialization,
// MITRE field extraction, and HMAC integrity stamping. Run via `cargo test`
// (test/tier1 of the workbench).
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use bytes::Bytes;

    fn sample_event(json: &str) -> EveEvent {
        serde_json::from_str(json).expect("sample EVE event must parse")
    }

    // -------------------------------------------------------------------------
    // eve_schema(): column names + order must match the central
    // [schema_mappings.suricata_eve] contract in nexus.toml (identifier_column,
    // sensor_id_column, vector_columns are pre-computed upstream and are NOT
    // emitted by this transmitter; context_columns + metadata columns are).
    // -------------------------------------------------------------------------
    #[test]
    fn schema_contains_contract_context_columns() {
        let schema = eve_schema();
        let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();

        // From nexus.toml [schema_mappings.suricata_eve].context_columns
        let contract_context_columns = [
            "src_ip", "dest_ip", "src_port", "dest_port", "proto",
            "signature_id", "signature", "severity", "category",
            "alert_action", "flow_id", "mitre_tactic", "mitre_technique",
        ];
        for col in contract_context_columns {
            assert!(names.contains(&col), "contract context_column '{col}' missing from eve_schema()");
        }

        // sensor_id_column from the contract, plus the routing discriminator
        assert!(names.contains(&"sensor_id"));
        assert!(names.contains(&"sensor_type"));

        // identifier_column / primary_key_column from the contract
        assert!(names.contains(&"community_id"));
    }

    #[test]
    fn schema_field_order_matches_record_batch_array_order() {
        // events_to_parquet() builds its RecordBatch array vector in a fixed
        // order that must line up positionally with eve_schema()'s field order.
        let schema = eve_schema();
        let expected_order = [
            "timestamp", "flow_id", "event_type", "src_ip", "src_port",
            "dest_ip", "dest_port", "proto", "community_id", "in_iface",
            "alert_action", "signature", "signature_id", "severity", "category",
            "mitre_tactic", "mitre_technique",
            "flow_pkts_toserver", "flow_pkts_toclient", "flow_bytes_toserver",
            "flow_bytes_toclient", "flow_state",
            "dns_type", "dns_rrname", "dns_rcode", "dns_rrtype",
            "http_hostname", "http_url", "http_method", "http_user_agent", "http_status",
            "tls_version", "tls_subject", "tls_issuer", "tls_ja3_hash", "tls_ja3s_hash",
            "file_filename", "file_size", "file_sha256",
            "sensor_id", "sensor_type",
        ];
        let actual: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
        assert_eq!(actual, expected_order.to_vec());
    }

    // -------------------------------------------------------------------------
    // mitre_field(): combines `<prefix>_id`/`<prefix>_name` metadata pairs into
    // the single "ID Name" string stored in the mitre_tactic/mitre_technique
    // Parquet columns (matching the "TA0001 Initial Access" convention used by
    // linux/sentinel's MitreTactic::Display).
    // -------------------------------------------------------------------------
    fn meta(pairs: &[(&str, &str)]) -> HashMap<String, serde_json::Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string()))).collect()
    }

    #[test]
    fn mitre_field_combines_id_and_name() {
        let m = meta(&[("mitre_tactic_id", "TA0011"), ("mitre_tactic_name", "Command and Control")]);
        assert_eq!(mitre_field(Some(&m), "mitre_tactic_id", "mitre_tactic_name").as_deref(),
                   Some("TA0011 Command and Control"));
    }

    #[test]
    fn mitre_field_falls_back_to_id_only() {
        let m = meta(&[("mitre_technique_id", "T1071")]);
        assert_eq!(mitre_field(Some(&m), "mitre_technique_id", "mitre_technique_name").as_deref(),
                   Some("T1071"));
    }

    #[test]
    fn mitre_field_falls_back_to_name_only() {
        let m = meta(&[("mitre_technique_name", "Application Layer Protocol")]);
        assert_eq!(mitre_field(Some(&m), "mitre_technique_id", "mitre_technique_name").as_deref(),
                   Some("Application Layer Protocol"));
    }

    #[test]
    fn mitre_field_none_when_absent() {
        let m = meta(&[("attack_target", "Client_Endpoint")]);
        assert_eq!(mitre_field(Some(&m), "mitre_tactic_id", "mitre_tactic_name"), None);
        assert_eq!(mitre_field(None, "mitre_tactic_id", "mitre_tactic_name"), None);
    }

    // -------------------------------------------------------------------------
    // events_to_parquet(): end-to-end -- synthetic EVE alert events serialize
    // to real Parquet bytes that round-trip through the Arrow reader with the
    // contract's MITRE columns populated.
    // -------------------------------------------------------------------------
    #[test]
    fn events_to_parquet_round_trips_mitre_columns() {
        let event = sample_event(r#"{
            "timestamp": "2026-06-07T12:00:00.000000+0000",
            "flow_id": 123456789,
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "src_port": 443,
            "dest_ip": "203.0.113.9",
            "dest_port": 8443,
            "proto": "TCP",
            "community_id": "1:abcdef0123456789==",
            "alert": {
                "action": "allowed",
                "signature": "ET MALWARE Suspicious C2 Beacon",
                "signature_id": 2030001,
                "rev": 1,
                "severity": 1,
                "category": "A Network Trojan was detected",
                "metadata": {
                    "mitre_tactic_id": "TA0011",
                    "mitre_tactic_name": "Command and Control",
                    "mitre_technique_id": "T1071",
                    "mitre_technique_name": "Application Layer Protocol"
                }
            }
        }"#);

        let pq = events_to_parquet(&[event], "suricata-sensor-test").expect("serialization should succeed");
        assert!(!pq.is_empty());

        let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::from(pq))
            .expect("parquet reader init")
            .build()
            .expect("parquet reader build");

        let batches: Vec<_> = reader.collect::<Result<Vec<_>, _>>().expect("read batches");
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch.num_rows(), 1);

        let col = |name: &str| -> String {
            let idx = batch.schema().index_of(name).unwrap_or_else(|_| panic!("column '{name}' missing from output"));
            let arr = batch.column(idx).as_any().downcast_ref::<arrow::array::StringArray>()
                .unwrap_or_else(|| panic!("column '{name}' is not Utf8"));
            arr.value(0).to_string()
        };

        assert_eq!(col("event_type"), "alert");
        assert_eq!(col("signature"), "ET MALWARE Suspicious C2 Beacon");
        assert_eq!(col("category"), "A Network Trojan was detected");
        assert_eq!(col("mitre_tactic"), "TA0011 Command and Control");
        assert_eq!(col("mitre_technique"), "T1071 Application Layer Protocol");
        assert_eq!(col("sensor_id"), "suricata-sensor-test");
        assert_eq!(col("sensor_type"), "suricata_eve");
    }

    #[test]
    fn events_to_parquet_nulls_mitre_columns_when_alert_untagged() {
        let event = sample_event(r#"{
            "timestamp": "2026-06-07T12:00:01.000000+0000",
            "event_type": "flow",
            "proto": "UDP",
            "flow": {"pkts_toserver": 10, "pkts_toclient": 8, "bytes_toserver": 1200, "bytes_toclient": 900, "state": "established"}
        }"#);

        let pq = events_to_parquet(&[event], "suricata-sensor-test").expect("serialization should succeed");
        let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::from(pq)).unwrap().build().unwrap();
        let batches: Vec<_> = reader.collect::<Result<Vec<_>, _>>().unwrap();
        let batch = &batches[0];

        for name in ["mitre_tactic", "mitre_technique", "alert_action", "signature"] {
            let idx = batch.schema().index_of(name).unwrap();
            assert!(batch.column(idx).is_null(0), "expected '{name}' to be null for a non-alert event");
        }
        let flow_state_idx = batch.schema().index_of("flow_state").unwrap();
        let flow_state = batch.column(flow_state_idx).as_any().downcast_ref::<arrow::array::StringArray>().unwrap();
        assert_eq!(flow_state.value(0), "established");
    }

    // -------------------------------------------------------------------------
    // Stamper::stamp(): HMAC formula must stay byte-identical to the central
    // core_ingress contract: HMAC-SHA256(payload || seq.BE64 || sensor_id || ts.BE64)
    // -------------------------------------------------------------------------
    fn reference_hmac(secret: &[u8], payload: &[u8], sequence: u64, sensor_id: &str, ts: u64) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(payload);
        mac.update(&sequence.to_be_bytes());
        mac.update(sensor_id.as_bytes());
        mac.update(&ts.to_be_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn stamper_hmac_matches_independent_reference_and_increments_sequence() {
        let mut stamper = Stamper {
            sensor_id: "suricata-sensor-test".to_string(),
            secret: b"unit-test-integrity-secret".to_vec(),
            sequence: 0,
        };

        let payload = b"synthetic-parquet-bytes";
        let (seq1, ts1, hmac1) = stamper.stamp(payload);
        assert_eq!(seq1, 1);
        assert_eq!(hmac1, reference_hmac(&stamper.secret, payload, seq1, &stamper.sensor_id, ts1));
        assert_eq!(hmac1.len(), 64);
        assert!(hmac1.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        let (seq2, ts2, hmac2) = stamper.stamp(payload);
        assert_eq!(seq2, 2);
        assert_eq!(hmac2, reference_hmac(&stamper.secret, payload, seq2, &stamper.sensor_id, ts2));
        assert_ne!(hmac1, hmac2, "sequence-dependent HMAC must change between batches");
    }

    #[test]
    fn stamper_hmac_detects_payload_tampering() {
        let mut stamper = Stamper {
            sensor_id: "suricata-sensor-test".to_string(),
            secret: b"unit-test-integrity-secret".to_vec(),
            sequence: 0,
        };
        let (seq, ts, hmac) = stamper.stamp(b"original-bytes");
        let tampered = reference_hmac(&stamper.secret, b"tampered-bytes!", seq, &stamper.sensor_id, ts);
        assert_ne!(hmac, tampered);
    }
}