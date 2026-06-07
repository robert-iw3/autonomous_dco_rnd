/*=============================================================================================
 * SYSTEM:          C2 Sensor - Transmission Layer
 * COMPONENT:       lib.rs (Durable SQLite WAL to Parquet Forwarder)
 * DESCRIPTION:
 * Subscribes to the ML engine's alert channel, writes events securely to a local
 * SQLite WAL (DeepLedger), and asynchronously micro-batches rows into ZSTD-compressed
 * Parquet buffers for the Axum Zero-Trust Gateway.
 * @RW
 *============================================================================================*/

pub mod parquet;

use chrono;
use ini::Ini;
use reqwest::{Client, header};
use serde_json::Value;
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite, Row};
use std::fs;
use std::path::Path;
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::time::sleep;

use nexus_integrity::stamper::LineageStamper;
use nexus_integrity::{HDR_BATCH_HMAC, HDR_BATCH_SEQUENCE, HDR_BATCH_TIMESTAMP, HDR_SENSOR_ID};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Clone)]
pub struct TransmissionConfig {
    pub endpoint: String,
    pub auth_token: String,
    pub sensor_type: String,
    pub batch_size: u32,
    pub db_path: String,
    pub trust_self_signed: bool,
    pub integrity_secret: String,
}

impl TransmissionConfig {
    pub fn load(path: &str) -> Self {
        let conf = Ini::load_from_file(path).unwrap_or_default();
        let section = conf.section(Some("TRANSMISSION")).unwrap_or_default();

        Self {
            endpoint: section.get("MiddlewareEndpoint").unwrap_or("https://127.0.0.1:8443/api/v1/telemetry").to_string(),
            auth_token: section.get("AuthToken").unwrap_or("ChangeMe").to_string(),
            sensor_type: section.get("SensorType").unwrap_or("c2sensor").to_string(),
            batch_size: section.get("MaxBatchSize").unwrap_or("500").parse().unwrap_or(500),
            db_path: section.get("QueueDbPath").unwrap_or(r"C:\ProgramData\C2Sensor\Data\TransmissionQueue.db").to_string(),
            trust_self_signed: section.get("TrustSelfSignedCert").unwrap_or("False").eq_ignore_ascii_case("true"),
            integrity_secret: section.get("IntegritySecret").unwrap_or("Nexus-Integrity-SharedKey-Rotate-Me").to_string(),
        }
    }
}

pub struct C2TelemetryRow {
    pub id: i64,
    pub event_id: String,
    pub timestamp: i64,    // Unix epoch milliseconds -- DuckDB/spool compatible (was ISO-8601 String, fixed)
    pub host: String,
    pub user: String,
    pub host_ip: String,
    pub process: String,
    pub destination: String,
    pub domain: String,
    pub alert_reason: String,
    pub confidence: i64,
    pub event_type: String,
    pub severity: String,
    pub outbound_ratio: f64,      // [0] outbound/(inbound+outbound) bytes
    pub packet_size_mean: f64,    // [1] mean packet size in bytes
    pub packet_size_std: f64,     // [2] std dev packet size
    pub interval: f64,            // [3] mean inter-packet interval (ms)
    pub cv: f64,                  // [4] coefficient of variation of interval
    pub entropy: f64,             // [5] payload entropy (0-8 bits)
    pub cmd_entropy: f64,         // [6] command/query string entropy (0-8 bits)
    pub score: f64,               // [7] ML beacon confidence score 0-1
    pub payload_raw: String,
}

pub async fn start_transmission_worker<F>(config_path: String, mut rx: Receiver<Arc<Value>>, mut log_cb: F)
where
    F: FnMut(String) + Send + Sync + 'static,
{
    let config = TransmissionConfig::load(&config_path);

    if let Some(parent) = Path::new(&config.db_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let db_url = format!("sqlite://{}?mode=rwc", config.db_path);
    let pool = match SqlitePoolOptions::new()
        .max_connections(3)
        .connect(&db_url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            log_cb(format!("[TRANSMISSION FATAL] Failed to mount C2 SQLite WAL: {}", e));
            return;
        }
    };

    let _ = sqlx::query(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA auto_vacuum = INCREMENTAL;
         CREATE TABLE IF NOT EXISTS c2_ledger_queue (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             event_id TEXT,
             timestamp TEXT,
             host TEXT,
             user TEXT,
             host_ip TEXT,
             process TEXT,
             destination TEXT,
             domain TEXT,
             alert_reason TEXT,
             confidence INTEGER,
             event_type TEXT,
             severity TEXT,
             score REAL,
             payload_raw TEXT,
             outbound_ratio REAL DEFAULT 0.75,
             packet_size_mean REAL DEFAULT 0.0,
             packet_size_std REAL DEFAULT 0.0,
             interval_mean REAL DEFAULT 0.0,
             cv REAL DEFAULT 0.0,
             entropy REAL DEFAULT 0.0,
             cmd_entropy REAL DEFAULT 0.0
         );
         -- Migrate existing tables: ADD COLUMN is idempotent via separate queries below
         ;"
    ).execute(&pool).await;

    // Schema migration: add flow-stat columns to existing c2_ledger_queue tables.
    for col in &[
        "ALTER TABLE c2_ledger_queue ADD COLUMN outbound_ratio REAL DEFAULT 0.75",
        "ALTER TABLE c2_ledger_queue ADD COLUMN packet_size_mean REAL DEFAULT 0.0",
        "ALTER TABLE c2_ledger_queue ADD COLUMN packet_size_std REAL DEFAULT 0.0",
        "ALTER TABLE c2_ledger_queue ADD COLUMN interval_mean REAL DEFAULT 0.0",
        "ALTER TABLE c2_ledger_queue ADD COLUMN cv REAL DEFAULT 0.0",
        "ALTER TABLE c2_ledger_queue ADD COLUMN entropy REAL DEFAULT 0.0",
        "ALTER TABLE c2_ledger_queue ADD COLUMN cmd_entropy REAL DEFAULT 0.0",
    ] {
        // Ignore error -- "duplicate column name" means column already exists (idempotent)
        let _ = sqlx::query(col).execute(&pool).await;
    }

    log_cb("[TRANSMISSION] Typed C2 SQLite WAL Durable Queue Mounted.".to_string());

    // -- Integrity: sequence counter + stamper --------------------------------
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS integrity_sequence (
            sensor_id TEXT PRIMARY KEY,
            last_sequence INTEGER NOT NULL DEFAULT 0
        )"
    ).execute(&pool).await;

    let sensor_id = format!("{}-c2sensor",
        std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string()));

    let initial_seq: u64 = sqlx::query("SELECT last_sequence FROM integrity_sequence WHERE sensor_id = ?")
        .bind(&sensor_id)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten()
        .map(|row| row.get::<i64, _>("last_sequence") as u64)
        .unwrap_or(0);

    let _ = sqlx::query("INSERT OR IGNORE INTO integrity_sequence (sensor_id, last_sequence) VALUES (?, ?)")
        .bind(&sensor_id)
        .bind(initial_seq as i64)
        .execute(&pool)
        .await;

    let mut stamper = LineageStamper::new(
        sensor_id.clone(), config.integrity_secret.as_bytes(), initial_seq
    );

    log_cb(format!("[INTEGRITY] Stamper online: sensor_id={}, seq={}", sensor_id, initial_seq));
    // -------------------------------------------------------------------------

    let pool_producer = pool.clone();

    // -------------------------------------------------------------------------
    // LOOP 1: JSON Destructuring & Local Persistence (Producer)
    // -------------------------------------------------------------------------
    tokio::spawn(async move {
        while let Some(alert) = rx.recv().await {
            let payload_str = alert.to_string();

            let event_id = alert["event_id"].as_str().unwrap_or("");
            let timestamp = alert["timestamp"].as_str().unwrap_or("");
            let host = alert["host"].as_str().unwrap_or("");
            let user = alert["user"].as_str().unwrap_or("");
            let host_ip = alert["host_ip"].as_str().unwrap_or("");
            let process = alert["process"].as_str().unwrap_or("");
            let destination = alert["destination"].as_str().unwrap_or("");
            let domain = alert["domain"].as_str().unwrap_or("");
            let alert_reason = alert["alert_reason"].as_str().unwrap_or("");
            let confidence = alert["confidence"].as_i64().unwrap_or(0);
            let event_type = alert["event_type"].as_str().unwrap_or("");
            let severity = alert["severity"].as_str().unwrap_or("INFO");
            let score = alert["score"].as_f64().unwrap_or(0.0);
            // c2_math 8D vector fields -- passed from ml_engine dispatch_alert_to_gateway
            let outbound_ratio   = alert["outbound_ratio"].as_f64().unwrap_or(0.75);
            let packet_size_mean = alert["packet_size_mean"].as_f64().unwrap_or(0.0);
            let packet_size_std  = alert["packet_size_std"].as_f64().unwrap_or(0.0);
            let interval_mean    = alert["interval_mean"].as_f64().unwrap_or(0.0);
            let cv               = alert["cv"].as_f64().unwrap_or(0.0);
            let entropy          = alert["entropy"].as_f64().unwrap_or(0.0);
            let cmd_entropy      = alert["cmd_entropy"].as_f64().unwrap_or(0.0);

            let _ = sqlx::query(
                "INSERT INTO c2_ledger_queue (
                    event_id, timestamp, host, user, host_ip, process, destination, domain,
                    alert_reason, confidence, event_type, severity, score, payload_raw,
                    outbound_ratio, packet_size_mean, packet_size_std, interval_mean,
                    cv, entropy, cmd_entropy
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                          ?15, ?16, ?17, ?18, ?19, ?20, ?21)"
            )
            .bind(event_id).bind(timestamp).bind(host).bind(user).bind(host_ip)
            .bind(process).bind(destination).bind(domain).bind(alert_reason)
            .bind(confidence).bind(event_type).bind(severity).bind(score).bind(payload_str)
            .bind(outbound_ratio).bind(packet_size_mean).bind(packet_size_std)
            .bind(interval_mean).bind(cv).bind(entropy).bind(cmd_entropy)
            .execute(&pool_producer)
            .await;
        }
    });

    // -------------------------------------------------------------------------
    // LOOP 2: Parquet Micro-Batching & Gateway Forwarder (Consumer)
    // -------------------------------------------------------------------------
    let mut headers = header::HeaderMap::new();
    headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&format!("Bearer {}", config.auth_token)).unwrap());
    headers.insert("X-Sensor-Type", header::HeaderValue::from_str(&config.sensor_type).unwrap());
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/vnd.apache.parquet"));

    let mut client_builder = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(15));

    if config.trust_self_signed {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    let client = client_builder.build().expect("Failed to build Transmission HTTP Client");
    let mut backoff = 1000;
    let mut flush_counter: u64 = 0

    loop {
        let rows = match sqlx::query("SELECT * FROM c2_ledger_queue ORDER BY id ASC LIMIT ?")
            .bind(config.batch_size)
            .fetch_all(&pool)
            .await
        {
            Ok(r) => r,
            Err(_) => {
                sleep(Duration::from_millis(5000)).await;
                continue;
            }
        };

        if rows.is_empty() {
            backoff = 1000;
            sleep(Duration::from_millis(1000)).await;
            continue;
        }

        let mut batch = Vec::with_capacity(rows.len());
        let mut ids = Vec::with_capacity(rows.len());

        for row in rows {
            let id: i64 = row.get("id");
            ids.push(id);

            // Timestamp stored as ISO-8601 TEXT in SQLite; C2TelemetryRow needs epoch_ms i64
            let ts_raw: String = row.try_get("timestamp").unwrap_or_default();
            let ts_epoch_ms: i64 = chrono::DateTime::parse_from_rfc3339(&ts_raw)
                .map(|dt| dt.timestamp_millis())
                .unwrap_or_else(|_| chrono::Utc::now().timestamp_millis());

            batch.push(C2TelemetryRow {
                id,
                event_id:       row.get("event_id"),
                timestamp:      ts_epoch_ms,
                host:           row.get("host"),
                user:           row.get("user"),
                host_ip:        row.get("host_ip"),
                process:        row.get("process"),
                destination:    row.get("destination"),
                domain:         row.get("domain"),
                alert_reason:   row.get("alert_reason"),
                confidence:     row.get("confidence"),
                event_type:     row.get("event_type"),
                severity:       row.get("severity"),
                // c2_math 8D vector fields -- read from SQLite, written by producer loop
                outbound_ratio:   row.try_get("outbound_ratio").unwrap_or(0.75),
                packet_size_mean: row.try_get("packet_size_mean").unwrap_or(0.0),
                packet_size_std:  row.try_get("packet_size_std").unwrap_or(0.0),
                interval:         row.try_get("interval_mean").unwrap_or(0.0),
                cv:               row.try_get("cv").unwrap_or(0.0),
                entropy:          row.try_get("entropy").unwrap_or(0.0),
                cmd_entropy:      row.try_get("cmd_entropy").unwrap_or(0.0),
                score:            row.get("score"),
                payload_raw:      row.get("payload_raw"),
            });
        }

        match parquet::serialize_to_parquet(&batch) {
            Ok(parquet_bytes) => {
                // -- Integrity: stamp + persist -----------------------
                let stamp = stamper.stamp(&parquet_bytes);
                let _ = sqlx::query(
                    "UPDATE integrity_sequence SET last_sequence = ? WHERE sensor_id = ?"
                )
                .bind(stamp.sequence as i64)
                .bind(&sensor_id)
                .execute(&pool)
                .await;

                let res = client.post(&config.endpoint)
                    .header(HDR_BATCH_SEQUENCE, stamp.sequence.to_string())
                    .header(HDR_BATCH_TIMESTAMP, stamp.timestamp.to_string())
                    .header(HDR_SENSOR_ID, &stamp.sensor_id)
                    .header(HDR_BATCH_HMAC, &stamp.hmac_hex)
                    .body(parquet_bytes)
                    .send()
                    .await;

                match res {
                    Ok(response) if response.status().is_success() => {
                        let id_list = ids.iter().map(|id| id.to_string()).collect::<Vec<String>>().join(",");
                        let _ = sqlx::query(&format!("DELETE FROM c2_ledger_queue WHERE id IN ({})", id_list)).execute(&pool).await;
                        log_cb(format!("[TRANSMISSION] Flushed {} C2/UEBA events via Parquet (seq={}).", ids.len(), stamp.sequence));
                        backoff = 1000;
                    }
                    Ok(response) if response.status() == reqwest::StatusCode::FORBIDDEN => {
                        log_cb("[INTEGRITY] Gateway returned 403 FORBIDDEN. Sensor may be banned. Halting.".to_string());
                        return;
                    }
                    Ok(response) => {
                        log_cb(format!("[TRANSMISSION WARN] Gateway rejected batch (HTTP {}). Retrying...", response.status()));
                        sleep(Duration::from_millis(backoff)).await;
                        if backoff < 60000 { backoff *= 2; }
                    }
                    Err(e) => {
                        log_cb(format!("[TRANSMISSION NETWORK ERROR] Axum unreachable: {}. Data safely queued in SQLite.", e));
                        sleep(Duration::from_millis(backoff)).await;
                        if backoff < 60000 { backoff *= 2; }
                    }
                }
            }
            Err(e) => {
                log_cb(format!("[TRANSMISSION FATAL] Parquet generation error: {}. Dropping corrupted batch.", e));
                let id_list = ids.iter().map(|id| id.to_string()).collect::<Vec<String>>().join(",");
                let _ = sqlx::query(&format!("DELETE FROM c2_ledger_queue WHERE id IN ({})", id_list)).execute(&pool).await;
            }
        }

        // -- Hourly WAL Maintenance (prevents unbounded disk growth) ---------
        flush_counter += 1;
        if flush_counter >= 3600 {
            let _ = sqlx::query("PRAGMA wal_checkpoint(PASSIVE)").execute(&pool).await;

            // Daily incremental vacuum in background thread (non-blocking)
            if flush_counter >= 86400 {
                let db_path_clone = config.db_path.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(conn) = rusqlite::Connection::open(&db_path_clone) {
                        let _ = conn.execute_batch("PRAGMA busy_timeout=30000;");
                        let mut freed = 1;
                        while freed > 0 {
                            match conn.query_row("PRAGMA incremental_vacuum(100);", [], |r| r.get::<_, i32>(0)) {
                                Ok(p) => freed = p,
                                Err(_) => break,
                            }
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }
                });
                flush_counter = 0;
            }
        }
    }
}