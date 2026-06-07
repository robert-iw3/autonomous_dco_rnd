// =================================================================================
// File:        parquet_transmitter.rs
// Component:   Linux Sentinel -- Telemetry Forwarder
// Description: Bridges the local detection engine to upstream SIEM infrastructure.
// Role:        Buffers alerts into a local SQLite WAL (Write-Ahead Log) database
//              to ensure zero data loss during network outages, and reliably
//              dispatches batches to a NATS JetStream or HTTP ingress gateway.
// Author:      Robert Weber
// ===================================================================================

use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite, Row};
use reqwest::{Client, header};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
//use tokio::sync::mpsc::Receiver;
use tracing::{error, info, debug, warn};
use crate::siem::models::SecurityAlert;
use crate::config::MasterConfig;

// Data Plane Serialization
use arrow::array::{StringBuilder, UInt32Builder, UInt64Builder, Float64Builder, UInt16Builder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

// Integrity Layer
#[cfg(feature = "integrity")]
use nexus_integrity::stamper::LineageStamper;
#[cfg(feature = "integrity")]
use nexus_integrity::{HDR_BATCH_HMAC, HDR_BATCH_SEQUENCE, HDR_BATCH_TIMESTAMP, HDR_SENSOR_ID};

pub struct TransmissionLayer {
    db_pool: Pool<Sqlite>,
    client: Client,
    config: Arc<RwLock<MasterConfig>>,
    #[cfg(feature = "integrity")]
    stamper: Arc<tokio::sync::Mutex<LineageStamper>>,
    #[cfg(feature = "integrity")]
    sensor_id: String,
}

impl TransmissionLayer {
    pub async fn new(db_path: &str, config: Arc<RwLock<MasterConfig>>) -> anyhow::Result<Self> {
        let db_pool = SqlitePoolOptions::new()
            .max_connections(5)
            .min_connections(1)
            .idle_timeout(Duration::from_secs(60))
            .after_connect(|conn, _meta| Box::pin(async move {
                use sqlx::Executor;
                conn.execute("PRAGMA journal_mode=WAL;").await?;
                conn.execute("PRAGMA auto_vacuum=INCREMENTAL;").await?;
                conn.execute("PRAGMA synchronous=NORMAL;").await?;
                conn.execute("PRAGMA busy_timeout=5000;").await?;
                conn.execute("PRAGMA temp_store=MEMORY;").await?;
                conn.execute("PRAGMA mmap_size=268435456;").await?;
                conn.execute("PRAGMA cache_size=-20000;").await?;
                Ok(())
            }))
            .connect(&format!("sqlite:{}?mode=rwc", db_path))
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                level TEXT NOT NULL,
                mitre_tactic TEXT NOT NULL,
                mitre_technique TEXT NOT NULL,
                pid INTEGER,
                ppid INTEGER,
                uid INTEGER,
                cgroup_id INTEGER,
                container_id TEXT,
                container_name TEXT,
                comm TEXT,
                command_line TEXT,
                parent_comm TEXT,
                user_name TEXT,
                source_port INTEGER,
                target_file TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                shannon_entropy REAL,
                execution_velocity REAL,
                tuple_rarity REAL,
                path_depth INTEGER,
                anomaly_score REAL,
                message TEXT,
                in_memory_capture BOOLEAN,
                ml_vector TEXT,
                transmitted BOOLEAN DEFAULT 0
            )
            "#
        ).execute(&db_pool).await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);").execute(&db_pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_transmitted ON events(transmitted);").execute(&db_pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_score ON events(anomaly_score);").execute(&db_pool).await?;


        // -- Integrity: sequence counter table --------------------------------
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS integrity_sequence (
                sensor_id TEXT PRIMARY KEY,
                last_sequence INTEGER NOT NULL DEFAULT 0
            )"
        ).execute(&db_pool).await?;

        let sensor_id = std::env::var("SENTINEL_SENSOR_ID")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let sensor_id = format!("{}-sentinel", sensor_id);

        let initial_seq: u64 = sqlx::query("SELECT last_sequence FROM integrity_sequence WHERE sensor_id = ?")
            .bind(&sensor_id)
            .fetch_optional(&db_pool)
            .await?
            .map(|row| row.get::<i64, _>("last_sequence") as u64)
            .unwrap_or_else(|| {
                // Will insert on first persist -- no need to block here
                0
            });

        sqlx::query("INSERT OR IGNORE INTO integrity_sequence (sensor_id, last_sequence) VALUES (?, ?)")
            .bind(&sensor_id)
            .bind(initial_seq as i64)
            .execute(&db_pool)
            .await?;

        #[cfg(feature = "integrity")]
        let stamper = {
            let secret = {
                let lock = config.read().unwrap();
                lock.siem.integrity_secret.clone()
                    .unwrap_or_else(|| "Nexus-Integrity-SharedKey-Rotate-Me".to_string())
            };

            let s = Arc::new(tokio::sync::Mutex::new(
                LineageStamper::new(sensor_id.clone(), secret.as_bytes(), initial_seq)
            ));
            info!("[INTEGRITY] Stamper online: sensor_id={}, initial_seq={}", sensor_id, initial_seq);
            s
        };

        let mut headers = header::HeaderMap::new();
        headers.insert("X-Sensor-Type", header::HeaderValue::from_static("Linux-Sentinel"));
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/vnd.apache.parquet"));

        let mut client_builder = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .https_only(true);

        let (ca_cert_path, gateway_url) = {
            let lock = config.read().unwrap();
            (lock.siem.tls_ca_cert.clone(), lock.siem.middleware_gateway_url.clone())
        };

        if let Some(path) = ca_cert_path {
            if let Ok(cert_bytes) = std::fs::read(&path) {
                if let Ok(cert) = reqwest::Certificate::from_pem(&cert_bytes) {
                    client_builder = client_builder.add_root_certificate(cert);
                } else {
                    warn!("Failed to parse custom Root CA from PEM.");
                }
            }
        }

        if gateway_url.starts_with("http://") {
            warn!("SIEM gateway URL uses cleartext HTTP. Tokens and alerts will be transmitted unencrypted.");
        }

        if !gateway_url.starts_with("https://") {
            error!("CRITICAL: middleware_gateway_url must use HTTPS.");
            return Err(anyhow::anyhow!("TLS Enforcement Failed: Gateway URL is not HTTPS."));
        }

        let client = client_builder.build()?;

        Ok(Self {
            db_pool,
            client,
            config,
            #[cfg(feature = "integrity")]
            sensor_id,
            #[cfg(feature = "integrity")]
            stamper
        })
    }

    pub fn get_pool(&self) -> Pool<Sqlite> {
        self.db_pool.clone()
    }

    // Helper function for transactional micro-batching
    async fn flush_buffer(db_pool: &Pool<Sqlite>, buffer: &mut Vec<Arc<SecurityAlert>>) {
        if buffer.is_empty() { return; }

        match db_pool.begin().await {
            Ok(mut tx) => {
                for alert in buffer.iter() {
                    let res = sqlx::query(
                        r#"
                        INSERT INTO events (
                            event_id,
                            endpoint_id,
                            timestamp,
                            level,
                            mitre_tactic,
                            mitre_technique,
                            pid,
                            ppid,
                            uid,
                            cgroup_id,
                            container_id,
                            container_name,
                            comm,
                            command_line,
                            parent_comm,
                            user_name,
                            source_port,
                            target_file,
                            dest_ip,
                            dest_port,
                            shannon_entropy,
                            execution_velocity,
                            tuple_rarity,
                            path_depth,
                            anomaly_score,
                            message,
                            in_memory_capture,
                            ml_vector
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#
                    )
                    .bind(&alert.event_id)
                    .bind(&alert.endpoint_id)
                    .bind(alert.timestamp as i64)
                    .bind(alert.level.to_string())
                    .bind(alert.mitre_tactic.to_string())
                    .bind(&alert.mitre_technique)
                    .bind(alert.pid)
                    .bind(alert.ppid)
                    .bind(alert.uid)
                    .bind(alert.cgroup_id as i64)
                    .bind(&alert.container_id)
                    .bind(&alert.container_name)
                    .bind(&alert.comm)
                    .bind(&alert.command_line)
                    .bind(&alert.parent_comm)
                    .bind(&alert.user_name)
                    .bind(alert.source_port)
                    .bind(&alert.target_file)
                    .bind(&alert.dest_ip)
                    .bind(alert.dest_port)
                    .bind(alert.shannon_entropy)
                    .bind(alert.execution_velocity)
                    .bind(alert.tuple_rarity)
                    .bind(alert.path_depth as i64)
                    .bind(alert.anomaly_score)
                    .bind(&alert.message)
                    .bind(alert.in_memory_capture)
                    .bind(alert.ml_vector.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()))
                    .execute(&mut *tx).await;

                    if let Err(e) = res { error!("SQLite Batch Insert Fault: {}", e); }
                }

                if let Err(e) = tx.commit().await {
                    error!("FATAL: Failed to commit telemetry batch to disk: {}", e);
                }
            }
            Err(e) => error!("Failed to acquire SQLite transaction lock: {}", e),
        }
        buffer.clear();
        tokio::task::yield_now().await;
    }

    pub fn spawn_worker(&self, mut rx: mpsc::Receiver<Arc<SecurityAlert>>) {
        info!("Transmission Layer Active. Bridging SQLite WAL to Parquet Ingress.");
        let db_pool = self.db_pool.clone();
        let client = self.client.clone();
        let config_ref = self.config.clone();
        #[cfg(feature = "integrity")]
        let stamper = self.stamper.clone();
        #[cfg(feature = "integrity")]
        let sensor_id = self.sensor_id.clone();

        let db_writer = db_pool.clone();
        tokio::spawn(async move {
            let mut buffer = Vec::with_capacity(500);
            let mut flush_interval = tokio::time::interval(Duration::from_millis(500));

            loop {
                tokio::select! {
                    res = rx.recv() => {
                        match res {
                            Some(alert) => {
                                if alert.message.starts_with("YARA Match:") && alert.message.contains("/opt/linux-sentinel/linux-sentinel") {
                                    continue;
                                }
                                buffer.push(alert);
                                if buffer.len() >= 500 {
                                    Self::flush_buffer(&db_writer, &mut buffer).await;
                                }
                            }
                            None => {
                                Self::flush_buffer(&db_writer, &mut buffer).await;
                                break;
                            }
                        }
                    }
                    _ = flush_interval.tick() => {
                        Self::flush_buffer(&db_writer, &mut buffer).await;
                    }
                }
            }
        });

        // Parquet Forwarder & 72-Hour Cache Task
        let mut current_backoff = Duration::from_secs(5);
        let max_backoff = Duration::from_secs(300);

        // Define Arrow Schema matching the SQLite table
        let schema = Arc::new(Schema::new(vec![
            Field::new("event_id", DataType::Utf8, false),
            Field::new("endpoint_id", DataType::Utf8, false),
            Field::new("timestamp", DataType::UInt64, false),
            Field::new("level", DataType::Utf8, false),
            Field::new("mitre_tactic", DataType::Utf8, false),
            Field::new("mitre_technique", DataType::Utf8, false),
            Field::new("pid", DataType::UInt32, false),
            Field::new("ppid", DataType::UInt32, false),
            Field::new("uid", DataType::UInt32, false),
            Field::new("container_name", DataType::Utf8, false),
            Field::new("comm", DataType::Utf8, false),
            Field::new("command_line", DataType::Utf8, true),
            Field::new("parent_comm", DataType::Utf8, false),
            Field::new("user_name", DataType::Utf8, false),
            Field::new("target_file", DataType::Utf8, true),
            Field::new("dest_ip", DataType::Utf8, true),
            Field::new("dest_port", DataType::UInt16, true),
            Field::new("shannon_entropy", DataType::Float64, false),
            Field::new("execution_velocity", DataType::Float64, false),
            Field::new("tuple_rarity", DataType::Float64, false),
            Field::new("path_depth", DataType::Float64, false),
            Field::new("anomaly_score", DataType::Float64, false),
            Field::new("message", DataType::Utf8, false),
            Field::new("in_memory_capture", DataType::Boolean, true),
            Field::new("ml_vector", DataType::Utf8, true),
        ]));

        tokio::spawn(async move {
            let mut last_prune = tokio::time::Instant::now();
            let mut hour_counter = 0;

            loop {
                tokio::time::sleep(current_backoff).await;

                let batch_size = {
                    let lock = config_ref.read().unwrap_or_else(|e| e.into_inner());
                    lock.siem.batch_size as i64
                };

                loop {
                    let records_res = sqlx::query("SELECT * FROM events WHERE transmitted = 0 ORDER BY timestamp ASC LIMIT ?")
                        .bind(batch_size)
                        .fetch_all(&db_pool).await;

                    match records_res {
                        Ok(rows) if !rows.is_empty() => {
                            let row_count = rows.len();
                            let mut processed_ids = Vec::with_capacity(row_count);

                            // Initialize Parquet Builders
                            let mut id_b = StringBuilder::new();
                            let mut ep_b = StringBuilder::new();
                            let mut ts_b = UInt64Builder::new();
                            let mut lvl_b = StringBuilder::new();
                            let mut tactic_b = StringBuilder::new();
                            let mut tech_b = StringBuilder::new();
                            let mut pid_b = UInt32Builder::new();
                            let mut ppid_b = UInt32Builder::new();
                            let mut uid_b = UInt32Builder::new();
                            let mut cont_b = StringBuilder::new();
                            let mut comm_b = StringBuilder::new();
                            let mut cmd_b = StringBuilder::new();
                            let mut pcomm_b = StringBuilder::new();
                            let mut user_b = StringBuilder::new();
                            let mut tgt_b = StringBuilder::new();
                            let mut ip_b = StringBuilder::new();
                            let mut port_b = UInt16Builder::new();
                            let mut ent_b = Float64Builder::new();
                            let mut vel_b = Float64Builder::new();
                            let mut rar_b = Float64Builder::new();
                            let mut path_b = Float64Builder::new();
                            let mut score_b = Float64Builder::new();
                            let mut msg_b = StringBuilder::new();
                            let mut mem_cap_b = arrow::array::BooleanBuilder::new();
                            let mut ml_vec_b = StringBuilder::new();

                            for row in rows {
                                let ev_id: String = row.try_get("event_id").unwrap_or_default();
                                ep_b.append_value(row.try_get::<String, _>("endpoint_id").unwrap_or_default());
                                processed_ids.push(ev_id.clone());

                                id_b.append_value(ev_id);
                                ts_b.append_value(row.try_get::<i64, _>("timestamp").unwrap_or(0) as u64);
                                lvl_b.append_value(row.try_get::<String, _>("level").unwrap_or_default());
                                tactic_b.append_value(row.try_get::<String, _>("mitre_tactic").unwrap_or_default());
                                tech_b.append_value(row.try_get::<String, _>("mitre_technique").unwrap_or_default());
                                pid_b.append_value(row.try_get::<i32, _>("pid").unwrap_or(0) as u32);
                                ppid_b.append_value(row.try_get::<i32, _>("ppid").unwrap_or(0) as u32);
                                uid_b.append_value(row.try_get::<i32, _>("uid").unwrap_or(0) as u32);
                                cont_b.append_value(row.try_get::<String, _>("container_name").unwrap_or_else(|_| "host".to_string()));
                                comm_b.append_value(row.try_get::<String, _>("comm").unwrap_or_default());

                                match row.try_get::<Option<String>, _>("command_line") {
                                    Ok(Some(v)) if !v.is_empty() => cmd_b.append_value(v), _ => cmd_b.append_null(),
                                }

                                pcomm_b.append_value(row.try_get::<String, _>("parent_comm").unwrap_or_else(|_| "unknown".to_string()));
                                user_b.append_value(row.try_get::<String, _>("user_name").unwrap_or_else(|_| "system".to_string()));

                                match row.try_get::<Option<String>, _>("target_file") {
                                    Ok(Some(v)) if !v.is_empty() => tgt_b.append_value(v), _ => tgt_b.append_null(),
                                }
                                match row.try_get::<Option<String>, _>("dest_ip") {
                                    Ok(Some(v)) if !v.is_empty() => ip_b.append_value(v), _ => ip_b.append_null(),
                                }
                                match row.try_get::<Option<i32>, _>("dest_port") {
                                    Ok(Some(p)) if p > 0 => port_b.append_value(p as u16), _ => port_b.append_null(),
                                }

                                ent_b.append_value(row.try_get::<f64, _>("shannon_entropy").unwrap_or(0.0));
                                vel_b.append_value(row.try_get::<f64, _>("execution_velocity").unwrap_or(0.0));
                                rar_b.append_value(row.try_get::<f64, _>("tuple_rarity").unwrap_or(0.0));
                                path_b.append_value(row.try_get::<i64, _>("path_depth").unwrap_or(0) as f64);
                                score_b.append_value(row.try_get::<f64, _>("anomaly_score").unwrap_or(0.0));
                                msg_b.append_value(row.try_get::<String, _>("message").unwrap_or_default());
                                mem_cap_b.append_option(row.try_get::<Option<bool>, _>("in_memory_capture").unwrap_or(None));

                                match row.try_get::<Option<String>, _>("ml_vector") {
                                    Ok(Some(v)) if !v.is_empty() => ml_vec_b.append_value(v),
                                    _ => ml_vec_b.append_null(),
                                }
                            }

                            // Build Parquet Batch
                            let batch = RecordBatch::try_new(
                                schema.clone(),
                                vec![
                                    Arc::new(id_b.finish()),
                                    Arc::new(ep_b.finish()),
                                    Arc::new(ts_b.finish()),
                                    Arc::new(lvl_b.finish()),
                                    Arc::new(tactic_b.finish()),
                                    Arc::new(tech_b.finish()),
                                    Arc::new(pid_b.finish()),
                                    Arc::new(ppid_b.finish()),
                                    Arc::new(uid_b.finish()),
                                    Arc::new(cont_b.finish()),
                                    Arc::new(comm_b.finish()),
                                    Arc::new(cmd_b.finish()),
                                    Arc::new(pcomm_b.finish()),
                                    Arc::new(user_b.finish()),
                                    Arc::new(tgt_b.finish()),
                                    Arc::new(ip_b.finish()),
                                    Arc::new(port_b.finish()),
                                    Arc::new(ent_b.finish()),
                                    Arc::new(vel_b.finish()),
                                    Arc::new(rar_b.finish()),
                                    Arc::new(path_b.finish()),
                                    Arc::new(score_b.finish()),
                                    Arc::new(msg_b.finish()),
                                    Arc::new(mem_cap_b.finish()),
                                    Arc::new(ml_vec_b.finish()),
                                ],
                            ).expect("Failed to build Arrow RecordBatch");

                            let mut parquet_buffer = Vec::new();
                            let props = WriterProperties::builder().set_compression(Compression::ZSTD(Default::default())).build();

                            {
                                let mut writer = ArrowWriter::try_new(&mut parquet_buffer, schema.clone(), Some(props)).unwrap();
                                writer.write(&batch).unwrap();
                                writer.close().unwrap();
                            }

                            let (gateway_url, token) = {
                                let lock = config_ref.read().unwrap_or_else(|e| e.into_inner());
                                (lock.siem.middleware_gateway_url.clone(), lock.siem.auth_token.clone())
                            };

                            debug!("Dispatching {} events in Parquet payload...", processed_ids.len());

                            #[cfg(feature = "integrity")]
                            let response = {
                                let stamp = {
                                    let mut s = stamper.lock().await;
                                    s.stamp(&parquet_buffer)
                                };

                                let _ = sqlx::query("UPDATE integrity_sequence SET last_sequence = ? WHERE sensor_id = ?")
                                    .bind(stamp.sequence as i64)
                                    .bind(&sensor_id)
                                    .execute(&db_pool).await;

                                client.post(&gateway_url)
                                    .bearer_auth(&token)
                                    .header(HDR_BATCH_SEQUENCE, stamp.sequence.to_string())
                                    .header(HDR_BATCH_TIMESTAMP, stamp.timestamp.to_string())
                                    .header(HDR_SENSOR_ID, &stamp.sensor_id)
                                    .header(HDR_BATCH_HMAC, &stamp.hmac_hex)
                                    .body(parquet_buffer)
                                    .send()
                                    .await
                            };

                            #[cfg(not(feature = "integrity"))]
                            let response = {
                                client.post(&gateway_url)
                                    .bearer_auth(&token)
                                    .body(parquet_buffer)
                                    .send()
                                    .await
                            };

                            match response {
                                Ok(resp) if resp.status().is_success() => {
                                    current_backoff = Duration::from_secs(5);

                                    if !processed_ids.is_empty() {
                                        let placeholders: Vec<String> = vec!["?".to_string(); processed_ids.len()];
                                        let query = format!("UPDATE events SET transmitted = 1 WHERE event_id IN ({})", placeholders.join(","));
                                        let mut q = sqlx::query(&query);
                                        for id in &processed_ids { q = q.bind(id); }
                                        let _ = q.execute(&db_pool).await;
                                    }
                                }
                                Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                                    error!("[INTEGRITY] Gateway returned 403 FORBIDDEN. Sensor may be banned. Halting transmission.");
                                    break;
                                }
                                Ok(resp) => {
                                    warn!("SIEM rejected Parquet payload: HTTP {}. Increasing backoff.", resp.status());
                                    current_backoff = std::cmp::min(current_backoff * 2, max_backoff);
                                    break;
                                }
                                Err(e) => {
                                    if current_backoff.as_secs() <= 10 {
                                        error!("SIEM Gateway unreachable: {}. Backing off.", e);
                                    }
                                    current_backoff = std::cmp::min(current_backoff * 2, max_backoff);
                                    break;
                                }
                            }

                            if row_count < batch_size as usize { break; }
                            tokio::task::yield_now().await;
                        }
                        Ok(_) => break, // Empty queue
                        Err(e) => {
                            error!("Failed to poll SQLite for untransmitted events: {}", e);
                            break;
                        }
                    }
                }

                // Hourly Cache Prune & SQLite WAL Maintenance
                if last_prune.elapsed().as_secs() >= 3600 {
                    hour_counter += 1;
                    let cutoff_ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
                        .saturating_sub(3 * 24 * 60 * 60);

                    if let Err(e) = sqlx::query("DELETE FROM events WHERE transmitted = 1 AND timestamp < ?")
                        .bind(cutoff_ts as i64).execute(&db_pool).await {
                        error!("SQLite Prune Fault: Failed to clear stale cache: {}", e);
                    }

                    let _ = sqlx::query("PRAGMA wal_checkpoint(PASSIVE)").execute(&db_pool).await;

                    if hour_counter % 24 == 0 {
                        let db_path_clone = {
                            let lock = config_ref.read().unwrap_or_else(|e| e.into_inner());
                            lock.storage.sqlite_db_path.clone()
                        };
                        tokio::task::spawn_blocking(move || {
                            match rusqlite::Connection::open(&db_path_clone) {
                                Ok(conn) => {
                                    let _ = conn.execute_batch("PRAGMA busy_timeout=30000;");

                                    let mut freed_pages = 1;
                                    while freed_pages > 0 {
                                        match conn.query_row("PRAGMA incremental_vacuum(100);", [], |row| row.get::<_, i32>(0)) {
                                            Ok(pages) => freed_pages = pages,
                                            Err(_) => break, // Database locked or empty, yield gracefully
                                        }
                                        std::thread::sleep(std::time::Duration::from_millis(50)); // Yield to the ingestion thread
                                    }
                                    info!("Incremental WAL vacuum completed without stalling ingestion.");
                                }
                                Err(e) => warn!("Maintenance deferred -- connection failed: {}", e),
                            }
                        });
                        hour_counter = 0;
                    }

                    last_prune = tokio::time::Instant::now();
                }
            }
        });
    }
}

pub struct LocalParquetArchiver {
    rx: mpsc::Receiver<Arc<SecurityAlert>>,
    flush_dir: String,
    compression: String,
    flush_interval_sec: u64,
    buffer: Vec<Arc<SecurityAlert>>,
    buffer_max_rows: usize,
}

impl LocalParquetArchiver {
    pub fn new(
        rx: mpsc::Receiver<Arc<SecurityAlert>>,
        flush_dir: String,
        compression: String,
        batch_size: usize,
        flush_interval_sec: u64,
    ) -> Self {
        std::fs::create_dir_all(&flush_dir).unwrap_or_default();
        Self {
            rx,
            flush_dir,
            compression,
            flush_interval_sec,
            buffer: Vec::with_capacity(batch_size),
            buffer_max_rows: batch_size,
        }
    }

    pub async fn run(&mut self) {
        info!("Local Parquet Archiver initialized. batch_size={}, flush_interval={}s",
            self.buffer_max_rows, self.flush_interval_sec);
        let mut flush_timer = tokio::time::interval(Duration::from_secs(self.flush_interval_sec));

        loop {
            tokio::select! {
                res = self.rx.recv() => {
                    match res {
                        Some(alert) => {
                            self.buffer.push(alert);
                            if self.buffer.len() >= self.buffer_max_rows {
                                if let Err(e) = self.flush_to_disk() {
                                    error!("Local Parquet flush failed: {}", e);
                                }
                            }
                        }
                        None => {
                            if !self.buffer.is_empty() {
                                let _ = self.flush_to_disk();
                            }
                            break;
                        }
                    }
                }
                _ = flush_timer.tick() => {
                    if !self.buffer.is_empty() {
                        if let Err(e) = self.flush_to_disk() {
                            error!("Local Parquet timed flush failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    fn flush_to_disk(&mut self) -> anyhow::Result<()> {
        debug!("Memory watermark breached. Flushing {} records to local Parquet...", self.buffer.len());

        let schema = Arc::new(Schema::new(vec![
            Field::new("event_id", DataType::Utf8, false),
            Field::new("endpoint_id", DataType::Utf8, false),
            Field::new("timestamp", DataType::UInt64, false),
            Field::new("level", DataType::Utf8, false),
            Field::new("mitre_tactic", DataType::Utf8, false),
            Field::new("mitre_technique", DataType::Utf8, false),
            Field::new("pid", DataType::UInt32, false),
            Field::new("ppid", DataType::UInt32, false),
            Field::new("uid", DataType::UInt32, false),
            Field::new("container_name", DataType::Utf8, false),
            Field::new("comm", DataType::Utf8, false),
            Field::new("command_line", DataType::Utf8, true),
            Field::new("parent_comm", DataType::Utf8, false),
            Field::new("user_name", DataType::Utf8, false),
            Field::new("target_file", DataType::Utf8, true),
            Field::new("dest_ip", DataType::Utf8, true),
            Field::new("dest_port", DataType::UInt16, true),
            Field::new("shannon_entropy", DataType::Float64, false),
            Field::new("execution_velocity", DataType::Float64, false),
            Field::new("tuple_rarity", DataType::Float64, false),
            Field::new("path_depth", DataType::Float64, false),
            Field::new("anomaly_score", DataType::Float64, false),
            Field::new("message", DataType::Utf8, false),
            Field::new("in_memory_capture", DataType::Boolean, true),
            Field::new("ml_vector", DataType::Utf8, true),
        ]));

        let mut id_b = StringBuilder::new();
        let mut ep_b = StringBuilder::new();
        let mut ts_b = UInt64Builder::new();
        let mut lvl_b = StringBuilder::new();
        let mut tactic_b = StringBuilder::new();
        let mut tech_b = StringBuilder::new();
        let mut pid_b = UInt32Builder::new();
        let mut ppid_b = UInt32Builder::new();
        let mut uid_b = UInt32Builder::new();
        let mut cont_b = StringBuilder::new();
        let mut comm_b = StringBuilder::new();
        let mut cmd_b = StringBuilder::new();
        let mut pcomm_b = StringBuilder::new();
        let mut user_b = StringBuilder::new();
        let mut tgt_b = StringBuilder::new();
        let mut ip_b = StringBuilder::new();
        let mut port_b = UInt16Builder::new();
        let mut ent_b = Float64Builder::new();
        let mut vel_b = Float64Builder::new();
        let mut rar_b = Float64Builder::new();
        let mut path_b = Float64Builder::new();
        let mut score_b = Float64Builder::new();
        let mut msg_b = StringBuilder::new();
        let mut mem_b = arrow::array::BooleanBuilder::new();
        let mut ml_b = StringBuilder::new();

        for alert in &self.buffer {
            id_b.append_value(&alert.event_id);
            ep_b.append_value(&alert.endpoint_id);
            ts_b.append_value(alert.timestamp);
            lvl_b.append_value(alert.level.to_string());
            tactic_b.append_value(alert.mitre_tactic.to_string());
            tech_b.append_value(&alert.mitre_technique);
            pid_b.append_value(alert.pid);
            ppid_b.append_value(alert.ppid);
            uid_b.append_value(alert.uid);
            cont_b.append_value(&alert.container_name);
            comm_b.append_value(&alert.comm);

            if alert.command_line.is_empty() { cmd_b.append_null(); } else { cmd_b.append_value(&alert.command_line); }
            pcomm_b.append_value(&alert.parent_comm);
            user_b.append_value(&alert.user_name);

            match &alert.target_file { Some(v) if !v.is_empty() => tgt_b.append_value(v), _ => tgt_b.append_null() }
            match &alert.dest_ip { Some(v) if !v.is_empty() => ip_b.append_value(v), _ => ip_b.append_null() }
            match alert.dest_port { Some(p) if p > 0 => port_b.append_value(p), _ => port_b.append_null() }

            ent_b.append_value(alert.shannon_entropy);
            vel_b.append_value(alert.execution_velocity);
            rar_b.append_value(alert.tuple_rarity);
            path_b.append_value(alert.path_depth as f64);
            score_b.append_value(alert.anomaly_score);
            msg_b.append_value(&alert.message);

            mem_b.append_option(alert.in_memory_capture);
            match &alert.ml_vector {
                Some(v) => ml_b.append_value(serde_json::to_string(v).unwrap_or_default()),
                None => ml_b.append_null(),
            }
        }

        let batch = RecordBatch::try_new(schema.clone(), vec![
            Arc::new(id_b.finish()),
            Arc::new(ep_b.finish()),
            Arc::new(ts_b.finish()),
            Arc::new(lvl_b.finish()),
            Arc::new(tactic_b.finish()),
            Arc::new(tech_b.finish()),
            Arc::new(pid_b.finish()),
            Arc::new(ppid_b.finish()),
            Arc::new(uid_b.finish()),
            Arc::new(cont_b.finish()),
            Arc::new(comm_b.finish()),
            Arc::new(cmd_b.finish()),
            Arc::new(pcomm_b.finish()),
            Arc::new(user_b.finish()),
            Arc::new(tgt_b.finish()),
            Arc::new(ip_b.finish()),
            Arc::new(port_b.finish()),
            Arc::new(ent_b.finish()),
            Arc::new(vel_b.finish()),
            Arc::new(rar_b.finish()),
            Arc::new(path_b.finish()),
            Arc::new(score_b.finish()),
            Arc::new(msg_b.finish()),
            Arc::new(mem_b.finish()),
            Arc::new(ml_b.finish()),
        ])?;

        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let path = format!("{}/archive_{}.parquet", self.flush_dir, ts);

        let comp_type = match self.compression.to_lowercase().as_str() {
            "snappy" => Compression::SNAPPY,
            "zstd" => Compression::ZSTD(Default::default()),
            "lz4" => Compression::LZ4,
            _ => Compression::UNCOMPRESSED,
        };
        let props = WriterProperties::builder().set_compression(comp_type).build();

        let mut writer = ArrowWriter::try_new(std::fs::File::create(&path)?, schema, Some(props))?;
        writer.write(&batch)?;
        writer.close()?;

        self.buffer.clear();
        Ok(())
    }
}