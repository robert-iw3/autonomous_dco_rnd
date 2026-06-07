use crate::models::NetworkFlowRecord;
use anyhow::Result;
use metrics::counter;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Executor, Pool, Row, Sqlite};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

const MAX_STR_LEN: usize = 4096;

pub struct SpoolDb {
    pool:            Pool<Sqlite>,
    max_spool_bytes: u64,
    // Throttle spool-cap enforcement to at most once per 60 seconds
    last_cap_check:  Mutex<Instant>,
}

impl SpoolDb {
    pub async fn new(db_path: &str, max_spool_bytes: u64) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .min_connections(1)
            .idle_timeout(Duration::from_secs(60))
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute("PRAGMA journal_mode=WAL;").await?;
                    conn.execute("PRAGMA synchronous=NORMAL;").await?;
                    conn.execute("PRAGMA busy_timeout=5000;").await?;
                    // Keep temp tables in memory -- avoids leaking sensitive data to /tmp
                    conn.execute("PRAGMA temp_store=MEMORY;").await?;
                    conn.execute("PRAGMA mmap_size=268435456;").await?;
                    conn.execute("PRAGMA cache_size=-20000;").await?;
                    Ok(())
                })
            })
            .connect(&format!("sqlite:{}?mode=rwc", db_path))
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS flows (
                rowid                   INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id              TEXT    NOT NULL,
                timestamp_start         INTEGER NOT NULL,
                timestamp_end           INTEGER NOT NULL,
                session_duration_ms     INTEGER NOT NULL,
                src_ip                  TEXT    NOT NULL,
                dst_ip                  TEXT    NOT NULL,
                src_port                INTEGER NOT NULL,
                dst_port                INTEGER NOT NULL,
                protocol                INTEGER NOT NULL,
                protocol_name           TEXT    NOT NULL,
                bytes_src               INTEGER NOT NULL,
                bytes_dst               INTEGER NOT NULL,
                data_bytes_src          INTEGER NOT NULL,
                data_bytes_dst          INTEGER NOT NULL,
                packets_src             INTEGER NOT NULL,
                packets_dst             INTEGER NOT NULL,
                byte_ratio              REAL    NOT NULL,
                avg_inter_arrival       REAL    NOT NULL,
                variance_inter_arrival  REAL    NOT NULL,
                ratio_small_packets     REAL    NOT NULL,
                ratio_large_packets     REAL    NOT NULL,
                packet_size_entropy     REAL    NOT NULL,
                tcp_syn                 INTEGER,
                tcp_rst                 INTEGER,
                tcp_fin                 INTEGER,
                dns_query               TEXT,
                dns_status              TEXT,
                http_method             TEXT,
                http_uri                TEXT,
                http_useragent          TEXT,
                http_status_code        INTEGER,
                tls_ja3                 TEXT,
                tls_ja3s                TEXT,
                tls_version             TEXT,
                tls_cipher              TEXT,
                cert_cn                 TEXT,
                cert_issuer_cn          TEXT,
                cert_self_signed        INTEGER,
                cert_valid_days         INTEGER,
                hostname                TEXT,
                src_geo_country         TEXT,
                dst_geo_country         TEXT,
                dst_asn_org             TEXT,
                is_internal_dst         INTEGER NOT NULL DEFAULT 0,
                port_class              TEXT    NOT NULL DEFAULT 'well_known',
                transmitted             INTEGER DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await?;

        // Incremental schema migrations -- errors are silently ignored (column already exists
        // or rename already applied).
        for migration in [
            "ALTER TABLE flows ADD COLUMN is_internal_dst INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE flows ADD COLUMN port_class TEXT NOT NULL DEFAULT 'well_known'",
            // Rename from original field name to clearer name
            "ALTER TABLE flows RENAME COLUMN payload_entropy TO packet_size_entropy",
        ] {
            let _ = sqlx::query(migration).execute(&pool).await;
        }

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_flows_transmitted ON flows(transmitted);"
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(timestamp_start);"
        )
        .execute(&pool)
        .await?;

        info!(path = db_path, max_bytes = max_spool_bytes, "SQLite WAL spool initialized");

        // Force an immediate cap check on the first insert
        let initial = Instant::now() - Duration::from_secs(61);
        Ok(Self { pool, max_spool_bytes, last_cap_check: Mutex::new(initial) })
    }

    pub fn pool(&self) -> Pool<Sqlite> {
        self.pool.clone()
    }

    async fn enforce_spool_cap(&self) {
        if self.max_spool_bytes == 0 {
            return;
        }

        // Throttle to at most once every 60 seconds
        {
            let mut last = self.last_cap_check.lock().unwrap();
            if last.elapsed() < Duration::from_secs(60) {
                return;
            }
            *last = Instant::now();
        }

        let size_result = sqlx::query(
            "SELECT page_count * page_size AS db_size \
             FROM pragma_page_count(), pragma_page_size()"
        )
        .fetch_one(&self.pool)
        .await;

        let db_size: i64 = match size_result {
            Ok(row) => row.try_get("db_size").unwrap_or(0),
            Err(_) => return,
        };

        if (db_size as u64) <= self.max_spool_bytes {
            return;
        }

        let overage_mb = ((db_size as u64) - self.max_spool_bytes) / (1024 * 1024);
        warn!(
            db_size_mb  = db_size / (1024 * 1024),
            cap_mb       = self.max_spool_bytes / (1024 * 1024),
            overage_mb,
            "Spool cap exceeded -- dropping oldest untransmitted rows"
        );

        let total: i64 = sqlx::query(
            "SELECT COUNT(*) AS cnt FROM flows WHERE transmitted = 0"
        )
        .fetch_one(&self.pool)
        .await
        .ok()
        .and_then(|r| r.try_get("cnt").ok())
        .unwrap_or(0);

        let drop_count = (total / 10).max(1000);

        let _ = sqlx::query(
            "DELETE FROM flows WHERE rowid IN (
                SELECT rowid FROM flows WHERE transmitted = 0
                ORDER BY timestamp_start ASC LIMIT ?
            )"
        )
        .bind(drop_count)
        .execute(&self.pool)
        .await;

        counter!("gateway.spool_rows_dropped_cap").increment(drop_count as u64);
        warn!(dropped = drop_count, "Spool cap: dropped oldest rows");
    }

    /// Transactional batch insert. Returns Err if the transaction fails to commit,
    /// so the caller can skip Kafka offset advancement and retry on restart.
    pub async fn insert_batch(&self, batch: &[NetworkFlowRecord]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        self.enforce_spool_cap().await;

        let mut tx = self.pool.begin().await?;

        for r in batch {
            // Truncate unbounded string fields at the boundary
            let http_uri = r.http_uri.as_deref().map(|s| &s[..s.len().min(MAX_STR_LEN)]);
            let http_ua  = r.http_useragent.as_deref().map(|s| &s[..s.len().min(MAX_STR_LEN)]);
            let cert_cn  = r.cert_cn.as_deref().map(|s| &s[..s.len().min(MAX_STR_LEN)]);

            let res = sqlx::query(
                r#"
                INSERT INTO flows (
                    session_id, timestamp_start, timestamp_end, session_duration_ms,
                    src_ip, dst_ip, src_port, dst_port, protocol, protocol_name,
                    bytes_src, bytes_dst, data_bytes_src, data_bytes_dst,
                    packets_src, packets_dst,
                    byte_ratio, avg_inter_arrival, variance_inter_arrival,
                    ratio_small_packets, ratio_large_packets, packet_size_entropy,
                    tcp_syn, tcp_rst, tcp_fin,
                    dns_query, dns_status,
                    http_method, http_uri, http_useragent, http_status_code,
                    tls_ja3, tls_ja3s, tls_version, tls_cipher,
                    cert_cn, cert_issuer_cn, cert_self_signed, cert_valid_days,
                    hostname, src_geo_country, dst_geo_country, dst_asn_org,
                    is_internal_dst, port_class
                ) VALUES (
                    ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?
                )
                "#,
            )
            .bind(&r.session_id)
            .bind(r.timestamp_start as i64)
            .bind(r.timestamp_end as i64)
            .bind(r.session_duration_ms as i64)
            .bind(&r.src_ip)
            .bind(&r.dst_ip)
            .bind(r.src_port as i32)
            .bind(r.dst_port as i32)
            .bind(r.protocol as i32)
            .bind(&r.protocol_name)
            .bind(r.bytes_src as i64)
            .bind(r.bytes_dst as i64)
            .bind(r.data_bytes_src as i64)
            .bind(r.data_bytes_dst as i64)
            .bind(r.packets_src as i64)
            .bind(r.packets_dst as i64)
            .bind(r.byte_ratio as f64)
            .bind(r.avg_inter_arrival as f64)
            .bind(r.variance_inter_arrival as f64)
            .bind(r.ratio_small_packets as f64)
            .bind(r.ratio_large_packets as f64)
            .bind(r.packet_size_entropy as f64)
            .bind(r.tcp_syn.map(|v| v as i64))
            .bind(r.tcp_rst.map(|v| v as i64))
            .bind(r.tcp_fin.map(|v| v as i64))
            .bind(&r.dns_query)
            .bind(&r.dns_status)
            .bind(&r.http_method)
            .bind(http_uri)
            .bind(http_ua)
            .bind(r.http_status_code.map(|v| v as i32))
            .bind(&r.tls_ja3)
            .bind(&r.tls_ja3s)
            .bind(&r.tls_version)
            .bind(&r.tls_cipher)
            .bind(cert_cn)
            .bind(&r.cert_issuer_cn)
            .bind(r.cert_self_signed.map(|v| v as i32))
            .bind(r.cert_valid_days)
            .bind(&r.hostname)
            .bind(&r.src_geo_country)
            .bind(&r.dst_geo_country)
            .bind(&r.dst_asn_org)
            .bind(r.is_internal_dst as i32)
            .bind(&r.port_class)
            .execute(&mut *tx)
            .await;

            if let Err(e) = res {
                error!("SQLite row insert fault: {}", e);
            }
        }

        tx.commit().await.map_err(|e| {
            error!("FATAL: Failed to commit flow batch: {}", e);
            anyhow::anyhow!(e)
        })?;

        counter!("gateway.spool_rows_written").increment(batch.len() as u64);
        Ok(())
    }
}
