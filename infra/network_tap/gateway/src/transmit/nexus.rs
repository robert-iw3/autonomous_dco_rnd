// =============================================================================
// Nexus Transmitter -- Bridges SQLite WAL spool to upstream Axum gateway
// =============================================================================

use crate::config::GatewayConfig;
use crate::integrity::stamper::LineageStamper;
use crate::integrity::{HDR_BATCH_HMAC, HDR_BATCH_SEQUENCE, HDR_BATCH_TIMESTAMP, HDR_SENSOR_ID};
use anyhow::{Context, Result};
use arrow::array::{
    BooleanBuilder, Float64Builder, Int32Builder, StringBuilder, UInt16Builder,
    UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use chrono::{TimeZone, Utc};
use metrics::counter;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use reqwest::{header, Client};
use sqlx::{Pool, Row, Sqlite};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

const SCHEMA_VERSION: &str = "v2";

fn flow_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        // Identity
        Field::new("session_id",             DataType::Utf8,    false),
        Field::new("src_ip",                 DataType::Utf8,    false),
        Field::new("dst_ip",                 DataType::Utf8,    false),
        Field::new("src_port",               DataType::UInt16,  false),
        Field::new("dst_port",               DataType::UInt16,  false),
        Field::new("protocol",               DataType::UInt32,  false),
        Field::new("protocol_name",          DataType::Utf8,    false),
        // Temporal
        Field::new("timestamp_start",        DataType::UInt64,  false),
        Field::new("timestamp_end",          DataType::UInt64,  false),
        Field::new("session_duration_ms",    DataType::UInt64,  false),
        // Volume
        Field::new("bytes_src",              DataType::UInt64,  false),
        Field::new("bytes_dst",              DataType::UInt64,  false),
        Field::new("data_bytes_src",         DataType::UInt64,  false),
        Field::new("data_bytes_dst",         DataType::UInt64,  false),
        Field::new("packets_src",            DataType::UInt32,  false),
        Field::new("packets_dst",            DataType::UInt32,  false),
        // Statistical
        Field::new("byte_ratio",             DataType::Float64, false),
        Field::new("avg_inter_arrival",      DataType::Float64, false),
        Field::new("variance_inter_arrival", DataType::Float64, false),
        Field::new("ratio_small_packets",    DataType::Float64, false),
        Field::new("ratio_large_packets",    DataType::Float64, false),
        Field::new("payload_entropy",         DataType::Float64, false),
        // TCP
        Field::new("tcp_syn",                DataType::UInt32,  true),
        Field::new("tcp_rst",                DataType::UInt32,  true),
        Field::new("tcp_fin",                DataType::UInt32,  true),
        // DNS
        Field::new("dns_query",              DataType::Utf8,    true),
        Field::new("dns_status",             DataType::Utf8,    true),
        // HTTP
        Field::new("http_method",            DataType::Utf8,    true),
        Field::new("http_uri",               DataType::Utf8,    true),
        Field::new("http_useragent",         DataType::Utf8,    true),
        Field::new("http_status_code",       DataType::UInt16,  true),
        // TLS
        Field::new("tls_ja3",                DataType::Utf8,    true),
        Field::new("tls_ja3s",               DataType::Utf8,    true),
        Field::new("tls_version",            DataType::Utf8,    true),
        Field::new("tls_cipher",             DataType::Utf8,    true),
        // Certificate
        Field::new("cert_cn",                DataType::Utf8,    true),
        Field::new("cert_issuer_cn",         DataType::Utf8,    true),
        Field::new("cert_self_signed",       DataType::Boolean,  true),
        Field::new("cert_valid_days",        DataType::Int32,    true),
        // Hostname / GeoIP
        Field::new("hostname",               DataType::Utf8,    true),
        Field::new("src_geo_country",        DataType::Utf8,    true),
        Field::new("dst_geo_country",        DataType::Utf8,    true),
        Field::new("dst_asn_org",            DataType::Utf8,    true),
        // Sensor metadata
        Field::new("sensor_name",            DataType::Utf8,    false),
        Field::new("sensor_type",            DataType::Utf8,    false),
        // Derived ML features
        Field::new("is_internal_dst",        DataType::Boolean, false),
        Field::new("port_class",             DataType::Utf8,    false),
        // Schema version -- consumers gate on this for forward compatibility
        Field::new("schema_version",         DataType::Utf8,    false),
    ]))
}

/// Derive Hive-style partition hints from the first row's timestamp.
/// Arkime fp/lp are always milliseconds -- divide by 1000 unconditionally.
fn extract_partition_hints(rows: &[sqlx::sqlite::SqliteRow]) -> (String, String) {
    let ts_ms: i64 = rows.first()
        .and_then(|r| r.try_get::<i64, _>("timestamp_start").ok())
        .unwrap_or(0);

    let dt = if ts_ms > 0 {
        Utc.timestamp_opt(ts_ms / 1000, 0)
            .single()
            .unwrap_or_else(Utc::now)
    } else {
        Utc::now()
    };
    (dt.format("%Y-%m-%d").to_string(), dt.format("%H").to_string())
}

pub async fn transmit_loop(
    db_pool: Pool<Sqlite>,
    cfg: GatewayConfig,
    cancel_token: CancellationToken,
) -> Result<()> {
    let schema = flow_schema();

    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/vnd.apache.parquet"),
    );
    headers.insert(
        "X-Sensor-Type",
        header::HeaderValue::from_str(&cfg.global.sensor_type)?,
    );
    headers.insert(
        "X-Sensor-Name",
        header::HeaderValue::from_str(&cfg.global.sensor_name)?,
    );

    let mut client_builder = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .https_only(true);

    if cfg.nexus.tls.enabled {
        match cfg.nexus.tls.ca_path.as_deref() {
            None | Some("") => {
                anyhow::bail!("nexus.tls.enabled = true but nexus.tls.ca_path is not configured");
            }
            Some(ca_path) => {
                let cert_bytes = std::fs::read(ca_path)
                    .with_context(|| format!("Failed to read TLS CA cert: {}", ca_path))?;
                let cert = reqwest::Certificate::from_pem(&cert_bytes)
                    .with_context(|| format!("Failed to parse TLS CA cert: {}", ca_path))?;
                client_builder = client_builder.add_root_certificate(cert);
            }
        }
    }

    let client = client_builder.build()?;
    let batch_size    = cfg.nexus.transmit_batch_size;
    let max_backoff   = Duration::from_secs(cfg.nexus.max_backoff_sec);
    let base_interval = Duration::from_secs(cfg.nexus.poll_interval_sec);
    let retention_sec = cfg.nexus.cache_retention_sec;
    let row_group_size = cfg.nexus.parquet_row_group_size;

    let mut current_backoff = base_interval;
    let mut last_prune      = Instant::now();

    // -- Integrity: sequence counter ------------------------------------------
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS integrity_sequence (
            sensor_id     TEXT    PRIMARY KEY,
            last_sequence INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(&db_pool)
    .await?;

    let sensor_id = format!("{}-{}", cfg.global.sensor_name, cfg.global.sensor_type);

    let initial_seq: u64 = sqlx::query(
        "SELECT last_sequence FROM integrity_sequence WHERE sensor_id = ?",
    )
    .bind(&sensor_id)
    .fetch_optional(&db_pool)
    .await?
    .map(|row| row.get::<i64, _>("last_sequence") as u64)
    .unwrap_or(0);

    sqlx::query(
        "INSERT OR IGNORE INTO integrity_sequence (sensor_id, last_sequence) VALUES (?, ?)",
    )
    .bind(&sensor_id)
    .bind(initial_seq as i64)
    .execute(&db_pool)
    .await?;

    // integrity_secret is validated as non-empty in config::load()
    let integrity_secret = cfg.nexus.integrity_secret.as_deref().unwrap_or_default();
    let mut stamper = LineageStamper::new(
        sensor_id.clone(),
        integrity_secret.as_bytes(),
        initial_seq,
    );

    info!(sensor_id = %sensor_id, seq = initial_seq, url = %cfg.nexus.gateway_url, "Nexus transmitter started");

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("Nexus transmitter caught cancellation. Exiting.");
                break;
            }
            _ = tokio::time::sleep(current_backoff) => {}
        }

        // Inner drain loop -- exhaust the spool before sleeping again
        loop {
            if cancel_token.is_cancelled() {
                break;
            }

            // Fetch by rowid order -- enables efficient max-rowid UPDATE
            let rows_res = sqlx::query(
                "SELECT rowid, session_id, timestamp_start, timestamp_end, session_duration_ms, \
                 src_ip, dst_ip, src_port, dst_port, protocol, protocol_name, \
                 bytes_src, bytes_dst, data_bytes_src, data_bytes_dst, packets_src, packets_dst, \
                 byte_ratio, avg_inter_arrival, variance_inter_arrival, \
                 ratio_small_packets, ratio_large_packets, packet_size_entropy, \
                 tcp_syn, tcp_rst, tcp_fin, dns_query, dns_status, \
                 http_method, http_uri, http_useragent, http_status_code, \
                 tls_ja3, tls_ja3s, tls_version, tls_cipher, \
                 cert_cn, cert_issuer_cn, cert_self_signed, cert_valid_days, \
                 hostname, src_geo_country, dst_geo_country, dst_asn_org, \
                 is_internal_dst, port_class \
                 FROM flows WHERE transmitted = 0 ORDER BY rowid ASC LIMIT ?",
            )
            .bind(batch_size as i64)
            .fetch_all(&db_pool)
            .await;

            match rows_res {
                Ok(rows) if !rows.is_empty() => {
                    let row_count = rows.len();

                    // Track the highest rowid for the single-query UPDATE
                    let max_rowid: i64 = rows.iter()
                        .filter_map(|r| r.try_get::<i64, _>("rowid").ok())
                        .max()
                        .unwrap_or(0);

                    // Optionally sort by timestamp for DuckDB predicate pushdown
                    let mut rows = rows;
                    if cfg.nexus.transmit_sort_by_timestamp {
                        rows.sort_by_key(|r| r.try_get::<i64, _>("timestamp_start").unwrap_or(0));
                    }

                    let (partition_date, partition_hour) = extract_partition_hints(&rows);

                    // -- Build Arrow arrays -----------------------------------
                    let mut session_id_b    = StringBuilder::with_capacity(row_count, row_count * 36);
                    let mut src_ip_b        = StringBuilder::with_capacity(row_count, row_count * 15);
                    let mut dst_ip_b        = StringBuilder::with_capacity(row_count, row_count * 15);
                    let mut src_port_b      = UInt16Builder::with_capacity(row_count);
                    let mut dst_port_b      = UInt16Builder::with_capacity(row_count);
                    let mut protocol_b      = UInt32Builder::with_capacity(row_count);
                    let mut protocol_name_b = StringBuilder::with_capacity(row_count, row_count * 5);
                    let mut ts_start_b      = UInt64Builder::with_capacity(row_count);
                    let mut ts_end_b        = UInt64Builder::with_capacity(row_count);
                    let mut dur_b           = UInt64Builder::with_capacity(row_count);
                    let mut by_src_b        = UInt64Builder::with_capacity(row_count);
                    let mut by_dst_b        = UInt64Builder::with_capacity(row_count);
                    let mut dby_src_b       = UInt64Builder::with_capacity(row_count);
                    let mut dby_dst_b       = UInt64Builder::with_capacity(row_count);
                    let mut pk_src_b        = UInt32Builder::with_capacity(row_count);
                    let mut pk_dst_b        = UInt32Builder::with_capacity(row_count);
                    let mut byte_ratio_b    = Float64Builder::with_capacity(row_count);
                    let mut avg_ia_b        = Float64Builder::with_capacity(row_count);
                    let mut var_ia_b        = Float64Builder::with_capacity(row_count);
                    let mut rsmall_b        = Float64Builder::with_capacity(row_count);
                    let mut rlarge_b        = Float64Builder::with_capacity(row_count);
                    let mut entropy_b       = Float64Builder::with_capacity(row_count);
                    let mut tcp_syn_b       = UInt32Builder::with_capacity(row_count);
                    let mut tcp_rst_b       = UInt32Builder::with_capacity(row_count);
                    let mut tcp_fin_b       = UInt32Builder::with_capacity(row_count);
                    let mut dns_q_b         = StringBuilder::new();
                    let mut dns_s_b         = StringBuilder::new();
                    let mut http_m_b        = StringBuilder::new();
                    let mut http_u_b        = StringBuilder::new();
                    let mut http_ua_b       = StringBuilder::new();
                    let mut http_sc_b       = UInt16Builder::with_capacity(row_count);
                    let mut ja3_b           = StringBuilder::new();
                    let mut ja3s_b          = StringBuilder::new();
                    let mut tlsv_b          = StringBuilder::new();
                    let mut tlsc_b          = StringBuilder::new();
                    let mut ccn_b           = StringBuilder::new();
                    let mut cicn_b          = StringBuilder::new();
                    let mut css_b           = BooleanBuilder::with_capacity(row_count);
                    let mut cvd_b           = Int32Builder::with_capacity(row_count);
                    let mut host_b          = StringBuilder::new();
                    let mut sgeo_b          = StringBuilder::new();
                    let mut dgeo_b          = StringBuilder::new();
                    let mut dasn_b          = StringBuilder::new();
                    let mut sname_b         = StringBuilder::with_capacity(row_count, row_count * 20);
                    let mut stype_b         = StringBuilder::with_capacity(row_count, row_count * 12);
                    let mut is_internal_b   = BooleanBuilder::with_capacity(row_count);
                    let mut port_class_b    = StringBuilder::with_capacity(row_count, row_count * 10);
                    let mut sver_b          = StringBuilder::with_capacity(row_count, row_count * 2);

                    macro_rules! append_opt_str {
                        ($row:expr, $builder:expr, $col:expr) => {
                            match $row.try_get::<Option<String>, _>($col) {
                                Ok(Some(v)) if !v.is_empty() => $builder.append_value(v),
                                _ => $builder.append_null(),
                            }
                        };
                    }

                    for row in &rows {
                        session_id_b.append_value(
                            row.try_get::<String, _>("session_id").unwrap_or_default()
                        );
                        src_ip_b.append_value(
                            row.try_get::<String, _>("src_ip").unwrap_or_default()
                        );
                        dst_ip_b.append_value(
                            row.try_get::<String, _>("dst_ip").unwrap_or_default()
                        );
                        src_port_b.append_value(
                            row.try_get::<i32, _>("src_port").unwrap_or(0) as u16
                        );
                        dst_port_b.append_value(
                            row.try_get::<i32, _>("dst_port").unwrap_or(0) as u16
                        );
                        protocol_b.append_value(
                            row.try_get::<i32, _>("protocol").unwrap_or(0) as u32
                        );
                        protocol_name_b.append_value(
                            row.try_get::<String, _>("protocol_name").unwrap_or_default()
                        );

                        ts_start_b.append_value(
                            row.try_get::<i64, _>("timestamp_start").unwrap_or(0) as u64
                        );
                        ts_end_b.append_value(
                            row.try_get::<i64, _>("timestamp_end").unwrap_or(0) as u64
                        );
                        dur_b.append_value(
                            row.try_get::<i64, _>("session_duration_ms").unwrap_or(0) as u64
                        );

                        by_src_b.append_value(
                            row.try_get::<i64, _>("bytes_src").unwrap_or(0) as u64
                        );
                        by_dst_b.append_value(
                            row.try_get::<i64, _>("bytes_dst").unwrap_or(0) as u64
                        );
                        dby_src_b.append_value(
                            row.try_get::<i64, _>("data_bytes_src").unwrap_or(0) as u64
                        );
                        dby_dst_b.append_value(
                            row.try_get::<i64, _>("data_bytes_dst").unwrap_or(0) as u64
                        );
                        pk_src_b.append_value(
                            row.try_get::<i64, _>("packets_src").unwrap_or(0) as u32
                        );
                        pk_dst_b.append_value(
                            row.try_get::<i64, _>("packets_dst").unwrap_or(0) as u32
                        );

                        byte_ratio_b.append_value(
                            row.try_get::<f64, _>("byte_ratio").unwrap_or(0.0)
                        );
                        avg_ia_b.append_value(
                            row.try_get::<f64, _>("avg_inter_arrival").unwrap_or(0.0)
                        );
                        var_ia_b.append_value(
                            row.try_get::<f64, _>("variance_inter_arrival").unwrap_or(0.0)
                        );
                        rsmall_b.append_value(
                            row.try_get::<f64, _>("ratio_small_packets").unwrap_or(0.0)
                        );
                        rlarge_b.append_value(
                            row.try_get::<f64, _>("ratio_large_packets").unwrap_or(0.0)
                        );
                        entropy_b.append_value(
                            row.try_get::<f64, _>("packet_size_entropy").unwrap_or(0.0)
                        );

                        match row.try_get::<Option<i64>, _>("tcp_syn") {
                            Ok(Some(v)) => tcp_syn_b.append_value(v as u32),
                            _ => tcp_syn_b.append_null(),
                        }
                        match row.try_get::<Option<i64>, _>("tcp_rst") {
                            Ok(Some(v)) => tcp_rst_b.append_value(v as u32),
                            _ => tcp_rst_b.append_null(),
                        }
                        match row.try_get::<Option<i64>, _>("tcp_fin") {
                            Ok(Some(v)) => tcp_fin_b.append_value(v as u32),
                            _ => tcp_fin_b.append_null(),
                        }

                        append_opt_str!(row, dns_q_b,   "dns_query");
                        append_opt_str!(row, dns_s_b,   "dns_status");
                        append_opt_str!(row, http_m_b,  "http_method");
                        append_opt_str!(row, http_u_b,  "http_uri");
                        append_opt_str!(row, http_ua_b, "http_useragent");

                        match row.try_get::<Option<i32>, _>("http_status_code") {
                            Ok(Some(v)) if v > 0 => http_sc_b.append_value(v as u16),
                            _ => http_sc_b.append_null(),
                        }

                        append_opt_str!(row, ja3_b,  "tls_ja3");
                        append_opt_str!(row, ja3s_b, "tls_ja3s");
                        append_opt_str!(row, tlsv_b, "tls_version");
                        append_opt_str!(row, tlsc_b, "tls_cipher");
                        append_opt_str!(row, ccn_b,  "cert_cn");
                        append_opt_str!(row, cicn_b, "cert_issuer_cn");

                        match row.try_get::<Option<i32>, _>("cert_self_signed") {
                            Ok(Some(v)) => css_b.append_value(v != 0),
                            _ => css_b.append_null(),
                        }
                        match row.try_get::<Option<i32>, _>("cert_valid_days") {
                            Ok(Some(v)) => cvd_b.append_value(v),
                            _ => cvd_b.append_null(),
                        }

                        append_opt_str!(row, host_b, "hostname");
                        append_opt_str!(row, sgeo_b, "src_geo_country");
                        append_opt_str!(row, dgeo_b, "dst_geo_country");
                        append_opt_str!(row, dasn_b, "dst_asn_org");

                        sname_b.append_value(&cfg.global.sensor_name);
                        stype_b.append_value(&cfg.global.sensor_type);

                        let is_int = row.try_get::<i32, _>("is_internal_dst").unwrap_or(0) != 0;
                        is_internal_b.append_value(is_int);
                        port_class_b.append_value(
                            row.try_get::<String, _>("port_class")
                                .unwrap_or_else(|_| "well_known".into())
                        );
                        sver_b.append_value(SCHEMA_VERSION);
                    }

                    // -- Serialize to Parquet ---------------------------------
                    let columns: Vec<Arc<dyn arrow::array::Array>> = vec![
                        Arc::new(session_id_b.finish()),
                        Arc::new(src_ip_b.finish()),
                        Arc::new(dst_ip_b.finish()),
                        Arc::new(src_port_b.finish()),
                        Arc::new(dst_port_b.finish()),
                        Arc::new(protocol_b.finish()),
                        Arc::new(protocol_name_b.finish()),
                        Arc::new(ts_start_b.finish()),
                        Arc::new(ts_end_b.finish()),
                        Arc::new(dur_b.finish()),
                        Arc::new(by_src_b.finish()),
                        Arc::new(by_dst_b.finish()),
                        Arc::new(dby_src_b.finish()),
                        Arc::new(dby_dst_b.finish()),
                        Arc::new(pk_src_b.finish()),
                        Arc::new(pk_dst_b.finish()),
                        Arc::new(byte_ratio_b.finish()),
                        Arc::new(avg_ia_b.finish()),
                        Arc::new(var_ia_b.finish()),
                        Arc::new(rsmall_b.finish()),
                        Arc::new(rlarge_b.finish()),
                        Arc::new(entropy_b.finish()),
                        Arc::new(tcp_syn_b.finish()),
                        Arc::new(tcp_rst_b.finish()),
                        Arc::new(tcp_fin_b.finish()),
                        Arc::new(dns_q_b.finish()),
                        Arc::new(dns_s_b.finish()),
                        Arc::new(http_m_b.finish()),
                        Arc::new(http_u_b.finish()),
                        Arc::new(http_ua_b.finish()),
                        Arc::new(http_sc_b.finish()),
                        Arc::new(ja3_b.finish()),
                        Arc::new(ja3s_b.finish()),
                        Arc::new(tlsv_b.finish()),
                        Arc::new(tlsc_b.finish()),
                        Arc::new(ccn_b.finish()),
                        Arc::new(cicn_b.finish()),
                        Arc::new(css_b.finish()),
                        Arc::new(cvd_b.finish()),
                        Arc::new(host_b.finish()),
                        Arc::new(sgeo_b.finish()),
                        Arc::new(dgeo_b.finish()),
                        Arc::new(dasn_b.finish()),
                        Arc::new(sname_b.finish()),
                        Arc::new(stype_b.finish()),
                        Arc::new(is_internal_b.finish()),
                        Arc::new(port_class_b.finish()),
                        Arc::new(sver_b.finish()),
                    ];

                    // Wrap Arrow+Parquet operations so errors don't abort the process
                    let parquet_buffer: Vec<u8> = match (|| -> Result<Vec<u8>> {
                        let rb = RecordBatch::try_new(schema.clone(), columns)
                            .context("Arrow RecordBatch construction failed")?;
                        let props = WriterProperties::builder()
                            .set_compression(Compression::ZSTD(Default::default()))
                            .set_max_row_group_size(row_group_size)
                            .build();
                        let mut buf = Vec::new();
                        let mut writer = ArrowWriter::try_new(&mut buf, schema.clone(), Some(props))
                            .context("Parquet ArrowWriter init failed")?;
                        writer.write(&rb).context("Parquet write failed")?;
                        writer.close().context("Parquet writer close failed")?;
                        Ok(buf)
                    })() {
                        Ok(buf) => buf,
                        Err(e) => {
                            error!("Parquet serialization error: {}", e);
                            counter!("gateway.nexus_serialize_errors").increment(1);
                            current_backoff = std::cmp::min(current_backoff * 2, max_backoff);
                            break;
                        }
                    };

                    // -- Stamp and persist sequence before sending ------------
                    let stamp = stamper.stamp(&parquet_buffer);
                    if let Err(e) = sqlx::query(
                        "UPDATE integrity_sequence SET last_sequence = ? WHERE sensor_id = ?",
                    )
                    .bind(stamp.sequence as i64)
                    .bind(&sensor_id)
                    .execute(&db_pool)
                    .await
                    {
                        // Log but proceed -- a sequence gap is visible to the upstream
                        // and will be flagged as a monitoring event, not a hard failure
                        warn!("Sequence {} persistence failed (gap will be visible): {}", stamp.sequence, e);
                        counter!("gateway.nexus_sequence_sync_failures").increment(1);
                    }

                    debug!(
                        rows  = row_count,
                        bytes = parquet_buffer.len(),
                        seq   = stamp.sequence,
                        "Dispatching Parquet payload"
                    );

                    // -- HTTPS POST -------------------------------------------
                    let response = client
                        .post(&cfg.nexus.gateway_url)
                        .bearer_auth(&cfg.nexus.auth_token)
                        .header(HDR_BATCH_SEQUENCE, stamp.sequence.to_string())
                        .header(HDR_BATCH_TIMESTAMP, stamp.timestamp.to_string())
                        .header(HDR_SENSOR_ID, &stamp.sensor_id)
                        .header(HDR_BATCH_HMAC, &stamp.hmac_hex)
                        .header("X-Partition-Date", &partition_date)
                        .header("X-Partition-Hour", &partition_hour)
                        .body(parquet_buffer)
                        .send()
                        .await;

                    match response {
                        Ok(resp) if resp.status().is_success() => {
                            current_backoff = base_interval;
                            counter!("gateway.nexus_rows_transmitted").increment(row_count as u64);
                            counter!("gateway.nexus_payloads_sent").increment(1);

                            // Mark transmitted using max rowid -- avoids building a
                            // dynamic IN clause on every cycle
                            if let Err(e) = sqlx::query(
                                "UPDATE flows SET transmitted = 1 \
                                 WHERE transmitted = 0 AND rowid <= ?",
                            )
                            .bind(max_rowid)
                            .execute(&db_pool)
                            .await
                            {
                                error!("Failed to mark rows transmitted: {}", e);
                            }
                        }
                        Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                            error!(
                                "[INTEGRITY] Gateway returned 403 FORBIDDEN -- sensor may be banned."
                            );
                            counter!("gateway.nexus_integrity_bans").increment(1);
                            break;
                        }
                        Ok(resp) => {
                            warn!(status = %resp.status(), "Gateway rejected payload; backing off");
                            counter!("gateway.nexus_rejections").increment(1);
                            current_backoff = std::cmp::min(current_backoff * 2, max_backoff);
                            break;
                        }
                        Err(e) => {
                            if current_backoff.as_secs() <= 10 {
                                error!("Gateway unreachable: {}. Backing off.", e);
                            }
                            counter!("gateway.nexus_connection_errors").increment(1);
                            current_backoff = std::cmp::min(current_backoff * 2, max_backoff);
                            break;
                        }
                    }

                    if row_count < batch_size as usize {
                        break; // Spool drained
                    }
                    tokio::task::yield_now().await;
                }
                Ok(_) => break, // No untransmitted rows
                Err(e) => {
                    error!("Failed to poll SQLite for untransmitted flows: {}", e);
                    break;
                }
            }
        }

        // -- Hourly maintenance: prune transmitted rows + checkpoint WAL ------
        if last_prune.elapsed().as_secs() >= 3600 {
            let cutoff = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64
                - (retention_sec as i64 * 1000);

            match sqlx::query(
                "DELETE FROM flows WHERE transmitted = 1 AND timestamp_start < ?",
            )
            .bind(cutoff)
            .execute(&db_pool)
            .await
            {
                Ok(r) => info!(deleted = r.rows_affected(), "Pruned old transmitted flows"),
                Err(e) => error!("SQLite prune fault: {}", e),
            }

            // TRUNCATE reclaims WAL disk space -- PASSIVE can be blocked indefinitely
            let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&db_pool)
                .await;

            last_prune = Instant::now();
        }
    }

    Ok(())
}