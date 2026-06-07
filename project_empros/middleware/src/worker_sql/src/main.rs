// Middleware Worker: Parquet → JSON array → SQL Server stored procedure

use bytes::Bytes;
use lib_etl::{read_parquet_batches, row_to_json};
use lib_middleware::ParquetWorker;
use metrics::{counter, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::Deserialize;
use serde_json::Value;
use std::{fs, sync::Arc, time::Duration};
use tiberius::{AuthMethod, Client, Config as TdsConfig, EncryptionLevel};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

#[derive(Deserialize)]
struct Config {
    global: GlobalConf,
    sql: SqlConf,
}

#[derive(Deserialize, Clone)]
struct GlobalConf {
    nats_url: String,
    stream_name: String,
    telemetry_subject: String,
    dlq_subject_prefix: String,
}

#[derive(Deserialize, Clone)]
struct SqlConf {
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    database: String,
    #[serde(default)]
    use_sspi: bool,
    user: Option<String>,
    pass: Option<String>,
    #[serde(default = "default_encryption")]
    encryption: String,
    #[serde(default)]
    trust_server_cert: bool,
    sproc: String,
    #[serde(default = "default_batch")]
    batch_size: usize,
    test_webhook_url: Option<String>,
    #[serde(default = "default_pool_size")]
    pool_size: u32,
    #[serde(default = "default_connect_timeout")]
    connect_timeout_sec: u64,
}

fn default_port() -> u16 { 1433 }
fn default_batch() -> usize { 2000 }
fn default_encryption() -> String { "Required".into() }
fn default_pool_size() -> u32 { 4 }
fn default_connect_timeout() -> u64 { 10 }

// ═══ Connection pool manager for tiberius ═══════════════════════════════════

struct TdsConnectionManager {
    config: TdsConfig,
}

impl TdsConnectionManager {
    fn new(sql_conf: &SqlConf) -> Result<Self, String> {
        let mut config = TdsConfig::new();
        config.host(&sql_conf.host);
        config.port(sql_conf.port);
        config.database(&sql_conf.database);
        config.trust_cert_self_signed(sql_conf.trust_server_cert);

        match sql_conf.encryption.to_lowercase().as_str() {
            "required" => config.encryption(EncryptionLevel::Required),
            "off" | "none" => config.encryption(EncryptionLevel::Off),
            _ => config.encryption(EncryptionLevel::Required),
        };

        if sql_conf.use_sspi {
            // SSPI (Windows Integrated Auth)
            #[cfg(windows)]
            config.authentication(AuthMethod::Integrated);
            #[cfg(not(windows))]
            return Err("SSPI auth requires Windows. Use sql_auth with user/pass on Linux.".into());
        } else {
            let user = sql_conf.user.as_deref().ok_or("sql.user required when use_sspi=false")?;
            let pass = sql_conf.pass.as_deref().ok_or("sql.pass required when use_sspi=false")?;
            config.authentication(AuthMethod::sql_server(user, pass));
        }

        Ok(Self { config })
    }

    async fn connect(&self) -> Result<Client<tokio_util::compat::Compat<TcpStream>>, tiberius::error::Error> {
        let tcp = TcpStream::connect(self.config.get_addr()).await?;
        tcp.set_nodelay(true)?;
        let client = Client::connect(self.config.clone(), tcp.compat_write()).await?;
        Ok(client)
    }
}

// ═══ Backend enum ═══════════════════════════════════════════════════════════

enum Backend {
    Tds {
        manager: TdsConnectionManager,
        sproc: String,
    },
    Webhook {
        client: reqwest::Client,
        url: String,
    },
    NotAvailable,
}

// ═══ Worker implementation ══════════════════════════════════════════════════

struct SqlWorker {
    backend: Backend,
    batch_size: usize,
}

impl ParquetWorker for SqlWorker {
    fn batch_size(&self) -> usize {
        self.batch_size
    }

    async fn transmit_batch(
        &self,
        payloads: Vec<(Bytes, Option<async_nats::HeaderMap>)>,
    ) -> Result<(), String> {
        let mut json_events = Vec::new();
        for (payload, headers) in &payloads {
            let sensor_type = headers
                .as_ref()
                .and_then(|h| h.get("X-Sensor-Type").map(|v| v.to_string()))
                .unwrap_or_default();

            let batches = read_parquet_batches(payload).map_err(|e| format!("Parquet: {}", e))?;
            for batch in &batches {
                for row in 0..batch.num_rows() {
                    let mut event = row_to_json(batch, row);
                    if !sensor_type.is_empty() {
                        event
                            .entry("sensor_type".to_string())
                            .or_insert(Value::String(sensor_type.clone()));
                    }
                    json_events.push(Value::Object(event));
                }
            }
        }

        if json_events.is_empty() {
            return Ok(());
        }

        let event_count = json_events.len();
        let json_array =
            serde_json::to_string(&json_events).map_err(|e| format!("JSON serialize: {}", e))?;

        match &self.backend {
            Backend::Tds { manager, sproc } => {
                let tx_start = std::time::Instant::now();

                let mut client = manager
                    .connect()
                    .await
                    .map_err(|e| format!("TDS connect: {}", e))?;

                let result = client
                    .execute(sproc, &[&json_array.as_str()])
                    .await
                    .map_err(|e| format!("TDS exec: {}", e))?;

                let mut total_inserted = 0i64;
                let mut total_rejected = 0i64;
                let mut sproc_duration_ms = 0i64;

                for row in result.into_first_result().await.map_err(|e| format!("TDS result: {}", e))? {
                    total_inserted = row.get::<i32, _>("endpoint_inserted").unwrap_or(0) as i64
                        + row.get::<i32, _>("cloud_inserted").unwrap_or(0) as i64
                        + row.get::<i32, _>("network_inserted").unwrap_or(0) as i64;
                    total_rejected = row.get::<i32, _>("rejected").unwrap_or(0) as i64;
                    sproc_duration_ms = row.get::<i32, _>("duration_ms").unwrap_or(0) as i64;
                }

                let client_duration_ms = tx_start.elapsed().as_millis() as f64;
                histogram!("middleware_sql_sproc_duration_ms", sproc_duration_ms as f64);
                histogram!("middleware_sql_round_trip_ms", client_duration_ms);
                counter!("middleware_sql_events_sent_total", total_inserted as u64);

                if total_rejected > 0 {
                    warn!(
                        "SQL sproc: {}/{} events rejected (sproc {}ms, round-trip {}ms)",
                        total_rejected, event_count, sproc_duration_ms, client_duration_ms as i64
                    );
                    counter!("middleware_sql_events_rejected_total", total_rejected as u64);
                } else {
                    info!(
                        "SQL sproc: {} events inserted (sproc {}ms, round-trip {}ms)",
                        total_inserted, sproc_duration_ms, client_duration_ms as i64
                    );
                }

                Ok(())
            }

            Backend::Webhook { client, url } => {
                let res = client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(json_array)
                    .send()
                    .await
                    .map_err(|e| format!("Webhook: {}", e))?;

                if res.status().is_success() {
                    counter!("middleware_sql_events_sent_total", event_count as u64);
                    info!("Webhook: {} events sent", event_count);
                    Ok(())
                } else {
                    Err(format!("Webhook HTTP {}", res.status()))
                }
            }

            Backend::NotAvailable => Err(
                "SQL backend not configured. Set sql.user/pass for TDS or sql.test_webhook_url for QA."
                    .into(),
            ),
        }
    }
}

// ═══ Main ═══════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .with_target(false)
        .init();

    let metrics_port: u16 = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9013);
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], metrics_port))
        .install()
        .unwrap();

    let config_path =
        std::env::var("MIDDLEWARE_CONFIG").unwrap_or_else(|_| "/config/middleware.toml".to_string());
    let raw = fs::read_to_string(&config_path).unwrap();
    let conf: Config = toml::from_str(&raw).unwrap();

    let backend = if let Some(url) = &conf.sql.test_webhook_url {
        if !url.is_empty() {
            info!("[SQL] TEST MODE → {}", url);
            Backend::Webhook {
                client: reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .timeout(Duration::from_secs(10))
                    .build()
                    .unwrap(),
                url: url.clone(),
            }
        } else {
            try_build_tds(&conf.sql)
        }
    } else {
        try_build_tds(&conf.sql)
    };

    match &backend {
        Backend::Tds { .. } => info!(
            "[SQL] TDS mode → {}:{}/{}",
            conf.sql.host, conf.sql.port, conf.sql.database
        ),
        Backend::Webhook { url, .. } => info!("[SQL] Webhook mode → {}", url),
        Backend::NotAvailable => {
            error!("[SQL] No backend configured. Set user/pass for TDS or test_webhook_url for QA.");
            error!("[SQL] Worker will route all batches to DLQ.");
        }
    }

    let worker = SqlWorker {
        backend,
        batch_size: conf.sql.batch_size,
    };

    info!("SQL worker starting | Metrics :{}", metrics_port);
    let subject_filter = format!("{}.*", conf.global.telemetry_subject);
    lib_middleware::start_worker(
        worker,
        &conf.global.nats_url,
        &conf.global.stream_name,
        &subject_filter,
        "Middleware_SQL_Group",
        &conf.global.dlq_subject_prefix,
    )
    .await;
}

fn try_build_tds(sql_conf: &SqlConf) -> Backend {
    match TdsConnectionManager::new(sql_conf) {
        Ok(manager) => {
            info!(
                "[SQL] TDS connection manager ready for {}:{}/{}",
                sql_conf.host, sql_conf.port, sql_conf.database
            );
            Backend::Tds {
                manager,
                sproc: sql_conf.sproc.clone(),
            }
        }
        Err(e) => {
            error!("[SQL] TDS init failed: {}", e);
            Backend::NotAvailable
        }
    }
}