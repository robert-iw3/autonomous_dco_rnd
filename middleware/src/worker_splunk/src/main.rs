use bytes::Bytes;
use lib_etl::{read_parquet_batches, row_to_json, apply_mapping};
use lib_etl::schema::SchemaRegistry;
use lib_middleware::ParquetWorker;
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::header;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fs, sync::Arc, time::Duration};
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

#[derive(Deserialize)]
struct Config {
    global: GlobalConf,
    splunk: SplunkConf,
    schemas: SchemasConf,
}

#[derive(Deserialize)]
struct GlobalConf { nats_url: String, stream_name: String, telemetry_subject: String, dlq_subject_prefix: String }

#[derive(Deserialize)]
struct SplunkConf {
    hec_url: String,
    hec_token: String,
    index_endpoint: String,
    index_cloud: String,
    index_network: String,
    index_alerts: String,
    #[serde(default = "default_fallback_index")]
    index_default: String,
    target_sourcetype: String,
    #[serde(default = "default_batch")] batch_size: usize,
    #[serde(default = "default_timeout")] timeout_seconds: u64,
    #[serde(default)] verify_tls: bool,
    #[serde(default = "default_alert_threshold")] alert_score_threshold: i64,
}

#[derive(Deserialize)]
struct SchemasConf { cim_mappings_file: String }
fn default_batch() -> usize { 500 }
fn default_timeout() -> u64 { 15 }
fn default_fallback_index() -> String { "nexus_endpoint".into() }
fn default_alert_threshold() -> i64 { 70 }

struct SplunkWorker {
    client: reqwest::Client,
    hec_url: String,
    hec_token: String,
    index_endpoint: String,
    index_cloud: String,
    index_network: String,
    index_alerts: String,
    index_default: String,
    target_sourcetype: String,
    alert_score_threshold: i64,
    batch_size: usize,
    schema_registry: Arc<SchemaRegistry>,
}

impl SplunkWorker {
    /// Route sensor_type + score to the correct Splunk index.
    /// High-score events from any category are copied to the alerts index.
    fn resolve_index(&self, sensor_type: &str, score: Option<i64>) -> &str {
        // High-score events go to the long-retention alerts index
        if let Some(s) = score {
            if s >= self.alert_score_threshold {
                return &self.index_alerts;
            }
        }

        match sensor_type {
            "linux-c2-sensor" | "Linux-Sentinel" | "windows_deepsensor" | "c2sensor"
            | "trellix_ens" => &self.index_endpoint,
            "network_tap" => &self.index_network,
            s if s.contains("connector") => &self.index_cloud,
            _ => &self.index_default,
        }
    }
}

impl ParquetWorker for SplunkWorker {
    fn batch_size(&self) -> usize { self.batch_size }

    async fn transmit_batch(&self, payloads: Vec<(Bytes, Option<async_nats::HeaderMap>)>) -> Result<(), String> {
        if payloads.is_empty() { return Ok(()); }

        let mut hec_body: Vec<u8> = Vec::new();
        let mut event_count = 0usize;

        for (payload, headers) in &payloads {
            let sensor_type = headers.as_ref()
                .and_then(|h| h.get("X-Sensor-Type").map(|v| v.to_string()))
                .unwrap_or_default();

            let batches = match read_parquet_batches(payload) {
                Ok(b) => b,
                Err(e) => { warn!("Corrupt Parquet: {}", e); counter!("middleware_splunk_parquet_errors_total").increment(1); continue; }
            };

            for batch in &batches {
                for row in 0..batch.num_rows() {
                    let mut raw_event = row_to_json(batch, row);
                    if !sensor_type.is_empty() {
                        raw_event.entry("sensor_type".to_string())
                            .or_insert(Value::String(sensor_type.clone()));
                    }

                    let schema = self.schema_registry.find_schema(&raw_event).await;

                    let cim_event = if let Some(s) = &schema {
                        let mut mapped = apply_mapping(&raw_event, &s.fields);
                        mapped.entry("vendor_product".to_string())
                            .or_insert(Value::String("Nexus_Middleware".to_string()));
                        Value::Object(mapped)
                    } else {
                        Value::Object(raw_event.clone())
                    };

                    let timestamp = raw_event.get("timestamp")
                        .or_else(|| raw_event.get("timestamp_start"))
                        .cloned().unwrap_or(Value::Null);

                    let sourcetype = schema.as_ref()
                        .and_then(|s| s.fields.get("sourcetype"))
                        .map(|v| v.trim_matches('"').to_string())
                        .unwrap_or_else(|| self.target_sourcetype.clone());

                    // Extract score for alert-index routing
                    let score = raw_event.get("score")
                        .and_then(|v| v.as_i64());

                    let index = self.resolve_index(&sensor_type, score);

                    let hec_event = json!({
                        "time": timestamp,
                        "index": index,
                        "sourcetype": sourcetype,
                        "event": cim_event
                    });

                    hec_body.extend_from_slice(hec_event.to_string().as_bytes());
                    hec_body.push(b'\n');
                    event_count += 1;
                }
            }
        }

        if hec_body.is_empty() { return Ok(()); }

        let response = self.client.post(&self.hec_url)
            .header(header::AUTHORIZATION, format!("Splunk {}", self.hec_token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(hec_body)
            .send().await
            .map_err(|e| format!("Splunk HEC transport: {}", e))?;

        if response.status().is_success() {
            if let Ok(body) = response.json::<Value>().await {
                let code = body.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                if code != 0 {
                    let text = body.get("text").and_then(|t| t.as_str()).unwrap_or("unknown");
                    warn!("Splunk HEC code {}: {}", code, text);
                    counter!("middleware_splunk_hec_errors_total").increment(1);
                    return Err(format!("Splunk HEC error code {}: {}", code, text));
                }
            }
            counter!("middleware_splunk_events_sent_total").increment(event_count as u64);
            info!("Sent {} CIM events to Splunk", event_count);
            Ok(())
        } else {
            counter!("middleware_splunk_send_errors_total").increment(1);
            Err(format!("Splunk HEC HTTP {}", response.status()))
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into())).with_target(false).init();

    let metrics_port: u16 = std::env::var("METRICS_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(9010);
    PrometheusBuilder::new().with_http_listener(([0, 0, 0, 0], metrics_port)).install().unwrap();

    let config_path = std::env::var("MIDDLEWARE_CONFIG").unwrap_or_else(|_| "/config/middleware.toml".to_string());
    let raw = fs::read_to_string(&config_path).unwrap();
    let conf: Config = toml::from_str(&raw).unwrap();

    let schema_registry = Arc::new(SchemaRegistry::load(&conf.schemas.cim_mappings_file)
        .expect("Failed to load CIM schemas"));
    let sr = Arc::clone(&schema_registry);
    tokio::spawn(async move { sr.watch_loop().await; });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(conf.splunk.timeout_seconds))
        .danger_accept_invalid_certs(!conf.splunk.verify_tls)
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .build().unwrap();

    let worker = SplunkWorker {
        client,
        hec_url: conf.splunk.hec_url,
        hec_token: conf.splunk.hec_token,
        index_endpoint: conf.splunk.index_endpoint,
        index_cloud: conf.splunk.index_cloud,
        index_network: conf.splunk.index_network,
        index_alerts: conf.splunk.index_alerts,
        index_default: conf.splunk.index_default,
        target_sourcetype: conf.splunk.target_sourcetype,
        alert_score_threshold: conf.splunk.alert_score_threshold,
        batch_size: conf.splunk.batch_size,
        schema_registry,
    };

    info!("Splunk CIM worker starting | indexes: endpoint={}, cloud={}, network={}, alerts={} | Metrics :{}",
        worker.index_endpoint, worker.index_cloud, worker.index_network, worker.index_alerts, metrics_port);
    let subject_filter = format!("{}.*", conf.global.telemetry_subject);
    lib_middleware::start_worker(worker, &conf.global.nats_url, &conf.global.stream_name,
        &subject_filter, "Middleware_Splunk_CIM_Group", &conf.global.dlq_subject_prefix).await;
}