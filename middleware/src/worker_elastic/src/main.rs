use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use lib_etl::{read_parquet_batches, row_to_json, apply_mapping};
use lib_etl::schema::SchemaRegistry;
use lib_middleware::ParquetWorker;
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::header;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{fs, sync::Arc, time::Duration};
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

#[derive(Deserialize)]
struct Config { global: GlobalConf, elastic: ElasticConf, schemas: SchemasConf }

#[derive(Deserialize)]
struct GlobalConf { nats_url: String, stream_name: String, telemetry_subject: String, dlq_subject_prefix: String }

#[derive(Deserialize)]
struct ElasticConf {
    host: String,
    index_endpoint: String,
    index_cloud: String,
    index_network: String,
    #[serde(default = "default_fallback_index")]
    index_default: String,
    auth: Option<String>,
    #[serde(default)]
    pipeline: Option<String>,
    #[serde(default = "default_batch")] batch_size: usize,
    #[serde(default = "default_timeout")] timeout_seconds: u64,
    #[serde(default)] verify_tls: bool,
}

#[derive(Deserialize)]
struct SchemasConf { ecs_mappings_file: String }
fn default_batch() -> usize { 1000 }
fn default_timeout() -> u64 { 15 }
fn default_fallback_index() -> String { "nexus-telemetry".into() }

struct ElasticWorker {
    client: reqwest::Client,
    bulk_url: String,
    index_endpoint: String,
    index_cloud: String,
    index_network: String,
    index_default: String,
    batch_size: usize,
    schema_registry: Arc<SchemaRegistry>,
}

impl ElasticWorker {
    /// Route sensor_type to the correct Elastic data stream.
    fn resolve_index(&self, sensor_type: &str) -> &str {
        match sensor_type {
            "linux-c2-sensor" | "Linux-Sentinel" | "windows_deepsensor" | "c2sensor"
            | "sysmon_sensor" | "trellix_ens" => &self.index_endpoint,
            "gcp_audit" | "gcp_scc" | "gcp_vpc_flow" | "vmware_syslog" => &self.index_cloud,
            "network_tap" => &self.index_network,
            s if s.contains("connector") => &self.index_cloud,
            _ => &self.index_default,
        }
    }
}

impl ParquetWorker for ElasticWorker {
    fn batch_size(&self) -> usize { self.batch_size }

    async fn transmit_batch(&self, payloads: Vec<(Bytes, Option<async_nats::HeaderMap>)>) -> Result<(), String> {
        if payloads.is_empty() { return Ok(()); }

        let mut bulk_body = String::new();
        let mut event_count = 0usize;

        for (payload, headers) in &payloads {
            let sensor_type = headers.as_ref()
                .and_then(|h| h.get("X-Sensor-Type").map(|v| v.to_string()))
                .unwrap_or_default();

            let batches = match read_parquet_batches(payload) {
                Ok(b) => b,
                Err(e) => { warn!("Corrupt Parquet: {}", e); counter!("middleware_elastic_parquet_errors_total").increment(1); continue; }
            };

            for batch in &batches {
                for row in 0..batch.num_rows() {
                    let mut raw_event = row_to_json(batch, row);
                    if !sensor_type.is_empty() {
                        raw_event.entry("sensor_type".to_string())
                            .or_insert(Value::String(sensor_type.clone()));
                    }

                    let schema = self.schema_registry.find_schema(&raw_event).await;

                    let mut ecs_doc = if let Some(s) = &schema {
                        apply_mapping(&raw_event, &s.fields)
                    } else {
                        raw_event.clone()
                    };

                    if !ecs_doc.contains_key("@timestamp") {
                        let ts = raw_event.get("timestamp")
                            .or_else(|| raw_event.get("timestamp_start"))
                            .cloned().unwrap_or(Value::Null);
                        ecs_doc.insert("@timestamp".to_string(), ts);
                    }
                    ecs_doc.insert("ecs".to_string(), json!({"version": "8.0.0"}));

                    // Route to the correct data stream by sensor_type
                    let target_index = self.resolve_index(&sensor_type);

                    // For data streams, use "create" action (append-only)
                    bulk_body.push_str(&json!({"create": {"_index": target_index}}).to_string());
                    bulk_body.push('\n');
                    bulk_body.push_str(&Value::Object(ecs_doc).to_string());
                    bulk_body.push('\n');
                    event_count += 1;
                }
            }
        }

        if bulk_body.is_empty() { return Ok(()); }

        let response = self.client.post(&self.bulk_url)
            .header(header::CONTENT_TYPE, "application/x-ndjson")
            .body(bulk_body)
            .send().await
            .map_err(|e| format!("Elastic transport: {}", e))?;

        if response.status().is_success() {
            if let Ok(body) = response.json::<Value>().await {
                if body.get("errors").and_then(|v| v.as_bool()).unwrap_or(false) {
                    let items = body.get("items").and_then(|i| i.as_array());
                    let error_count = items.map(|items| items.iter().filter(|item| {
                        item.get("create").and_then(|c| c.get("error")).is_some()
                    }).count()).unwrap_or(0);

                    if error_count > 0 {
                        counter!("middleware_elastic_item_errors_total").increment(error_count as u64);
                        warn!("Elastic bulk: {}/{} items had errors", error_count, event_count);
                    }
                }
            }
            counter!("middleware_elastic_events_sent_total").increment(event_count as u64);
            info!("Sent {} ECS events to Elastic", event_count);
            Ok(())
        } else {
            counter!("middleware_elastic_send_errors_total").increment(1);
            Err(format!("Elastic bulk HTTP {}", response.status()))
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into())).with_target(false).init();

    let metrics_port: u16 = std::env::var("METRICS_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(9011);
    PrometheusBuilder::new().with_http_listener(([0, 0, 0, 0], metrics_port)).install().unwrap();

    let config_path = std::env::var("MIDDLEWARE_CONFIG").unwrap_or_else(|_| "/config/middleware.toml".to_string());
    let raw = fs::read_to_string(&config_path).unwrap();
    let conf: Config = toml::from_str(&raw).unwrap();

    let schema_registry = Arc::new(SchemaRegistry::load(&conf.schemas.ecs_mappings_file)
        .expect("Failed to load ECS schemas"));
    let sr = Arc::clone(&schema_registry);
    tokio::spawn(async move { sr.watch_loop().await; });

    let mut default_headers = header::HeaderMap::new();
    if let Some(ref auth) = conf.elastic.auth {
        if !auth.is_empty() {
            if auth.contains(':') {
                let encoded = BASE64.encode(auth);
                default_headers.insert(header::AUTHORIZATION, format!("Basic {}", encoded).parse().unwrap());
            } else {
                default_headers.insert(header::AUTHORIZATION, format!("ApiKey {}", auth).parse().unwrap());
            }
        }
    }

    let client = reqwest::Client::builder()
        .default_headers(default_headers)
        .timeout(Duration::from_secs(conf.elastic.timeout_seconds))
        .danger_accept_invalid_certs(!conf.elastic.verify_tls)
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .build().unwrap();

    let base = conf.elastic.host.trim_end_matches('/');
    let bulk_url = match &conf.elastic.pipeline {
        Some(p) if !p.is_empty() => format!("{}/_bulk?pipeline={}", base, p),
        _ => format!("{}/_bulk", base),
    };

    let worker = ElasticWorker {
        client,
        bulk_url: bulk_url.clone(),
        index_endpoint: conf.elastic.index_endpoint,
        index_cloud: conf.elastic.index_cloud,
        index_network: conf.elastic.index_network,
        index_default: conf.elastic.index_default,
        batch_size: conf.elastic.batch_size,
        schema_registry,
    };

    info!("Elastic ECS worker starting | bulk_url={} | streams: endpoint={}, cloud={}, network={} | Metrics :{}",
        bulk_url, worker.index_endpoint, worker.index_cloud, worker.index_network, metrics_port);
    let subject_filter = format!("{}.*", conf.global.telemetry_subject);
    lib_middleware::start_worker(worker, &conf.global.nats_url, &conf.global.stream_name,
        &subject_filter, "Middleware_Elastic_ECS_Group", &conf.global.dlq_subject_prefix).await;
}