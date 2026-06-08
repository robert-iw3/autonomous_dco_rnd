use async_trait::async_trait;
use bytes::Bytes;
use failsafe::{backoff, failure_policy, futures::CircuitBreaker, Config as FailsafeConfig, StateMachine};
use lib_siem_core::{start_durable_worker, SiemAdapter, WorkerConfig};
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::{fs, time::Duration};
use tracing::{error, info, info_span, Instrument, Level};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

type RedisCircuitBreaker = StateMachine<
    failsafe::failure_policy::ConsecutiveFailures<failsafe::backoff::Exponential>,
    (),
>;

#[derive(Deserialize)]
struct Config {
    global: Global,
    redis: RedisConf,
}

#[derive(Deserialize)]
struct Global {
    nats_url: String,
    telemetry_stream: String,
    telemetry_subject: String,
    dlq_subject_prefix: String,
}

#[derive(Deserialize)]
struct RedisConf {
    url: String,
    alert_queue_key: String,
}

// -- 1. OS-Agnostic Extracted Event --
#[derive(Debug, Deserialize, Serialize)]
struct ExtractedEvent {
    event_id: String,
    timestamp: f64,
    sensor_id: String,
    source_type: String,
    pid: u32,
    uid: u32,
    process_name: String,
    command_line: String,
    dest_ip: String,
    dns_query: String,
    edge_tactic: Option<String>,
    edge_technique: Option<String>,
}

struct RulesAdapter {
    redis_client: redis::Client,
    alert_queue_key: String,
    batch_size: usize,
    circuit_breaker: RedisCircuitBreaker,
}

#[async_trait]
impl SiemAdapter for RulesAdapter {
    fn initialize(config_path: &str, _nats_client: Option<async_nats::Client>) -> Self {
        let config_raw = fs::read_to_string(config_path).expect("CRITICAL: Config not found");
        let conf: Config = toml::from_str(&config_raw).expect("CRITICAL: Malformed TOML");

        let redis_client = redis::Client::open(conf.redis.url.clone())
            .expect("CRITICAL: Failed to open Redis client");

        let circuit_breaker = FailsafeConfig::new()
            .failure_policy(failure_policy::consecutive_failures(
                3,
                backoff::exponential(Duration::from_secs(2), Duration::from_secs(60)),
            ))
            .build();

        info!("Dual-Layer Deterministic Rules Engine initialized | Redis: {}", conf.redis.url);

        RulesAdapter {
            redis_client,
            alert_queue_key: conf.redis.alert_queue_key,
            batch_size: 5000,
            circuit_breaker,
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    async fn transmit_batch(
        &self,
        raw_payloads: &[Bytes],
        _nats_headers: &[Option<async_nats::HeaderMap>],
    ) -> Result<(), String> {
        if raw_payloads.is_empty() { return Ok(()); }

        let mut matched_alerts = Vec::new();

        for payload_bytes in raw_payloads {
            let builder = match parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(payload_bytes.clone()) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let schema = builder.schema().clone();
            let mut col_indices = std::collections::HashMap::new();
            for (i, field) in schema.fields().iter().enumerate() {
                col_indices.insert(field.name().to_string(), i);
            }

            let mut reader = match builder.build() {
                Ok(r) => r,
                Err(_) => continue,
            };

            while let Some(batch_result) = reader.next() {
                let batch = match batch_result { Ok(b) => b, Err(_) => continue };
                let num_rows = batch.num_rows();

                for row_idx in 0..num_rows {
                    let get_str = |col: &str| -> String {
                        if let Some(&idx) = col_indices.get(col) {
                            let column = batch.column(idx);
                            if column.is_valid(row_idx) {
                                use arrow::array::AsArray;
                                return column.as_string::<i32>().value(row_idx).to_string();
                            }
                        }
                        String::new()
                    };

                    let get_u32 = |col: &str| -> u32 {
                        if let Some(&idx) = col_indices.get(col) {
                            let column = batch.column(idx);
                            if column.is_valid(row_idx) {
                                use arrow::array::AsArray;
                                match column.data_type() {
                                    arrow::datatypes::DataType::Int32 => return column.as_primitive::<arrow::datatypes::Int32Type>().value(row_idx) as u32,
                                    arrow::datatypes::DataType::Int64 => return column.as_primitive::<arrow::datatypes::Int64Type>().value(row_idx) as u32,
                                    _ => return 0,
                                }
                            }
                        }
                        0
                    };

                    let has_col = |col: &str| col_indices.contains_key(col);

                    // -- 2. Duck-Typing --
                    let source_type = if has_col("outbound_ratio") && has_col("comm") {
                        "linux_c2"
                    } else if has_col("outbound_ratio") && has_col("Image") {
                        "windows_c2"
                    } else if has_col("shannon_entropy") {
                        "linux_sentinel"
                    } else if has_col("max_velocity") {
                        "windows_deepsensor"
                    } else if has_col("event_type") && has_col("mitre_tactic") && has_col("sensor_id") {
                        let evt = get_str("event_type");
                        match evt.as_str() {
                            "vpc_flow" | "nsg_flow" | "gcp_vpc_flow" => "cloud_network",
                            "cloudtrail_api" | "azure_activity" | "gcp_audit" => "cloud_control_plane",
                            "guardduty_finding" | "gcp_scc" => "cloud_alert",
                            "entraid_signin" | "entraid_signin_noninteractive" => "cloud_identity_signin",
                            "entraid_audit" => "cloud_identity_audit",
                            "vmware_syslog" => "cloud_network",
                            _ => "cloud_unknown",
                        }
                    } else if has_col("session_id") && has_col("tls_ja3") {
                        "network_tap"
                    } else if has_col("rule") && has_col("evt_type") {
                        "falco_runtime"
                    } else {
                        continue;
                    };

                    let edge_signature = {
                        let s1 = get_str("signature_name");
                        let s2 = get_str("message");
                        let s3 = get_str("rule");
                        if !s1.is_empty() { s1 } else if !s2.is_empty() { s2 } else { s3 }
                    };

                    let edge_tactic = {
                        let t1 = get_str("tactic");
                        let t2 = get_str("mitre_tactic");
                        if !t1.is_empty() { t1 } else { t2 }
                    };

                    let edge_technique = {
                        let t1 = get_str("technique");
                        let t2 = get_str("mitre_technique");
                        if !t1.is_empty() { t1 } else { t2 }
                    };

                    // -- 3. OS-Agnostic Extraction --
                    // sensor_id: try linux field ("sensor_id"), then Windows field ("host"),
                    // then hostname. Never use dest_ip -- that's the attack target, not the sensor.
                    let sensor_id = {
                        let id = get_str("sensor_id");
                        if !id.is_empty() { id } else {
                            let h = get_str("host");
                            if !h.is_empty() { h } else { get_str("hostname") }
                        }
                    };

                    let event = ExtractedEvent {
                        event_id: { let id1 = get_str("event_id"); if !id1.is_empty() { id1 } else { get_str("id") } },
                        timestamp: {
                            if let Some(&idx) = col_indices.get("timestamp") {
                                let column = batch.column(idx);
                                if column.is_valid(row_idx) {
                                    use arrow::array::AsArray;
                                    match column.data_type() {
                                        arrow::datatypes::DataType::Float64 => column.as_primitive::<arrow::datatypes::Float64Type>().value(row_idx),
                                        _ => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64(),
                                    }
                                } else {
                                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()
                                }
                            } else {
                                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()
                            }
                        },
                        sensor_id,
                        source_type: source_type.to_string(),
                        pid: { let p = get_u32("pid"); if p != 0 { p } else { get_u32("PID") } },
                        uid: { let u = get_u32("uid"); if u != 0 { u } else { get_u32("user_uid") } },
                        process_name: { let c = get_str("comm"); if !c.is_empty() { c } else { let i = get_str("Image"); if !i.is_empty() { i } else { get_str("proc_name") } } },
                        command_line: { let c = get_str("command_line"); if !c.is_empty() { c } else { let cl = get_str("CommandLine"); if !cl.is_empty() { cl } else { get_str("proc_cmdline") } } },
                        dest_ip: { let d = get_str("dst_ip"); if !d.is_empty() { d } else { let di = get_str("destination_ip"); if !di.is_empty() { di } else { get_str("fd_dip") } } },
                        dns_query: { let q = get_str("dns_query"); if !q.is_empty() { q } else { get_str("Query") } },
                        edge_tactic: if edge_tactic.is_empty() { None } else { Some(edge_tactic) },
                        edge_technique: if edge_technique.is_empty() { None } else { Some(edge_technique) },
                    };

                    if event.event_id.is_empty() { continue; }

                    // -- 4. DUAL-LAYER EVALUATION --

                    // LAYER A: Edge Pass-Through (O(1) Evaluation)
                    if !edge_signature.is_empty() && edge_signature != "unknown" {
                        matched_alerts.push(create_alert(&edge_signature, &event));
                        continue;
                    }

                    // LAYER B: Centralized Fallback (O(N) Evaluation)
                    let cmd_lower = event.command_line.to_lowercase();

                    // Linux LotL Web Shell
                    if (event.uid == 33 || event.uid == 48) && (event.process_name == "wget" || event.process_name == "curl") {
                        matched_alerts.push(create_alert("Web_Shell_Downloader_LotL", &event));
                        continue;
                    }

                    // Universal Suspicious DGA TLD
                    if event.dns_query.ends_with(".top") || event.dns_query.ends_with(".xyz") {
                        matched_alerts.push(create_alert("Suspicious_DGA_TLD", &event));
                        continue;
                    }

                    // -- Cloud Control Plane Rules --
                    if source_type == "cloud_control_plane" {
                        let api_action = &event.process_name;
                        for critical_action in &["StopLogging", "DeleteTrail", "DeleteDetector",
                            "DisableKey", "PutBucketPolicy", "AuthorizeSecurityGroupIngress"] {
                            if api_action.contains(critical_action) {
                                matched_alerts.push(create_alert(
                                    &format!("Cloud_Critical_API_{}", critical_action), &event));
                                break;
                            }
                        }
                    }

                    // -- Cloud Identity Rules --
                    if source_type == "cloud_identity_signin" {
                        let score: i32 = get_str("score").parse().unwrap_or(0);
                        if score >= 60 {
                            matched_alerts.push(create_alert("Entra_High_Risk_SignIn", &event));
                        }
                    }

                    // -- GuardDuty / SCC Pass-Through --
                    if source_type == "cloud_alert" {
                        let score: i32 = get_str("score").parse().unwrap_or(0);
                        if score >= 70 {
                            matched_alerts.push(create_alert("GuardDuty_High_Severity", &event));
                        }
                    }

                    // -- Network Tap Rules --
                    if source_type == "network_tap" {
                        let cert_self_signed = get_str("cert_self_signed");
                        let tls_ja3 = get_str("tls_ja3");
                        if cert_self_signed == "true" && !tls_ja3.is_empty() {
                            matched_alerts.push(create_alert("SelfSigned_TLS_With_JA3", &event));
                        }
                    }

                    // Windows Suspicious Binaries
                    for ioc in &["whoami.exe", "vssadmin.exe", "procdump.exe", "shadowcopy", "regsvr32.exe /s /u /i:"] {
                        if cmd_lower.contains(ioc) {
                            matched_alerts.push(create_alert(&format!("Suspicious_Windows_Bin_{}", ioc), &event));
                            break;
                        }
                    }
                }
            }
        }

        // -- 5. RESILIENT DISPATCH TO REDIS QUEUE --
        if !matched_alerts.is_empty() {
            let dispatch_span = info_span!("redis_dispatch", alerts_count = matched_alerts.len());

            // Obtain multiplexed connection per batch -- MultiplexedConnection is cheap to create
            // and safe to use from async context without holding across await points.
            let mut con = self.redis_client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| format!("Redis connection failed: {}", e))?;

            let alert_queue_key = self.alert_queue_key.clone();
            let alert_count = matched_alerts.len();

            let dispatch_result = self.circuit_breaker
                .call(async move {
                    for alert in &matched_alerts {
                        let _: () = con.lpush(&alert_queue_key, alert).await
                            .map_err(|e| format!("Redis LPUSH failed: {}", e))?;
                    }
                    Ok::<(), String>(())
                })
                .instrument(dispatch_span)
                .await;

            match dispatch_result {
                Ok(_) => {
                    info!("Fired {} deterministic alerts to Redis (Edge + Centralized).", alert_count);
                    counter!("nexus_rules_alerts_fired_total").increment(alert_count as u64);
                }
                Err(failsafe::Error::Inner(e)) => {
                    counter!("nexus_rules_redis_faults_total").increment(1);
                    error!("Redis pipeline fault, retaining events: {}", e);
                    return Err(e);
                }
                Err(failsafe::Error::Rejected) => {
                    counter!("nexus_rules_redis_rejected_total").increment(1);
                    error!("Redis circuit breaker OPEN. Suspending ingestion block.");
                    return Err("Circuit breaker rejected execution.".to_string());
                }
            }
        }

        Ok(())
    }
}

// -- 6. UnifiedAlertSchema JSON Formatting --
fn create_alert(rule_name: &str, event: &ExtractedEvent) -> String {
    serde_json::json!({
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "sensor_id": event.sensor_id,
        "source_type": event.source_type,
        "vector_name": "sigma_rule",
        "anomaly_score": 1.0,
        "raw_event": {
            "rule_triggered": rule_name,
            "process": event.process_name,
            "command_line": event.command_line,
            "dest_ip": event.dest_ip,
            "dns_query": event.dns_query,
            "uid": event.uid,
            "tactic": event.edge_tactic,
            "technique": event.edge_technique
        }
    }).to_string()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    PrometheusBuilder::new().with_http_listener(([0, 0, 0, 0], 9002)).install().unwrap();

    let config_path = std::env::var("NEXUS_CONFIG")
        .unwrap_or_else(|_| "../config/nexus.toml".to_string());

    let conf_raw = fs::read_to_string(&config_path).unwrap();
    let conf: Config = toml::from_str(&conf_raw).unwrap();

    let worker_cfg = WorkerConfig {
        nats_url:      conf.global.nats_url.clone(),
        stream_name:   conf.global.telemetry_stream.clone(),
        subject:       conf.global.telemetry_subject.clone(),
        consumer_name: "Sigma_Rules_Group".into(),
        dlq_prefix:    conf.global.dlq_subject_prefix.clone(),
        ..WorkerConfig::default()
    };

    start_durable_worker(RulesAdapter::initialize(&config_path, None), worker_cfg).await;
}
