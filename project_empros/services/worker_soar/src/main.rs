use async_trait::async_trait;
use bytes::Bytes;
use futures::future::join_all;
use lib_siem_core::{start_durable_worker, SiemAdapter, WorkerConfig};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use minijinja::{context, Environment};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn, Level};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// ── Configuration Schemas ────────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
struct ContainmentConfig {
    global: GlobalConfig,
    #[serde(default)]
    cloud_routing: CloudRouting,
    providers: HashMap<String, ProviderConfig>,
}

#[derive(Deserialize, Clone, Default)]
struct CloudRouting {
    #[serde(default)] aws_source_types:     Vec<String>,
    #[serde(default)] azure_source_types:   Vec<String>,
    #[serde(default)] gcp_source_types:     Vec<String>,
    #[serde(default)] vmware_source_types:  Vec<String>,
    #[serde(default)] active_aws_provider:    String,
    #[serde(default)] active_azure_provider:  String,
    #[serde(default)] active_gcp_provider:    String,
    #[serde(default)] active_vmware_provider: String,
}

impl CloudRouting {
    /// Return the cloud provider key for the given source_type, or None if on-prem.
    fn provider_for(&self, source_type: &str) -> Option<&str> {
        if self.aws_source_types.iter().any(|s| s == source_type) {
            if !self.active_aws_provider.is_empty() { return Some(&self.active_aws_provider); }
        }
        if self.azure_source_types.iter().any(|s| s == source_type) {
            if !self.active_azure_provider.is_empty() { return Some(&self.active_azure_provider); }
        }
        if self.gcp_source_types.iter().any(|s| s == source_type) {
            if !self.active_gcp_provider.is_empty() { return Some(&self.active_gcp_provider); }
        }
        if self.vmware_source_types.iter().any(|s| s == source_type) {
            if !self.active_vmware_provider.is_empty() { return Some(&self.active_vmware_provider); }
        }
        None
    }
}

#[derive(Deserialize, Clone)]
struct GlobalConfig {
    active_edr: String,
    active_firewall: String,
    #[serde(default)] active_playbook_executor: String,
}

#[derive(Deserialize, Clone)]
struct ProviderConfig {
    actions: HashMap<String, ActionSchema>,
}

#[derive(Deserialize, Clone)]
struct ActionSchema {
    method: String,
    endpoint: String,
    headers: HashMap<String, String>,
    body_template: String,
}

#[derive(Deserialize)]
struct Config {
    global: Global,
    soar: SoarConf,
}

#[derive(Deserialize)]
struct Global {
    nats_url: String,
    telemetry_stream: String,
    dlq_subject_prefix: String,
}

#[derive(Deserialize)]
struct SoarConf {
    edr_api_url: String,
    firewall_api_url: String,
    simulated_auth_token: String,
}

// ── Payload Schemas ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
struct ContainmentPayload {
    action_type: String,
    targets: Vec<String>,
    incident_id: String,
    #[serde(default)]
    reason: String,
    /// Source sensor type (e.g. "aws_guardduty", "azure_entraid") -- used to
    /// route cloud incidents to the appropriate cloud containment provider
    /// instead of the on-prem EDR/firewall/SSH executor.
    #[serde(default)]
    source_type: String,
}

#[derive(Serialize, Debug)]
struct ExecutionPlan {
    incident_id: String,
    execution_steps: Vec<ExecutionStep>,
}

#[derive(Serialize, Debug)]
struct ExecutionStep {
    step_name: String,
    method: String,
    url: String,
    headers: HashMap<String, String>,
    body: Value,
}

// ── TTL-Based Deduplication ──────────────────────────────────────────────────

struct TimedDedup {
    entries: HashMap<String, Instant>,
    ttl: Duration,
}

impl TimedDedup {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Returns true if the key is a duplicate (already seen within TTL).
    fn is_duplicate(&mut self, key: &str) -> bool {
        self.evict_expired();
        if self.entries.contains_key(key) {
            return true;
        }
        self.entries.insert(key.to_string(), Instant::now());
        false
    }

    fn evict_expired(&mut self) {
        let ttl = self.ttl;
        self.entries.retain(|_, ts| ts.elapsed() < ttl);
    }
}

// ── Adapter ──────────────────────────────────────────────────────────────────

struct SoarAdapter {
    http_client: Client,
    jinja_env: Environment<'static>,
    containment_config: ContainmentConfig,
    batch_size: usize,
    edr_url: String,
    fw_url: String,
    auth_token: String,
    n8n_webhook_url: String,
    dedup: Arc<RwLock<TimedDedup>>,
}

#[async_trait]
impl SiemAdapter for SoarAdapter {
    fn initialize(config_path: &str, _nats_client: Option<async_nats::Client>) -> Self {
        let config_raw =
            std::fs::read_to_string(config_path).expect("FATAL: Config not found");
        let conf: Config = toml::from_str(&config_raw).expect("FATAL: Malformed TOML");

        let containment_path = std::env::var("CONTAINMENT_CONFIG")
            .unwrap_or_else(|_| "/etc/nexus/containment.toml".into());
        let containment_raw =
            std::fs::read_to_string(&containment_path).expect("FATAL: containment.toml not found");
        let containment_config: ContainmentConfig =
            toml::from_str(&containment_raw).expect("Malformed containment TOML");

        let n8n_url = std::env::var("N8N_WEBHOOK_URL")
            .unwrap_or_else(|_| "http://n8n.nexus:5678/webhook/master-containment".into());

        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(20)
            .build()
            .expect("Failed to build HTTP client");

        let dedup_ttl_secs: u64 = std::env::var("SOAR_DEDUP_TTL_SECS")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(300);

        info!(n8n = %n8n_url, dedup_ttl = dedup_ttl_secs, "SOAR Engine initialized");

        SoarAdapter {
            http_client,
            jinja_env: Environment::new(),
            containment_config,
            batch_size: 50,
            edr_url: conf.soar.edr_api_url,
            fw_url: conf.soar.firewall_api_url,
            auth_token: conf.soar.simulated_auth_token,
            n8n_webhook_url: n8n_url,
            dedup: Arc::new(RwLock::new(TimedDedup::new(Duration::from_secs(dedup_ttl_secs)))),
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
        if raw_payloads.is_empty() {
            return Ok(());
        }

        let mut containment_tasks = Vec::new();
        let failure_counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let total_targets = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut n8n_failures = 0u32;

        for payload_bytes in raw_payloads {
            let payload: ContainmentPayload = match serde_json::from_slice(payload_bytes) {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, "Malformed SOAR JSON, dropping");
                    continue;
                }
            };

            // TTL-based deduplication
            let dedup_key = format!("{}:{}", payload.incident_id, payload.action_type);
            {
                let mut dedup = self.dedup.write().await;
                if dedup.is_duplicate(&dedup_key) {
                    warn!(key = %dedup_key, "Duplicate containment suppressed");
                    continue;
                }
            }

            info!(
                action = %payload.action_type,
                incident = %payload.incident_id,
                targets = payload.targets.len(),
                "Executing containment"
            );

            total_targets.fetch_add(
                payload.targets.len() as u32,
                std::sync::atomic::Ordering::Relaxed,
            );

            // ── 1. Build n8n ExecutionPlan ────────────────────────────────
            let mut steps = Vec::new();

            // Cloud source types bypass on-prem EDR/firewall and route to a
            // cloud-specific provider (aws_containment_v1, azure_containment_v1,
            // or gcp_containment_v1) whose endpoint is the Cloud_Containment n8n
            // webhook or directly to the cloud provider API.
            let active_provider_key = if let Some(cloud_provider) = self
                .containment_config
                .cloud_routing
                .provider_for(&payload.source_type)
            {
                info!(
                    source_type = %payload.source_type,
                    provider = %cloud_provider,
                    incident = %payload.incident_id,
                    "Cloud source -- routing to cloud containment provider"
                );
                cloud_provider
            } else if payload.action_type.contains("host") {
                &self.containment_config.global.active_edr
            } else {
                &self.containment_config.global.active_firewall
            };

            if let Some(provider) = self.containment_config.providers.get(active_provider_key) {
                if let Some(schema) = provider.actions.get(&payload.action_type) {
                    for target in &payload.targets {
                        let url = self.jinja_env
                            .render_str(&schema.endpoint, context!(target => target))
                            .unwrap_or_else(|_| schema.endpoint.clone());

                        let raw_body = self.jinja_env
                            .render_str(
                                &schema.body_template,
                                context!(target => target, incident_id => payload.incident_id, reason => payload.reason),
                            )
                            .unwrap_or_else(|_| "{}".into());

                        let mut resolved_headers = HashMap::new();
                        for (k, v) in &schema.headers {
                            let resolved = if v.starts_with("${") && v.ends_with('}') {
                                let env_key = &v[2..v.len() - 1];
                                std::env::var(env_key).unwrap_or_else(|_| "UNRESOLVED_SECRET".into())
                            } else {
                                v.clone()
                            };
                            resolved_headers.insert(k.clone(), resolved);
                        }

                        steps.push(ExecutionStep {
                            step_name: payload.action_type.clone(),
                            method: schema.method.clone(),
                            url,
                            headers: resolved_headers,
                            body: serde_json::from_str(&raw_body).unwrap_or(serde_json::json!({})),
                        });
                    }
                }
            }

            // n8n dispatch -- INSIDE the batch result path (not fire-and-forget)
            if !steps.is_empty() {
                let plan = ExecutionPlan {
                    incident_id: payload.incident_id.clone(),
                    execution_steps: steps,
                };

                let n8n_start = Instant::now();
                match self.http_client.post(&self.n8n_webhook_url).json(&plan).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        histogram!("nexus_soar_n8n_latency_seconds")
                            .record(n8n_start.elapsed().as_secs_f64());
                        info!(incident = %plan.incident_id, "ExecutionPlan dispatched to n8n");
                    }
                    Ok(resp) => {
                        warn!(status = %resp.status(), "n8n webhook rejected payload");
                        n8n_failures += 1;
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to reach n8n webhook");
                        n8n_failures += 1;
                    }
                }
            }

            // ── 2. Native API fallback (parallel per target) ─────────────
            for target_ip in payload.targets {
                let client = self.http_client.clone();
                let edr_url = format!("{}/api/v1/isolate", self.edr_url);
                let fw_url = format!("{}/api/v1/isolate", self.fw_url);
                let token = self.auth_token.clone();
                let action = payload.action_type.clone();
                let fail_count = Arc::clone(&failure_counter);

                containment_tasks.push(tokio::spawn(async move {
                    let req_body = serde_json::json!({
                        "ip_address": target_ip,
                        "action": action,
                        "policy": "STRICT_QUARANTINE"
                    });

                    let mut failed = false;

                    match client.post(&edr_url).bearer_auth(&token).json(&req_body).send().await {
                        Ok(r) if r.status().is_success() => {
                            counter!("nexus_soar_edr_isolations_total").increment(1);
                        }
                        _ => { failed = true; }
                    }

                    match client.post(&fw_url).bearer_auth(&token).json(&req_body).send().await {
                        Ok(r) if r.status().is_success() => {
                            counter!("nexus_soar_fw_isolations_total").increment(1);
                        }
                        _ => { failed = true; }
                    }

                    if failed {
                        fail_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }));
            }
        }

        // Await all containment tasks
        let results = join_all(containment_tasks).await;
        for result in &results {
            if let Err(e) = result {
                error!(error = %e, "Containment task panicked");
                counter!("nexus_soar_task_panics_total").increment(1);
            }
        }

        let failures = failure_counter.load(std::sync::atomic::Ordering::Relaxed);
        let expected = total_targets.load(std::sync::atomic::Ordering::Relaxed);

        // Any failure in containment execution → Err → lib_siem_core retries → DLQ.
        // Returning Ok(()) on partial failure ACKs the message and permanently loses
        // the containment action for the failed targets (H-F2 fix).
        // Safety: TimedDedup prevents double-execution on retry within the TTL window.
        if failures > 0 || n8n_failures > 0 {
            counter!("nexus_soar_partial_failures_total").increment(1);
            Err(format!(
                "Containment failure: {failures}/{expected} API targets unreachable, \
                 {n8n_failures} n8n dispatch failures -- message retained for retry"
            ))
        } else {
            Ok(())
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let metrics_port: u16 = std::env::var("METRICS_PORT")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(9003);
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], metrics_port))
        .install()
        .unwrap();

    let config_path = std::env::var("NEXUS_CONFIG")
        .unwrap_or_else(|_| "/etc/nexus/nexus.toml".into());

    let conf_raw = std::fs::read_to_string(&config_path).unwrap();
    let conf: Config = toml::from_str(&conf_raw).unwrap();

    let worker_cfg = WorkerConfig {
        nats_url: conf.global.nats_url.clone(),
        stream_name: conf.global.telemetry_stream.clone(),
        subject: "nexus.soar.execute".into(),
        consumer_name: "SOAR_Execution_Group".into(),
        dlq_prefix: conf.global.dlq_subject_prefix.clone(),
        ..WorkerConfig::default()
    };

    info!(subject = "nexus.soar.execute", "worker_soar starting");

    start_durable_worker(SoarAdapter::initialize(&config_path, None), worker_cfg).await;
}