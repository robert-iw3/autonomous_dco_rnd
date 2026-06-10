use async_trait::async_trait;
use bytes::Bytes;
use lib_siem_core::{start_durable_worker, SiemAdapter, WorkerConfig};
use metrics::counter;
use serde::{Deserialize, Serialize};
use async_nats::jetstream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::LazyLock;
use tracing::{error, info, warn, Level};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// ── Schemas ──────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct RlhfFeedback {
    incident_id: String,
    operator_id: String,
    swarm_verdict: String,
    operator_action: String,
    timestamp: String,
}

#[derive(Serialize, Debug)]
struct TrainingRecord {
    incident_id: String,
    reward_score: f32,
    operator_override: bool,
    timestamp: String,
}

// ── Rate Limiting (process-level -- see note on multi-replica) ────────────────

static OVERRIDE_VELOCITY: LazyLock<std::sync::Mutex<std::collections::HashMap<String, u32>>> =
    LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

static GLOBAL_OVERRIDE_COUNT: AtomicU32 = AtomicU32::new(0);
static VELOCITY_RESET_STARTED: AtomicBool = AtomicBool::new(false);

// ── Adapter ──────────────────────────────────────────────────────────────────

struct RlhfAdapter {
    nats_client: async_nats::Client,
    spool_subject: String,
    batch_size: usize,
    global_circuit_breaker_threshold: u32,
    per_operator_threshold: u32,
}

#[async_trait]
impl SiemAdapter for RlhfAdapter {
    fn initialize(config_path: &str, nats_client: Option<async_nats::Client>) -> Self {
        let nats_client = nats_client.expect("CRITICAL: RLHF worker requires a NATS client");

        let batch_size: usize = std::env::var("RLHF_BATCH_SIZE")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(100);
        let global_threshold: u32 = std::env::var("RLHF_GLOBAL_CIRCUIT_BREAKER")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(50);
        let per_operator: u32 = std::env::var("RLHF_PER_OPERATOR_THRESHOLD")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(10);
        let spool_subject = std::env::var("RLHF_SPOOL_SUBJECT")
            .unwrap_or_else(|_| "nexus.training.rlhf.records".into());

        info!(
            batch_size,
            global_threshold,
            per_operator,
            spool_subject = %spool_subject,
            "RLHF Parquet Spooler initialized"
        );

        RlhfAdapter {
            nats_client,
            spool_subject,
            batch_size,
            global_circuit_breaker_threshold: global_threshold,
            per_operator_threshold: per_operator,
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
        if !VELOCITY_RESET_STARTED.swap(true, Ordering::Relaxed) {
            tokio::spawn(async {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    GLOBAL_OVERRIDE_COUNT.store(0, Ordering::Relaxed);
                    if let Ok(mut vel) = OVERRIDE_VELOCITY.lock() {
                        vel.clear();
                    }
                }
            });
        }

        if raw_payloads.is_empty() {
            return Ok(());
        }

        let mut training_batch = Vec::with_capacity(raw_payloads.len());

        for payload_bytes in raw_payloads {
            let feedback: RlhfFeedback = match serde_json::from_slice(payload_bytes) {
                Ok(f) => f,
                Err(e) => {
                    warn!(error = %e, "Malformed RLHF feedback, skipping");
                    continue;
                }
            };

            let mut is_override = false;
            let reward_score = match feedback.operator_action.as_str() {
                "CONFIRM_QUARANTINE" => 1.0,
                "DISMISS_FALSE_POSITIVE" => {
                    is_override = true;
                    -1.0
                }
                "MANUAL_REVIEW" => 0.5,
                _ => 0.0,
            };

            if is_override {
                let global_count = GLOBAL_OVERRIDE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if global_count > self.global_circuit_breaker_threshold {
                    error!(
                        count = global_count,
                        threshold = self.global_circuit_breaker_threshold,
                        "GLOBAL CIRCUIT BREAKER: override threshold exceeded. Halting RLHF."
                    );
                    return Err("Circuit breaker: global override threshold exceeded".into());
                }

                if let Ok(mut velocity) = OVERRIDE_VELOCITY.lock() {
                    let count = velocity.entry(feedback.operator_id.clone()).or_insert(0);
                    *count += 1;
                    if *count > self.per_operator_threshold {
                        warn!(
                            operator = %feedback.operator_id,
                            count = *count,
                            "Poisoning risk: operator exceeded override threshold. Quarantining."
                        );
                        counter!("nexus_rlhf_operator_quarantined_total").increment(1);
                        continue;
                    }
                }
            }

            training_batch.push(TrainingRecord {
                incident_id: feedback.incident_id,
                reward_score,
                operator_override: is_override,
                timestamp: feedback.timestamp,
            });
        }

        if training_batch.is_empty() {
            return Ok(());
        }

        // Durably publish each record to NATS JetStream so the MLOps pipeline
        // can consume them via 01_spool_datasets.py --target critic.
        let js = jetstream::new(self.nats_client.clone());
        let mut publish_errors = 0usize;

        for record in &training_batch {
            match serde_json::to_vec(record) {
                Ok(payload) => {
                    if let Err(e) = js.publish(self.spool_subject.clone(), payload.into()).await {
                        error!(error = %e, "Failed to publish RLHF record to JetStream");
                        publish_errors += 1;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to serialize RLHF record");
                }
            }
        }

        let spooled = training_batch.len() - publish_errors;
        counter!("nexus_rlhf_records_spooled_total").increment(spooled as u64);
        info!(count = spooled, failed = publish_errors, "RLHF records published to JetStream for Model D");

        if publish_errors > 0 {
            return Err(format!("{} RLHF records failed to publish -- batch will retry", publish_errors));
        }

        Ok(())
    }
}

// ── H-R6: Dedicated RLHF JetStream stream ────────────────────────────────────
//
// worker_rlhf previously bound to Nexus_System (Limits retention). This causes
// two problems:
//   1. ACKed RLHF feedback messages are NOT deleted -- stream grows unboundedly
//      and replays stale feedback on worker restart.
//   2. No max_age -- old operator labels (weeks/months old) poison the reward model.
//
// Fix: bind a dedicated Nexus_RLHF_Feedback stream with:
//   • WorkQueuePolicy retention -- messages deleted after ACK (no replay)
//   • 7-day max_age             -- stale feedback auto-expires
//   • AckExplicit               -- consumer must explicitly ACK each message
//
// The Nexus_RLHF_Training stream (output) gets WorkQueue + 30-day retention
// so the MLOps pipeline can replay training records if needed.

async fn ensure_rlhf_streams(js: &jetstream::Context) {
    let max_age_feedback = std::time::Duration::from_secs(7 * 24 * 3600);
    let max_age_records  = std::time::Duration::from_secs(30 * 24 * 3600);

    let streams = [
        (
            "Nexus_RLHF_Feedback",
            vec!["nexus.training.rlhf".to_string()],
            jetstream::stream::RetentionPolicy::WorkQueue,
            max_age_feedback,
        ),
        (
            // C6: must match the stream name created by infrastructure/nats/streams_init.sh
            // for this subject — two streams cannot share nexus.training.rlhf.records.
            "Nexus_RLHF_Training",
            vec!["nexus.training.rlhf.records".to_string()],
            jetstream::stream::RetentionPolicy::WorkQueue,
            max_age_records,
        ),
    ];

    for (name, subjects, retention, max_age) in streams {
        match js.get_or_create_stream(jetstream::stream::Config {
            name: name.to_string(),
            subjects,
            retention,
            max_age,
            ..Default::default()
        }).await {
            Ok(_)  => info!(stream = name, "RLHF stream ensured"),
            Err(e) => tracing::error!(stream = name, error = %e, "Failed to ensure RLHF stream"),
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://nats:4222".into());
    let config_path = std::env::var("NEXUS_CONFIG").unwrap_or_default();

    // Connect NATS separately so we can pass the client to the adapter for JetStream publishing
    let nats_client = lib_siem_core::nats_connect(&nats_url)
        .await
        .unwrap_or_else(|e| { tracing::error!("NATS connect failed: {}", e); std::process::exit(1); });

    // H-R6: ensure RLHF streams exist with WorkQueuePolicy before binding consumer
    let js_init = jetstream::new(nats_client.clone());
    ensure_rlhf_streams(&js_init).await;

    let cfg = WorkerConfig {
        nats_url,
        // H-R6: bind the dedicated RLHF stream (not Nexus_System)
        stream_name: "Nexus_RLHF_Feedback".into(),
        subject: "nexus.training.rlhf".into(),
        consumer_name: "RLHF_Spooler_Group".into(),
        dlq_prefix: "nexus.dlq".into(),
        // RLHF feedback is low-latency; minimal batch wait
        batch_deadline_secs: 1,
        ..WorkerConfig::default()
    };

    info!(subject = %cfg.subject, stream = %cfg.stream_name, "worker_rlhf starting");

    start_durable_worker(RlhfAdapter::initialize(&config_path, Some(nats_client)), cfg).await;
}