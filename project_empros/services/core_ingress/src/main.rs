use async_nats::HeaderMap;
use axum::{
    body::Bytes,
    error_handling::HandleErrorLayer,
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::propagation::Injector;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal::unix::{signal, SignalKind};
use tower::{BoxError, ServiceBuilder};
use tracing::{error, info, info_span, warn, Level};
use tracing_opentelemetry::OpenTelemetrySpanExt;

mod integrity;
use integrity::{
    extract_parquet_column_names, IntegrityVerifier, IntegrityViolation,
    HDR_BATCH_HMAC, HDR_BATCH_SEQUENCE, HDR_BATCH_TIMESTAMP, HDR_SENSOR_ID, HDR_SENSOR_TYPE,
};

// -- Single Allocator (jemalloc on Linux, system on Windows) ------------------
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// -- JWT Claims ---------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// -- Application State --------------------------------------------------------

struct AppState {
    js: async_nats::jetstream::Context,
    jwt_secret: String,
    /// Shared HMAC secret -- verifies the artifact-upload body (Det Chamber).
    integrity_secret: String,
    verifier: IntegrityVerifier,
    /// Cache Parquet column names per sensor_id. Sensors always send the same
    /// schema, so parsing once eliminates ~2ms of Parquet footer decode per request.
    schema_cache: DashMap<String, Vec<String>>,
    max_payload_bytes: usize,
    /// Pending SOAR response tasks (DC-N11), keyed by host == the agent's JWT
    /// subject. worker_soar publishes signed tasks to `nexus.agent.tasks`; the
    /// subscriber files them here; GET /api/v1/tasks drains them on the agent poll.
    task_store: Arc<DashMap<String, Vec<serde_json::Value>>>,
}

struct NatsHeaderInjector<'a>(&'a mut HeaderMap);

impl<'a> Injector for NatsHeaderInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key, value.as_str());
    }
}

// -- Startup Configuration (parsed once, not on every request) ----------------

struct StartupConfig {
    nats_url: String,
    jwt_secret: String,
    integrity_secret: String,
    ban_threshold: u32,
    bind_addr: SocketAddr,
    max_concurrent_requests: usize,
    request_timeout_secs: u64,
    max_payload_bytes: usize,
    metrics_port: u16,
}

impl StartupConfig {
    fn from_env() -> Self {
        Self {
            nats_url: std::env::var("NATS_URL")
                .unwrap_or_else(|_| "nats://nats:4222".into()),

            // MANDATORY -- no fallback defaults for secrets in production
            jwt_secret: std::env::var("JWT_SECRET")
                .expect("FATAL: JWT_SECRET environment variable is required"),
            integrity_secret: std::env::var("INTEGRITY_HMAC_SECRET")
                .expect("FATAL: INTEGRITY_HMAC_SECRET environment variable is required"),

            ban_threshold: std::env::var("INTEGRITY_BAN_THRESHOLD")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            bind_addr: std::env::var("BIND_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".into())
                .parse().expect("FATAL: Invalid BIND_ADDR"),
            max_concurrent_requests: std::env::var("MAX_CONCURRENT_REQUESTS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(8192),
            request_timeout_secs: std::env::var("REQUEST_TIMEOUT_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            max_payload_bytes: std::env::var("MAX_PAYLOAD_BYTES")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(10_485_760),
            metrics_port: std::env::var("METRICS_PORT")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(9000),
        }
    }
}

// -- Main ---------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let cfg = StartupConfig::from_env();

    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], cfg.metrics_port))
        .install()
        .expect("FATAL: Failed to install Prometheus exporter");

    let verifier = IntegrityVerifier::new(cfg.integrity_secret.as_bytes(), cfg.ban_threshold);

    // C2: the production NATS server runs default-deny authorization — connect
    // with the ingress_node credentials from /etc/nexus/ingress.env when set.
    let nats_user = std::env::var("NATS_USER").unwrap_or_default();
    let nats_pass = std::env::var("NATS_PASS").unwrap_or_default();
    let connect_result = if !nats_user.is_empty() && !nats_pass.is_empty() {
        async_nats::ConnectOptions::with_user_and_password(nats_user, nats_pass)
            .connect(&cfg.nats_url)
            .await
    } else {
        async_nats::connect(&cfg.nats_url).await
    };
    let client = match connect_result {
        Ok(c) => c,
        Err(e) => {
            error!("FATAL: Ingress failed to connect to NATS at {}: {}", cfg.nats_url, e);
            std::process::exit(1);
        }
    };

    // -- Agent-task subscriber (DC-N11) ---------------------------------------
    // worker_soar publishes signed response tasks to `nexus.agent.tasks`. File each
    // by its `host` field; GET /api/v1/tasks drains them for the polling agent. The
    // signature is verified ON THE HOST (the agent owns the secret); the ingress
    // only routes -- it never executes.
    let task_store: Arc<DashMap<String, Vec<serde_json::Value>>> = Arc::new(DashMap::new());
    {
        use futures::StreamExt;
        let sub_client = client.clone();
        let store = task_store.clone();
        tokio::spawn(async move {
            match sub_client.subscribe("nexus.agent.tasks".to_string()).await {
                Ok(mut sub) => {
                    info!("agent-task subscriber listening on nexus.agent.tasks");
                    while let Some(msg) = sub.next().await {
                        match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                            Ok(task) => match task.get("host").and_then(|v| v.as_str()) {
                                Some(host) => {
                                    store.entry(host.to_string()).or_default().push(task);
                                    counter!("nexus_ingress_agent_tasks_queued_total").increment(1);
                                }
                                None => warn!("agent task missing host field -- dropped"),
                            },
                            Err(e) => warn!(error = %e, "dropping malformed agent task"),
                        }
                    }
                    error!("agent-task subscription ended");
                }
                Err(e) => error!(error = %e, "failed to subscribe to nexus.agent.tasks"),
            }
        });
    }

    let js = async_nats::jetstream::new(client);

    let state = Arc::new(AppState {
        js,
        jwt_secret: cfg.jwt_secret,
        integrity_secret: cfg.integrity_secret,
        verifier,
        schema_cache: DashMap::new(),
        max_payload_bytes: cfg.max_payload_bytes,
        task_store,
    });

    let app = Router::new()
        .route("/api/v1/telemetry", post(handle_binary_telemetry))
        // Det Chamber: outbound endpoint acquisition (no inbound SSH/WinRM). The
        // on-host agent polls /api/v1/tasks and transmits the acquired file to
        // /api/v1/artifact over HTTPS with JWT + HMAC.
        .route("/api/v1/artifact", post(handle_artifact_upload))
        .route("/api/v1/tasks", get(handle_task_poll))
        .route("/healthz", get(|| async { StatusCode::OK }))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    StatusCode::REQUEST_TIMEOUT
                }))
                .timeout(Duration::from_secs(cfg.request_timeout_secs))
                .concurrency_limit(cfg.max_concurrent_requests),
        )
        .with_state(state);

    info!(
        addr = %cfg.bind_addr,
        metrics_port = cfg.metrics_port,
        max_concurrent = cfg.max_concurrent_requests,
        "Zero-Trust Ingress Online | Integrity Verification ACTIVE"
    );

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr)
        .await
        .expect("FATAL: Failed to bind");

    let graceful_shutdown = async {
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to listen for SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to listen for SIGINT");
        tokio::select! {
            _ = sigterm.recv() => info!("SIGTERM received"),
            _ = sigint.recv()  => info!("SIGINT received"),
        };
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(graceful_shutdown)
        .await
        .unwrap();

    info!("Ingress shutdown complete.");
}

// -- JWT Validation -----------------------------------------------------------

fn validate_token(headers: &header::HeaderMap, secret: &str) -> Result<Claims, StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["nexus-ingress"]);

    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .map(|data| data.claims)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

fn hdr_str<'a>(headers: &'a header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

// -- Telemetry Handler --------------------------------------------------------

async fn handle_binary_telemetry(
    State(state): State<Arc<AppState>>,
    headers: header::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let payload_size = body.len();
    counter!("nexus_ingress_requests_total").increment(1);

    // 1. JWT
    if validate_token(&headers, &state.jwt_secret).is_err() {
        counter!("nexus_ingress_auth_failures_total").increment(1);
        return StatusCode::UNAUTHORIZED;
    }

    // 2. Content-Type
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if content_type != "application/vnd.apache.parquet" {
        counter!("nexus_ingress_invalid_content_type_total").increment(1);
        return StatusCode::UNSUPPORTED_MEDIA_TYPE;
    }

    // 3. Size guardrail (parsed at startup, not per-request)
    if payload_size > state.max_payload_bytes {
        counter!("nexus_ingress_payload_too_large_total").increment(1);
        return StatusCode::PAYLOAD_TOO_LARGE;
    }

    // 4. Integrity headers
    let sensor_type = hdr_str(&headers, HDR_SENSOR_TYPE).unwrap_or("unclassified");
    let sensor_id = match hdr_str(&headers, HDR_SENSOR_ID) {
        Some(id) => id,
        None => {
            counter!("nexus_ingress_missing_headers_total").increment(1);
            return StatusCode::BAD_REQUEST;
        }
    };
    let batch_sequence: u64 = match hdr_str(&headers, HDR_BATCH_SEQUENCE).and_then(|s| s.parse().ok()) {
        Some(seq) => seq,
        None => {
            counter!("nexus_ingress_missing_headers_total").increment(1);
            return StatusCode::BAD_REQUEST;
        }
    };
    let batch_timestamp: u64 = match hdr_str(&headers, HDR_BATCH_TIMESTAMP).and_then(|s| s.parse().ok()) {
        Some(ts) => ts,
        None => {
            counter!("nexus_ingress_missing_headers_total").increment(1);
            return StatusCode::BAD_REQUEST;
        }
    };
    let batch_hmac = match hdr_str(&headers, HDR_BATCH_HMAC) {
        Some(h) => h,
        None => {
            counter!("nexus_ingress_missing_headers_total").increment(1);
            return StatusCode::BAD_REQUEST;
        }
    };

    // 5. Schema introspection -- cached per sensor_id (parse once, reuse forever)
    let parquet_columns = match state.schema_cache.get(sensor_id) {
        Some(cached) => cached.clone(),
        None => {
            match extract_parquet_column_names(&body) {
                Ok(cols) => {
                    state.schema_cache.insert(sensor_id.to_string(), cols.clone());
                    cols
                }
                Err(e) => {
                    counter!("nexus_ingress_parquet_parse_failures_total").increment(1);
                    error!(sensor_id, error = %e, "Unreadable Parquet");
                    return StatusCode::BAD_REQUEST;
                }
            }
        }
    };

    // 6. Three-tier integrity verification
    let span = info_span!("integrity_check", sensor_type, sensor_id, seq = batch_sequence);
    let _enter = span.enter();

    if let Err(violation) = state.verifier.verify_batch(
        &body,
        batch_sequence,
        batch_timestamp,
        sensor_id,
        sensor_type,
        batch_hmac,
        &parquet_columns,
    ) {
        log_violation(&violation, sensor_id, batch_sequence, sensor_type);
        return match violation {
            IntegrityViolation::CrossOsCollision { .. }
            | IntegrityViolation::SensorBanned { .. } => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        };
    }

    counter!("nexus_ingress_integrity_verified_total").increment(1);

    // 7. Dynamic NATS topic routing
    let subject = format!("nexus.{sensor_type}.telemetry");

    // 8. OTLP trace propagation
    let trace_span = info_span!("ingress_binary_telemetry", bytes = payload_size, sensor_type, sensor_id);
    let _t = trace_span.enter();

    let cx = trace_span.context();
    let mut nats_headers = HeaderMap::new();
    opentelemetry::global::get_text_map_propagator(|prop| {
        prop.inject_context(&cx, &mut NatsHeaderInjector(&mut nats_headers));
    });

    // Forward lineage metadata + partition hints downstream
    let seq_str = batch_sequence.to_string();
    nats_headers.insert(HDR_SENSOR_ID, sensor_id);
    nats_headers.insert(HDR_SENSOR_TYPE, sensor_type);
    nats_headers.insert(HDR_BATCH_SEQUENCE, seq_str.as_str());

    // Forward Hive partition hints if present (from Arkime gateway)
    if let Some(dt) = hdr_str(&headers, "X-Partition-Date") {
        nats_headers.insert("X-Partition-Date", dt);
    }
    if let Some(hr) = hdr_str(&headers, "X-Partition-Hour") {
        nats_headers.insert("X-Partition-Hour", hr);
    }

    // 9. Publish to JetStream
    match state.js.publish_with_headers(subject.clone(), nats_headers, body.into()).await {
        Ok(_) => {
            counter!("nexus_ingress_events_accepted_total").increment(1);
            info!(bytes = payload_size, sensor_id, seq = batch_sequence, subject = %subject, "Verified → JetStream");
            StatusCode::ACCEPTED
        }
        Err(e) => {
            error!(error = %e, "JetStream publish rejected");
            counter!("nexus_ingress_broker_faults_total").increment(1);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

// -- Det Chamber: endpoint artifact acquisition (outbound HTTPS) --------------

const HDR_ARTIFACT_HMAC: &str = "X-Artifact-HMAC";
const HDR_ARTIFACT_SHA256: &str = "X-Artifact-SHA256";

/// Verify the HMAC-SHA256 over the artifact body with the shared integrity secret.
/// Same primitive the sensor telemetry path uses, applied to the whole upload.
fn verify_artifact_hmac(secret: &str, body: &[u8], provided_hex: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    match hex::decode(provided_hex) {
        Ok(expected) => mac.verify_slice(&expected).is_ok(),
        Err(_) => false,
    }
}

/// POST /api/v1/artifact -- the on-host acquisition agent transmits a zipped,
/// confirmed-TP file OUTBOUND over HTTPS. JWT-gated + HMAC-verified, then relayed
/// to intake_service over NATS, which persists it to the locked-down quarantine
/// bucket and detonates. The chain-of-custody sha256 (X-Artifact-SHA256) is
/// re-verified at intake after unzip.
async fn handle_artifact_upload(
    State(state): State<Arc<AppState>>,
    headers: header::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if validate_token(&headers, &state.jwt_secret).is_err() {
        counter!("nexus_ingress_auth_failures_total").increment(1);
        return StatusCode::UNAUTHORIZED;
    }
    let incident_id = hdr_str(&headers, "X-Incident-Id").unwrap_or("");
    let sha256 = hdr_str(&headers, HDR_ARTIFACT_SHA256).unwrap_or("");
    let provided_hmac = match hdr_str(&headers, HDR_ARTIFACT_HMAC) {
        Some(h) => h,
        None => return StatusCode::BAD_REQUEST,
    };
    if incident_id.is_empty() || sha256.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    if !verify_artifact_hmac(&state.integrity_secret, &body, provided_hmac) {
        counter!("nexus_ingress_hmac_failures_total").increment(1);
        error!(incident_id, "Artifact HMAC verification failed -- rejecting upload");
        return StatusCode::FORBIDDEN;
    }
    counter!("nexus_ingress_artifact_verified_total").increment(1);

    // Forward the manifest as headers; the artifact rides the message body.
    let mut nats_headers = HeaderMap::new();
    for key in [
        "X-Incident-Id", "X-Sensor-Id", "X-Os-Family", "X-Artifact-Filename",
        HDR_ARTIFACT_SHA256, "X-Artifact-Size", "X-Src-Path",
    ] {
        if let Some(v) = hdr_str(&headers, key) {
            nats_headers.insert(key, v);
        }
    }
    match state
        .js
        .publish_with_headers("nexus.detonation.intake".into(), nats_headers, body.into())
        .await
    {
        Ok(_) => {
            counter!("nexus_ingress_artifacts_accepted_total").increment(1);
            info!(incident_id, "Artifact verified → detonation intake");
            StatusCode::ACCEPTED
        }
        Err(e) => {
            error!(error = %e, "Artifact intake publish rejected");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

/// GET /api/v1/tasks -- the on-host agent polls (outbound) for pending SOAR
/// response / acquisition tasks. JWT-gated; drains the agent's queue keyed by its
/// JWT subject (== host). worker_soar fills the queue via `nexus.agent.tasks`.
async fn handle_task_poll(
    State(state): State<Arc<AppState>>,
    headers: header::HeaderMap,
) -> impl IntoResponse {
    let claims = match validate_token(&headers, &state.jwt_secret) {
        Ok(c) => c,
        Err(_) => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "tasks": [] }))),
    };
    // Drain this agent's queued tasks. At-least-once: the agent confirms completion
    // out of band (nexus.soar.callback); the signature is verified on the host.
    let tasks = state
        .task_store
        .remove(&claims.sub)
        .map(|(_, v)| v)
        .unwrap_or_default();
    if !tasks.is_empty() {
        counter!("nexus_ingress_agent_tasks_polled_total").increment(tasks.len() as u64);
        info!(sensor = %claims.sub, n = tasks.len(), "delivered pending agent tasks");
    }
    (StatusCode::OK, Json(serde_json::json!({ "tasks": tasks })))
}

// -- Violation Logging --------------------------------------------------------

fn log_violation(v: &IntegrityViolation, sensor_id: &str, seq: u64, sensor_type: &str) {
    match v {
        IntegrityViolation::HmacMismatch | IntegrityViolation::HmacDecodeError => {
            counter!("nexus_ingress_hmac_failures_total").increment(1);
            error!(sensor_id, seq, "HMAC verification failed");
        }
        IntegrityViolation::SequenceGap { expected_min, received } => {
            counter!("nexus_ingress_sequence_gap_total").increment(1);
            error!(sensor_id, expected_min, received, "Sequence gap");
        }
        IntegrityViolation::SequenceReplay { sequence } => {
            counter!("nexus_ingress_replay_detections_total").increment(1);
            error!(sensor_id, sequence, "Replay detected");
        }
        IntegrityViolation::TemporalDrift { delta_secs, .. } => {
            counter!("nexus_ingress_temporal_drift_total").increment(1);
            error!(sensor_id, delta_secs, "Temporal drift");
        }
        IntegrityViolation::CrossOsCollision { offending_columns, .. } => {
            counter!("nexus_ingress_cross_os_collision_total").increment(1);
            error!(sensor_id, sensor_type, columns = ?offending_columns, "CROSS-OS COLLISION → BANNED");
        }
        IntegrityViolation::SensorBanned { .. } => {
            counter!("nexus_ingress_banned_sensor_attempts_total").increment(1);
            warn!(sensor_id, "Banned sensor attempted reconnection");
        }
        IntegrityViolation::MissingHeaders => {
            counter!("nexus_ingress_missing_headers_total").increment(1);
        }
    }
}