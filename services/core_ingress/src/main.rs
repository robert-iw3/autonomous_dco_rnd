use async_nats::HeaderMap;
use axum::{
    body::Bytes,
    error_handling::HandleErrorLayer,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
// object_store 0.13 moved the `put` convenience method off the ObjectStore trait
// onto the ObjectStoreExt extension trait; both must be in scope.
use object_store::{aws::AmazonS3Builder, path::Path as ObjPath, ObjectStore, ObjectStoreExt};
use opentelemetry::propagation::Injector;
use serde::{Deserialize, Serialize};
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::{Duration, Instant}};
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

// -- Anti-DoS rate limiter (F-16) ---------------------------------------------
// Per-client-IP token bucket, applied as the OUTERMOST layer so a flood is
// dropped with 429 before it consumes JWT/HMAC verification, concurrency slots,
// or body parsing. `/healthz` is exempt. Capacity = burst, refill = rps/sec.
struct RateLimiter {
    buckets: DashMap<IpAddr, (f64, Instant)>,
    rps: f64,
    burst: f64,
}

impl RateLimiter {
    fn new(rps: f64, burst: f64) -> Self {
        Self { buckets: DashMap::new(), rps, burst: burst.max(1.0) }
    }
    /// Take one token for `ip`; false when the bucket is empty (request denied).
    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut e = self.buckets.entry(ip).or_insert((self.burst, now));
        let (tokens, last) = *e;
        let refilled = (tokens + now.duration_since(last).as_secs_f64() * self.rps).min(self.burst);
        if refilled >= 1.0 {
            *e = (refilled - 1.0, now);
            true
        } else {
            *e = (refilled, now);
            false
        }
    }
}

/// Best-effort client IP: first hop of X-Forwarded-For (behind a terminator),
/// else the peer socket address.
fn client_ip(req: &Request, peer: SocketAddr) -> IpAddr {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| peer.ip())
}

async fn rate_limit_mw(
    State(rl): State<Arc<RateLimiter>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    if !rl.allow(client_ip(&req, peer)) {
        counter!("nexus_ingress_rate_limited_total").increment(1);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    next.run(req).await
}

// -- Per-sensor adaptive ingest baseline (F-16, telemetry-aware) ---------------
// Telemetry is high-volume and bursty by design: during an incident, honest
// sensors legitimately emit far more events. So authenticated telemetry is NEVER
// dropped on volume here. Instead each sensor's arrival rate is tracked as an EWMA
// and an extreme deviation from ITS OWN baseline is surfaced as a surge signal
// (metric + log) for the SOC to judge "attack on the ingress" vs "the estate is
// under attack". The hard drop is the pre-auth per-IP flood guard above.
struct SensorBaseline {
    rates: DashMap<String, (f64, f64)>, // sensor_id -> (ewma_rps, last_seen_secs)
    alpha: f64,
    surge_factor: f64,
    floor_rps: f64,
}

/// One EWMA step. Returns (new_ewma, is_surge). A surge is an instantaneous rate
/// far above the sensor's own learned baseline AND above an absolute floor (so a
/// quiet sensor's first couple of events never read as an attack). Pure for tests.
fn surge_step(ewma: f64, last: f64, now: f64, alpha: f64, factor: f64, floor: f64) -> (f64, bool) {
    let dt = (now - last).max(1e-3);
    let inst = 1.0 / dt;
    let new_ewma = if ewma <= 0.0 { inst } else { alpha * inst + (1.0 - alpha) * ewma };
    let surge = ewma > 0.0 && inst > ewma * factor && inst > floor;
    (new_ewma, surge)
}

impl SensorBaseline {
    fn new(alpha: f64, surge_factor: f64, floor_rps: f64) -> Self {
        Self { rates: DashMap::new(), alpha, surge_factor, floor_rps }
    }
    /// Record an arrival for `sensor` at `now` (epoch secs); true if it is a surge.
    fn observe(&self, sensor: &str, now: f64) -> bool {
        let mut e = self.rates.entry(sensor.to_string()).or_insert((0.0, now));
        let (ewma, last) = *e;
        let (new_ewma, surge) = surge_step(ewma, last, now, self.alpha, self.surge_factor, self.floor_rps);
        *e = (new_ewma, now);
        surge
    }
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
    /// Larger cap for memory/IR evidence uploads (RAM images ≫ telemetry batches).
    max_evidence_bytes: usize,
    /// WORM image archive (GOVERNANCE-default bucket); the gateway streams verified
    /// memory images here, then publishes a handle on `nexus.memory.intake`.
    evidence_store: Option<Arc<dyn ObjectStore>>,
    /// Pending SOAR response tasks (DC-N11), keyed by host == the agent's JWT
    /// subject. worker_soar publishes signed tasks to `nexus.agent.tasks`; the
    /// subscriber files them here; GET /api/v1/tasks drains them on the agent poll.
    task_store: Arc<DashMap<String, Vec<serde_json::Value>>>,
    /// Per-sensor adaptive ingest baseline (surge signal, never a drop).
    baseline: SensorBaseline,
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
    max_evidence_bytes: usize,
    metrics_port: u16,
    /// Per-client-IP request rate (tokens/sec) and burst capacity for the
    /// anti-DoS limiter. Generous defaults; tune per deployment.
    rate_limit_rps: f64,
    rate_limit_burst: f64,
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
            // RAM images are far larger than telemetry batches (default 8 GiB cap).
            max_evidence_bytes: std::env::var("MAX_EVIDENCE_BYTES")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(8_589_934_592),
            metrics_port: std::env::var("METRICS_PORT")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(9000),
            rate_limit_rps: std::env::var("INGRESS_RATE_LIMIT_RPS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(200.0),
            rate_limit_burst: std::env::var("INGRESS_RATE_LIMIT_BURST")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(400.0),
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

    // WORM image archive — built only when a bucket is configured (S3/MinIO from env).
    let evidence_store: Option<Arc<dyn ObjectStore>> =
        match std::env::var("NEXUS_MEMORY_ARCHIVE_BUCKET") {
            Ok(bucket) if !bucket.is_empty() => match AmazonS3Builder::from_env()
                .with_bucket_name(&bucket).build() {
                Ok(s) => { info!(bucket, "WORM evidence archive enabled"); Some(Arc::new(s)) }
                Err(e) => { error!(error = %e, "evidence archive init failed; /api/v1/evidence disabled"); None }
            },
            _ => None,
        };

    let state = Arc::new(AppState {
        js,
        jwt_secret: cfg.jwt_secret,
        integrity_secret: cfg.integrity_secret,
        verifier,
        schema_cache: DashMap::new(),
        max_payload_bytes: cfg.max_payload_bytes,
        max_evidence_bytes: cfg.max_evidence_bytes,
        evidence_store,
        task_store,
        // Surge baseline: ~10x a sensor's EWMA rate and above a 50 rps floor reads
        // as a surge worth surfacing (tunable; never drops authenticated telemetry).
        baseline: SensorBaseline::new(0.2, 10.0, 50.0),
    });

    let app = Router::new()
        .route("/api/v1/telemetry", post(handle_binary_telemetry))
        // Det Chamber: outbound endpoint acquisition (no inbound SSH/WinRM). The
        // on-host agent polls /api/v1/tasks and transmits the acquired file to
        // /api/v1/artifact over HTTPS with JWT + HMAC.
        .route("/api/v1/artifact", post(handle_artifact_upload))
        // Memory/IR evidence (its own data class): JWT + HMAC + SHA-256 custody,
        // streamed to the WORM archive, then a verified handle → nexus.memory.intake.
        // Large body limit applies to THIS route only (RAM images); every other
        // route keeps the small default below.
        .route("/api/v1/evidence", post(handle_evidence_upload)
            .layer(DefaultBodyLimit::max(cfg.max_evidence_bytes)))
        .route("/api/v1/tasks", get(handle_task_poll))
        .route("/healthz", get(|| async { StatusCode::OK }))
        // Global small body cap — telemetry/artifact/task routes only; the evidence
        // route overrides it above so oversized uploads can't hit any other path.
        .layer(DefaultBodyLimit::max(cfg.max_payload_bytes))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    StatusCode::REQUEST_TIMEOUT
                }))
                .timeout(Duration::from_secs(cfg.request_timeout_secs))
                .concurrency_limit(cfg.max_concurrent_requests),
        )
        // Outermost: drop floods with 429 before any verification / concurrency use.
        .layer(middleware::from_fn_with_state(
            Arc::new(RateLimiter::new(cfg.rate_limit_rps, cfg.rate_limit_burst)),
            rate_limit_mw,
        ))
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

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
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

    // 6b. Adaptive per-sensor ingest baseline (F-16). Verified telemetry is never
    // dropped on volume -- a surge may mean the estate is under attack -- but an
    // extreme deviation from this sensor's own baseline is surfaced for the SOC.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    if state.baseline.observe(sensor_id, now_secs) {
        counter!("nexus_ingress_sensor_surge_total").increment(1);
        warn!(sensor_id, "ingest surge far above sensor baseline -- attack on ingress or estate under attack?");
    }

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
        .publish_with_headers("nexus.detonation.intake", nats_headers, body.into())
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

// -- Memory / IR evidence ingress (its own verified data class) ---------------

const HDR_EVIDENCE_KIND: &str = "X-Evidence-Kind";
const HDR_OS_FAMILY: &str = "X-Os-Family";

/// SHA-256 chain-of-custody: the body must hash to the sealed manifest value.
fn verify_sha256(body: &[u8], expected_hex: &str) -> bool {
    use sha2::{Digest, Sha256};
    let got = hex::encode(Sha256::digest(body));
    !expected_hex.is_empty() && got.eq_ignore_ascii_case(expected_hex)
}

/// POST /api/v1/evidence -- the on-host agent streams a captured RAM image (or IR
/// evidence) OUTBOUND over HTTPS. JWT-gated, HMAC-verified, SHA-256 custody-checked,
/// then streamed into the WORM archive; a small verified handle is published to
/// `nexus.memory.intake` so worker_memory pulls + re-checks before analysis.
async fn handle_evidence_upload(
    State(state): State<Arc<AppState>>,
    headers: header::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if validate_token(&headers, &state.jwt_secret).is_err() {
        counter!("nexus_ingress_auth_failures_total").increment(1);
        return StatusCode::UNAUTHORIZED;
    }
    let store = match &state.evidence_store {
        Some(s) => s,
        None => return StatusCode::SERVICE_UNAVAILABLE,   // WORM archive not configured
    };
    if body.len() > state.max_evidence_bytes {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let incident_id = hdr_str(&headers, "X-Incident-Id").unwrap_or("");
    let host = hdr_str(&headers, HDR_SENSOR_ID).unwrap_or("");
    let os_family = hdr_str(&headers, HDR_OS_FAMILY).unwrap_or("");
    let kind = hdr_str(&headers, HDR_EVIDENCE_KIND).unwrap_or("memory_image");
    let sha256 = hdr_str(&headers, HDR_ARTIFACT_SHA256).unwrap_or("");
    let provided_hmac = match hdr_str(&headers, HDR_ARTIFACT_HMAC) {
        Some(h) => h,
        None => return StatusCode::BAD_REQUEST,
    };
    if incident_id.is_empty() || host.is_empty() || sha256.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    // Verify BEFORE the bytes touch the archive: HMAC (authenticity) + SHA-256 (custody).
    if !verify_artifact_hmac(&state.integrity_secret, &body, provided_hmac) {
        counter!("nexus_ingress_hmac_failures_total").increment(1);
        return StatusCode::FORBIDDEN;
    }
    if !verify_sha256(&body, sha256) {
        counter!("nexus_ingress_custody_failures_total").increment(1);
        error!(incident_id, "evidence SHA-256 custody mismatch -- rejecting");
        return StatusCode::FORBIDDEN;
    }

    // Stream into the WORM archive (GOVERNANCE-default bucket) under a stable key.
    let key = format!("memory/{incident_id}/{host}/image");
    if let Err(e) = store.put(&ObjPath::from(key.clone()), body.clone().into()).await {
        error!(error = %e, incident_id, "WORM evidence write failed");
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    counter!("nexus_ingress_evidence_verified_total").increment(1);

    // Publish the small verified handle; worker_memory pulls + re-verifies custody.
    let handle = serde_json::json!({
        "incident_id": incident_id, "host": host, "os_family": os_family,
        "kind": kind, "sha256": sha256, "s3_key": key, "size": body.len(),
    });
    match state.js.publish("nexus.memory.intake".to_string(),
                           serde_json::to_vec(&handle).unwrap_or_default().into()).await {
        Ok(_) => { info!(incident_id, "evidence verified → WORM + nexus.memory.intake"); StatusCode::ACCEPTED }
        Err(e) => { error!(error = %e, "memory.intake publish rejected"); StatusCode::SERVICE_UNAVAILABLE }
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
#[cfg(test)]
mod ratelimit_tests {
    use super::{surge_step, RateLimiter};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)) }

    #[test]
    fn flood_from_one_ip_is_throttled_after_burst() {
        // capacity 5, no refill within the burst -> first 5 allowed, rest denied.
        let rl = RateLimiter::new(0.0, 5.0);
        let allowed = (0..100).filter(|_| rl.allow(ip(1))).count();
        assert_eq!(allowed, 5, "burst capacity must cap a single-source flood");
    }

    #[test]
    fn fleet_wide_traffic_is_isolated_per_ip() {
        // each distinct sensor IP gets its own bucket: a fleet surge does not trip.
        let rl = RateLimiter::new(0.0, 5.0);
        let denied = (0..50).filter(|n| !rl.allow(ip(*n as u8))).count();
        assert_eq!(denied, 0, "distinct sources must not share a bucket");
    }

    #[test]
    fn surge_detector_flags_extreme_deviation_not_normal_growth() {
        // baseline ~1 rps; a 2x bump is normal growth (no surge), a 100x spike is.
        let (ewma, _) = surge_step(0.0, 0.0, 1.0, 0.2, 10.0, 50.0);   // seed at 1 rps
        let (_, normal) = surge_step(ewma, 1.0, 1.5, 0.2, 10.0, 50.0); // ~2 rps
        assert!(!normal, "a modest increase must not read as an attack");
        let (_, surge) = surge_step(ewma, 1.0, 1.005, 0.2, 10.0, 50.0); // ~200 rps
        assert!(surge, "an extreme spike above baseline + floor must surge");
    }

    #[test]
    fn quiet_sensor_first_events_never_surge() {
        let (_, s) = surge_step(0.0, 0.0, 0.001, 0.2, 10.0, 50.0);
        assert!(!s, "no baseline yet -> never a surge");
    }
}
