mod config;
mod integrity;

use crate::config::MiddlewareConfig;
use crate::integrity::{IntegrityVerifier, IntegrityViolation, extract_parquet_column_names,
    HDR_BATCH_HMAC, HDR_BATCH_SEQUENCE, HDR_BATCH_TIMESTAMP, HDR_SENSOR_ID, HDR_SENSOR_TYPE};

use async_nats::HeaderMap;
use axum::{body::Bytes, extract::State, http::{header, StatusCode}, response::IntoResponse, routing::{get, post}, Router};
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal::unix::{signal, SignalKind};
use tower::{BoxError, ServiceBuilder};
use axum::error_handling::HandleErrorLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info, warn, Level};
use tracing_subscriber::EnvFilter;

struct AppState {
    js: async_nats::jetstream::Context,
    config: MiddlewareConfig,
    verifier: IntegrityVerifier,
    expected_auth: String, // #13: pre-computed "Bearer <token>"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .with_target(false)
        .init();

    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], 9000))
        .install()
        .expect("Prometheus init failed");

    let config_path = std::env::var("MIDDLEWARE_CONFIG")
        .unwrap_or_else(|_| "/config/middleware.toml".to_string());
    let config = MiddlewareConfig::load(&config_path);

    let verifier = IntegrityVerifier::new(
        config.ingress.integrity_secret.as_bytes(),
        config.ingress.integrity_ban_threshold,
    );

    let client = async_nats::connect(&config.global.nats_url).await
        .unwrap_or_else(|e| { error!("NATS connect failed: {}", e); std::process::exit(1); });
    let js = async_nats::jetstream::new(client);

    // Create telemetry stream
    js.get_or_create_stream(async_nats::jetstream::stream::Config {
        name: config.global.stream_name.clone(),
        subjects: vec![format!("{}.*", config.global.telemetry_subject)],
        ..Default::default()
    }).await.expect("Failed to create telemetry stream");

    // #9: Create DLQ stream
    let dlq_wildcard = format!("{}.>", config.global.dlq_subject_prefix);
    let dlq_stream_name = format!("{}_DLQ", config.global.stream_name);
    if let Err(e) = js.get_or_create_stream(async_nats::jetstream::stream::Config {
        name: dlq_stream_name, subjects: vec![dlq_wildcard], ..Default::default()
    }).await {
        warn!("DLQ stream creation failed (non-fatal): {}", e);
    }

    // #13: pre-compute auth string
    let expected_auth = format!("Bearer {}", config.ingress.auth_token);

    let state = Arc::new(AppState { js, config: config.clone(), verifier, expected_auth });

    // Production hardening layers (applied outermost-first in axum 0.8):
    //   1. Body size guard -- reject oversized payloads before reading into memory
    //   2. Timeout -- shed connections that stall (protect against slow-POST attacks)
    //   3. Concurrency cap -- back-pressure at 8192 in-flight requests; prevents
    //      memory exhaustion during 50k-endpoint reconnect storms
    // HandleErrorLayer converts BoxError (from Timeout) back to an axum response.
    let app = Router::new()
        .route("/api/v1/telemetry", post(handle_telemetry))
        .route("/healthz", get(|| async { StatusCode::OK }))
        .layer(RequestBodyLimitLayer::new(config.ingress.max_payload_bytes))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    StatusCode::REQUEST_TIMEOUT
                }))
                .timeout(Duration::from_secs(30))
                .concurrency_limit(8192),
        )
        .with_state(state);

    let addr: SocketAddr = config.ingress.bind_addr.parse().expect("Invalid bind_addr");

    // #14: graceful shutdown for both TLS and plain paths
    let shutdown = async {
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT");
        tokio::select! {
            _ = sigterm.recv() => info!("SIGTERM received"),
            _ = sigint.recv() => info!("SIGINT received"),
        }
    };

    if config.ingress.tls_enabled {
        let cert_path = config.ingress.tls_cert_path.as_deref().expect("tls_cert_path required");
        let key_path = config.ingress.tls_key_path.as_deref().expect("tls_key_path required");
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
            .await.expect("TLS cert load failed");

        info!("Middleware Ingress HTTPS on {} | Metrics :9000", addr);

        let handle = axum_server::Handle::new();
        let handle_clone = handle.clone();
        tokio::spawn(async move { shutdown.await; handle_clone.graceful_shutdown(Some(Duration::from_secs(10))); });

        axum_server::bind_rustls(addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await.unwrap();
    } else {
        info!("Middleware Ingress HTTP on {} | Metrics :9000", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await.unwrap();
    }
    info!("Ingress shutdown complete.");
}

/// Constant-time comparison (#12)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hdr_str<'a>(headers: &'a header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

async fn handle_telemetry(
    State(state): State<Arc<AppState>>,
    headers: header::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let payload_size = body.len();
    counter!("middleware_ingress_requests_total").increment(1);

    // #12: constant-time auth check with pre-computed string (#13)
    let auth = headers.get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !constant_time_eq(auth.as_bytes(), state.expected_auth.as_bytes()) {
        counter!("middleware_ingress_auth_failures_total").increment(1);
        return StatusCode::UNAUTHORIZED;
    }

    let ct = headers.get(header::CONTENT_TYPE).and_then(|h| h.to_str().ok()).unwrap_or("");
    if ct != "application/vnd.apache.parquet" {
        counter!("middleware_ingress_invalid_content_type_total").increment(1);
        return StatusCode::UNSUPPORTED_MEDIA_TYPE;
    }

    // Note: body size already enforced by RequestBodyLimitLayer (#19)

    let sensor_type = hdr_str(&headers, HDR_SENSOR_TYPE).unwrap_or("unclassified");
    let sensor_id = match hdr_str(&headers, HDR_SENSOR_ID) {
        Some(id) => id, None => return StatusCode::BAD_REQUEST,
    };
    let sequence: u64 = match hdr_str(&headers, HDR_BATCH_SEQUENCE).and_then(|s| s.parse().ok()) {
        Some(s) => s, None => return StatusCode::BAD_REQUEST,
    };
    let timestamp: u64 = match hdr_str(&headers, HDR_BATCH_TIMESTAMP).and_then(|s| s.parse().ok()) {
        Some(t) => t, None => return StatusCode::BAD_REQUEST,
    };
    let hmac_hex = match hdr_str(&headers, HDR_BATCH_HMAC) {
        Some(h) => h, None => return StatusCode::BAD_REQUEST,
    };

    let columns = match extract_parquet_column_names(&body) {
        Ok(c) => c,
        Err(e) => {
            counter!("middleware_ingress_parquet_parse_failures_total").increment(1);
            error!("[INTEGRITY] Unreadable Parquet from '{}': {}", sensor_id, e);
            return StatusCode::BAD_REQUEST;
        }
    };

    if let Err(violation) = state.verifier.verify_batch(
        &body, sequence, timestamp, sensor_id, sensor_type, hmac_hex, &columns,
    ) {
        error!("[INTEGRITY] {}", violation);
        return match violation {
            IntegrityViolation::SensorBanned { .. }
            | IntegrityViolation::CrossOsCollision { .. } => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        };
    }

    counter!("middleware_ingress_integrity_verified_total").increment(1);

    let subject = format!("{}.{}", state.config.global.telemetry_subject, sensor_type);
    let mut nats_headers = HeaderMap::new();
    let seq_str = sequence.to_string();
    nats_headers.insert(HDR_SENSOR_ID, sensor_id);
    nats_headers.insert(HDR_SENSOR_TYPE, sensor_type);
    nats_headers.insert(HDR_BATCH_SEQUENCE, seq_str.as_str());

    // Hive partition hints -- consumed by worker_s3_archive to build dt=YYYY-MM-DD/hour=HH/ paths
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let partition_date = {
        let days = secs / 86400;
        let y = 1970 + days / 365;
        let m = (days % 365) / 30 + 1;
        let d = (days % 365) % 30 + 1;
        format!("{:04}-{:02}-{:02}", y, m, d)
    };
    let partition_hour = format!("{:02}", (secs % 86400) / 3600);
    nats_headers.insert("X-Partition-Date", partition_date.as_str());
    nats_headers.insert("X-Partition-Hour", partition_hour.as_str());

    match state.js.publish_with_headers(subject.clone(), nats_headers, body.into()).await {
        Ok(_) => {
            counter!("middleware_ingress_accepted_total").increment(1);
            counter!("middleware_ingress_bytes_accepted_total").increment(payload_size as u64);
            StatusCode::ACCEPTED
        }
        Err(e) => {
            error!("JetStream publish failed: {}", e);
            counter!("middleware_ingress_broker_faults_total").increment(1);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
