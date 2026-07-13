// Middleware Ingress -- accepts Parquet from sensors, verifies HMAC integrity,
// and fans out to internal JetStream. Enabled destination workers consume independently.

mod config;
mod integrity;

use crate::config::MiddlewareConfig;
use crate::integrity::{IntegrityVerifier, extract_parquet_column_names, HDR_BATCH_HMAC, HDR_BATCH_SEQUENCE, HDR_BATCH_TIMESTAMP, HDR_SENSOR_ID, HDR_SENSOR_TYPE};

use async_nats::HeaderMap;
use axum::{body::Bytes, extract::State, http::{header, StatusCode}, response::IntoResponse, routing::post, Router};
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal::unix::{signal, SignalKind};
use tower::{limit::ConcurrencyLimitLayer, timeout::TimeoutLayer};
use tracing::{error, info, warn, Level};

struct AppState {
    js: async_nats::jetstream::Context,
    config: MiddlewareConfig,
    verifier: IntegrityVerifier,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).with_target(false).init();

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
        .expect("NATS connection failed");
    let js = async_nats::jetstream::new(client);

    // Ensure stream exists
    js.get_or_create_stream(async_nats::jetstream::stream::Config {
        name: config.global.stream_name.clone(),
        subjects: vec![format!("{}.*", config.global.telemetry_subject)],
        ..Default::default()
    }).await.expect("Failed to create JetStream stream");

    let state = Arc::new(AppState { js, config: config.clone(), verifier });
    let app = Router::new()
        .route("/api/v1/telemetry", post(handle_telemetry))
        .route("/healthz", axum::routing::get(|| async { StatusCode::OK }))
        .layer(ConcurrencyLimitLayer::new(4096))
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .with_state(state);

    let addr: SocketAddr = config.ingress.bind_addr.parse().expect("Invalid bind_addr");

    if config.ingress.tls_enabled {
        let cert_path = config.ingress.tls_cert_path.as_deref().expect("tls_cert_path required");
        let key_path = config.ingress.tls_key_path.as_deref().expect("tls_key_path required");
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
            .await.expect("TLS cert load failed");

        info!("Middleware Ingress HTTPS on {} | Metrics :9000", addr);

        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await.unwrap();
    } else {
        info!("Middleware Ingress HTTP on {} | Metrics :9000", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
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

    // 1. Auth
    let auth = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok());
    if auth != Some(&format!("Bearer {}", state.config.ingress.auth_token)) {
        counter!("middleware_ingress_auth_failures_total").increment(1);
        return StatusCode::UNAUTHORIZED;
    }

    // 2. Content type
    let ct = headers.get(header::CONTENT_TYPE).and_then(|h| h.to_str().ok()).unwrap_or("");
    if ct != "application/vnd.apache.parquet" {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE;
    }

    // 3. Payload size
    if payload_size > state.config.ingress.max_payload_bytes {
        counter!("middleware_ingress_payload_too_large_total").increment(1);
        return StatusCode::PAYLOAD_TOO_LARGE;
    }

    // 4. Extract integrity headers
    let sensor_type = hdr_str(&headers, HDR_SENSOR_TYPE).unwrap_or("unclassified");
    let sensor_id = match hdr_str(&headers, HDR_SENSOR_ID) {
        Some(id) => id,
        None => return StatusCode::BAD_REQUEST,
    };
    let sequence: u64 = match hdr_str(&headers, HDR_BATCH_SEQUENCE).and_then(|s| s.parse().ok()) {
        Some(s) => s,
        None => return StatusCode::BAD_REQUEST,
    };
    let timestamp: u64 = match hdr_str(&headers, HDR_BATCH_TIMESTAMP).and_then(|s| s.parse().ok()) {
        Some(t) => t,
        None => return StatusCode::BAD_REQUEST,
    };
    let hmac_hex = match hdr_str(&headers, HDR_BATCH_HMAC) {
        Some(h) => h,
        None => return StatusCode::BAD_REQUEST,
    };

    // 5. Parquet column introspection
    let columns = match extract_parquet_column_names(&body) {
        Ok(c) => c,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    // 6. HMAC + sequence + temporal + cross-schema verification
    if let Err(violation) = state.verifier.verify_batch(
        &body, sequence, timestamp, sensor_id, sensor_type, hmac_hex, &columns,
    ) {
        error!("[INTEGRITY] {}", violation);
        return match violation {
            integrity::IntegrityViolation::SensorBanned { .. }
            | integrity::IntegrityViolation::CrossOsCollision { .. } => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        };
    }

    // 7. Publish to internal JetStream with sensor metadata in headers
    let subject = format!("{}.{}", state.config.global.telemetry_subject, sensor_type);
    let mut nats_headers = HeaderMap::new();
    nats_headers.insert(HDR_SENSOR_ID, sensor_id);
    nats_headers.insert(HDR_SENSOR_TYPE, sensor_type);
    nats_headers.insert(HDR_BATCH_SEQUENCE, &sequence.to_string());

    match state.js.publish_with_headers(subject.clone(), nats_headers, body.into()).await {
        Ok(_) => {
            counter!("middleware_ingress_accepted_total").increment(1);
            counter!("middleware_ingress_bytes_accepted_total").increment(payload_size as u64);
            info!("{} bytes from '{}' (seq {}) → {}", payload_size, sensor_id, sequence, subject);
            StatusCode::ACCEPTED
        }
        Err(e) => {
            error!("JetStream publish failed: {}", e);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
