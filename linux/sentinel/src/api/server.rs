// =================================================================================
// File:        server.rs
// Component:   Linux Sentinel -- Embedded Agent API
// Description: An Axum-based asynchronous REST API running inside the core agent.
// Role:        Provides a secure control plane (TLS + Bearer Token) for local
//              orchestration and QA. Exposes endpoints for health monitoring,
//              telemetry extraction, and triggering live hot-reloads of YARA/Sigma
//              rules via Tokio broadcast channels. Implements constant-time
//              string comparison to prevent authentication timing attacks.
// Author:      Robert Weber
// =================================================================================

use crate::config::MasterConfig;
use anyhow::Result;
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use sqlx::{Pool, Sqlite};
use std::sync::{Arc, RwLock};
use axum_server::tls_rustls::RustlsConfig;
use crate::ReloadCommand;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use subtle::ConstantTimeEq;
use std::path::PathBuf;

struct AppState {
    db_pool: Pool<Sqlite>,
    config: Arc<RwLock<MasterConfig>>,
    reload_tx: broadcast::Sender<ReloadCommand>,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    version: String,
    engine_mode: String,
    active_modules: Vec<String>,
}

pub struct ApiServer {
    config: Arc<RwLock<MasterConfig>>,
    db_pool: Pool<Sqlite>,
    reload_tx: broadcast::Sender<ReloadCommand>,
}

impl ApiServer {
    pub fn new(config: Arc<RwLock<MasterConfig>>, db_pool: Pool<Sqlite>, reload_tx: broadcast::Sender<ReloadCommand>) -> Self {
        Self { config, db_pool, reload_tx }
    }

    pub async fn run(self) -> Result<()> {
        let shared_state = Arc::new(AppState {
            db_pool: self.db_pool,
            config: self.config.clone(),
            reload_tx: self.reload_tx.clone(),
        });

        let health_routes = Router::new()
            .route("/api/status", get(status_handler))
            .with_state(shared_state.clone());

        let protected_routes = Router::new()
            .route("/api/alerts", get(alerts_handler))
            .route("/api/rules/reload", post(reload_rules_handler))
            .route("/api/config/reload", post(reload_config_handler))
            .layer(middleware::from_fn_with_state(shared_state.clone(), auth_middleware))
            .with_state(shared_state);

        let app = health_routes.merge(protected_routes);

        let (bind_addr, port, tls_cert, tls_key) = {
            let lock = self.config.read().unwrap_or_else(|e| e.into_inner());
            (lock.api.bind_addr.clone(), lock.api.port, lock.api.tls_cert.clone(), lock.api.tls_key.clone())
        };

        let addr: std::net::SocketAddr = format!("{}:{}", bind_addr, port).parse()?;

        if !tls_cert.is_empty() && !tls_key.is_empty() {
            info!(addr = %addr, "Secure Dashboard API online (TLS Enabled)");
            let tls_config = RustlsConfig::from_pem_file(PathBuf::from(tls_cert), PathBuf::from(tls_key)).await?;
            if let Err(e) = axum_server::bind_rustls(addr, tls_config).serve(app.into_make_service()).await {
                error!(error = %e, "API Server fatal error");
            }
        } else {
            warn!("API server running without TLS. Bearer tokens are transmitted in cleartext.");
            info!(addr = %addr, "Dashboard API online (HTTP)");
            if let Err(e) = axum_server::bind(addr).serve(app.into_make_service()).await {
                error!(error = %e, "API Server fatal error");
            }
        }

        Ok(())
    }
}

/// Constant-time comparison using compiler barriers
fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("Authorization");
    let expected_token = {
        let lock = state.config.read().unwrap_or_else(|e| e.into_inner());
        format!("Bearer {}", lock.siem.auth_token)
    };

    if let Some(header_value) = auth_header {
        let provided_token = header_value.as_bytes();
        if secure_compare(provided_token, expected_token.as_bytes()) {
            return Ok(next.run(req).await);
        }
    }

    warn!("Unauthorized API access attempt blocked.");
    Err(StatusCode::UNAUTHORIZED)
}

async fn reload_rules_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    info!("API Command: Rule reload requested.");
    if state.reload_tx.send(ReloadCommand::Rules).is_ok() {
        Json(serde_json::json!({ "success": true, "message": "Rule reload broadcast dispatched" }))
    } else {
        Json(serde_json::json!({ "success": false, "error": "Internal broadcast failure" }))
    }
}

async fn reload_config_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    info!("API Command: Configuration reload requested.");
    if state.reload_tx.send(ReloadCommand::Config).is_ok() {
        Json(serde_json::json!({ "success": true, "message": "Config reload broadcast dispatched" }))
    } else {
        Json(serde_json::json!({ "success": false, "error": "Internal broadcast failure" }))
    }
}

async fn status_handler() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "Operational".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        engine_mode: "Decoupled".to_string(),
        active_modules: vec!["eBPF".to_string(), "YARA".to_string(), "Honeypot".to_string()],
    })
}

async fn alerts_handler(axum::extract::State(state): axum::extract::State<Arc<AppState>>) -> Json<serde_json::Value> {
    use sqlx::Row;
    let result = sqlx::query("SELECT event_id, timestamp, level, message, mitre_tactic, mitre_technique, container_id, container_name, user_name, parent_comm, source_port FROM events ORDER BY timestamp DESC LIMIT 100")
        .fetch_all(&state.db_pool).await;

    match result {
        Ok(records) => {
            let alerts: Vec<_> = records.into_iter().map(|rec| {
                serde_json::json!({
                    "id": rec.try_get::<String, _>("event_id").unwrap_or_default(),
                    "timestamp": rec.try_get::<i64, _>("timestamp").unwrap_or_default(),
                    "level": rec.try_get::<String, _>("level").unwrap_or_default(),
                    "message": rec.try_get::<String, _>("message").unwrap_or_default(),
                    "tactic": rec.try_get::<String, _>("mitre_tactic").unwrap_or_default(),
                    "technique": rec.try_get::<String, _>("mitre_technique").unwrap_or_default(),
                    "container_id": rec.try_get::<String, _>("container_id").unwrap_or_default(),
                    "container_name": rec.try_get::<String, _>("container_name").unwrap_or_default(),
                    "user_name": rec.try_get::<String, _>("user_name").unwrap_or_default(),
                    "parent_comm": rec.try_get::<String, _>("parent_comm").unwrap_or_default(),
                    "source_port": rec.try_get::<i32, _>("source_port").unwrap_or_default()
                })
            }).collect();
            Json(serde_json::json!({ "success": true, "count": alerts.len(), "data": alerts }))
        }
        Err(e) => {
            error!(error = %e, "API Database query failed");
            Json(serde_json::json!({ "success": false, "error": "Internal Database Error" }))
        }
    }
}