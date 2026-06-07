pub mod db;
pub mod routes;
pub mod auth;

use axum::{
    http::{header, HeaderValue},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};
use axum_server::tls_rustls::RustlsConfig;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use shared_models::config::CONFIG;

pub struct AppState {
    pub db: db::DatabaseManager,
}

pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let shared_state = Arc::new(AppState {
        db: db::DatabaseManager::new(),
    });

    if let Some(ref auth_db) = shared_state.db.auth_db {
        let conn = auth_db.lock().unwrap();
        auth::init_auth_db(&conn);
    }

    let static_path = &CONFIG.api_dashboard.static_ui_path;
    let index_path = format!("{}/index.html", static_path);

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(50)
            .burst_size(100)
            .finish()
            .unwrap(),
    );

    let app = Router::new()
        .route("/api/v2/metrics", get(routes::metrics::get_metrics))
        .route("/api/v2/anomalies", get(routes::telemetry::get_anomalies))
        .route("/api/v2/profiles", get(routes::profiles::get_profiles))
        .route("/api/v2/auth/login", post(auth::login))
        .route("/api/v2/auth/change_password", post(auth::change_password))
        .layer(GovernorLayer { config: governor_conf })
        .nest_service("/static", ServeDir::new(static_path))
        .fallback_service(ServeFile::new(&index_path))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;"),
        ))
        .with_state(shared_state);

    let bind_addr = format!("{}:{}", CONFIG.api_dashboard.bind_address, CONFIG.api_dashboard.port);
    let socket_addr: std::net::SocketAddr = bind_addr.parse()?;

    let tls_config = RustlsConfig::from_pem_file(
        &CONFIG.api_dashboard.tls_cert_path,
        &CONFIG.api_dashboard.tls_key_path,
    ).await?;

    tracing::info!("[+] API Server listening securely on https://{}", bind_addr);
    axum_server::bind_rustls(socket_addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;

    Ok(())
}