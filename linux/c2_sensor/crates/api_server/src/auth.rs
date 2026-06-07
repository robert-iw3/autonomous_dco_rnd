use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    response::Json,
    body::Bytes,
};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::AppState;
use shared_models::config::CONFIG;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordPayload {
    pub new_password: String,
}

pub fn init_auth_db(conn: &rusqlite::Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            must_change_pwd BOOLEAN DEFAULT 0
        );"
    ).unwrap_or_else(|e| tracing::warn!("[-] Auth table init: {}", e));

    let has_admin: bool = conn
        .query_row("SELECT COUNT(*) FROM users WHERE username = 'admin'", [], |row| row.get::<_, u32>(0))
        .map(|c| c > 0)
        .unwrap_or(false);

    if !has_admin {
        let pass = CONFIG.api_dashboard.default_admin_password.as_deref().unwrap_or("admin");
        if let Ok(hash) = bcrypt::hash(pass, bcrypt::DEFAULT_COST) {
            let _ = conn.execute(
                "INSERT INTO users (username, password_hash, role, must_change_pwd) VALUES (?1, ?2, 'admin', 1)",
                rusqlite::params!["admin", hash],
            );
            tracing::info!("[+] Admin user seeded in auth_db");
        }
    }
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<AuthResponse>, StatusCode> {
    let body_str = String::from_utf8_lossy(&body);
    tracing::info!("[AUTH] Raw body ({} bytes): {}", body.len(), body_str);

    let payload: LoginPayload = serde_json::from_slice(&body).map_err(|e| {
        tracing::error!("[AUTH] JSON parse failed: {}. Body was: {}", e, body_str);
        StatusCode::BAD_REQUEST
    })?;

    tracing::info!("[AUTH] Parsed login for '{}'", payload.username);

    if let Some(ref auth_db) = state.db.auth_db {
        let conn = auth_db.lock().unwrap();
        let result = conn.query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            [&payload.username],
            |row| row.get::<_, String>(0),
        );
        if let Ok(stored_hash) = result {
            if bcrypt::verify(&payload.password, &stored_hash).unwrap_or(false) {
                tracing::info!("[AUTH] '{}' verified via auth_db", payload.username);
                return Ok(Json(make_token(&payload.username)?));
            }
            tracing::warn!("[AUTH] bcrypt mismatch for '{}', trying config fallback", payload.username);
        } else {
            tracing::info!("[AUTH] '{}' not in auth_db, trying config fallback", payload.username);
        }
    }

    let expected_pass = CONFIG.api_dashboard.default_admin_password.as_deref().unwrap_or("admin");

    if payload.username == "admin" && payload.password == expected_pass {
        tracing::info!("[AUTH] '{}' verified via config fallback", payload.username);
        return Ok(Json(make_token("admin")?));
    }

    tracing::warn!("[AUTH] REJECTED '{}'", payload.username);
    Err(StatusCode::UNAUTHORIZED)
}

fn make_token(username: &str) -> Result<AuthResponse, StatusCode> {
    let exp = (chrono::Utc::now() + chrono::Duration::hours(12)).timestamp() as usize;
    let claims = Claims { sub: username.to_string(), exp };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(CONFIG.api_dashboard.jwt_secret.as_bytes()),
    ).map_err(|e| {
        tracing::error!("[AUTH] JWT encode failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(AuthResponse { token })
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = validate_token(token)?;

    let payload: ChangePasswordPayload = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let auth_db = state.db.auth_db.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let conn = auth_db.lock().unwrap();

    let new_hash = bcrypt::hash(&payload.new_password, bcrypt::DEFAULT_COST)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    conn.execute(
        "UPDATE users SET password_hash = ?1, must_change_pwd = 0 WHERE username = ?2",
        rusqlite::params![new_hash, claims.sub],
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("[+] Password rotated for '{}'", claims.sub);
    Ok(StatusCode::OK)
}

pub fn validate_token(token: &str) -> Result<Claims, StatusCode> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(CONFIG.api_dashboard.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| StatusCode::UNAUTHORIZED)
}