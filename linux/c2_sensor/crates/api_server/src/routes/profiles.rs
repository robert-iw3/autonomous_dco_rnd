use axum::{extract::State, Json, http::StatusCode};
use shared_models::ueba::{ProcessProfile, RoleProfile};
use serde::Serialize;
use std::sync::Arc;
use crate::AppState;

#[derive(Serialize)]
pub struct UebaResponse {
    pub processes: Vec<ProcessProfile>,
    pub roles: Vec<RoleProfile>,
}

pub async fn get_profiles(State(state): State<Arc<AppState>>) -> Result<Json<UebaResponse>, StatusCode> {
    let profiles = tokio::task::spawn_blocking(move || {
        let conn = state.db.telemetry_db.lock().unwrap();

        let mut processes = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT process_hash, event_count, mean_delta, m2_delta
             FROM ueba_process_profiles
             ORDER BY event_count DESC LIMIT 100"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok(ProcessProfile {
                    process_hash: row.get(0)?,
                    event_count: row.get(1)?,
                    mean_delta: row.get(2)?,
                    m2_delta: row.get(3)?,
                })
            }) {
                for row in rows.flatten() {
                    processes.push(row);
                }
            }
        }

        let mut roles = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT binary_name, instance_count, max_velocity, mean_entropy
             FROM ueba_role_profiles
             ORDER BY instance_count DESC LIMIT 100"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok(RoleProfile {
                    binary_name: row.get(0)?,
                    instance_count: row.get(1)?,
                    max_velocity: row.get(2)?,
                    mean_entropy: row.get(3)?,
                })
            }) {
                for row in rows.flatten() {
                    roles.push(row);
                }
            }
        }

        UebaResponse { processes, roles }
    })
    .await
    .unwrap_or_else(|_| UebaResponse { processes: vec![], roles: vec![] });

    Ok(Json(profiles))
}