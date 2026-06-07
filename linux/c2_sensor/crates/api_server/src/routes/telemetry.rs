use axum::{extract::{State, Query}, Json, http::StatusCode};
use shared_models::anomalies::Detection;
use std::sync::Arc;
use crate::AppState;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct AlertQuery {
    pub limit: Option<usize>,
    pub min_score: Option<u32>,
}

pub async fn get_anomalies(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AlertQuery>,
) -> Result<Json<Vec<Detection>>, StatusCode> {
    let limit = params.limit.unwrap_or(250);
    let min_score = params.min_score.unwrap_or(0);

    let anomalies = tokio::task::spawn_blocking(move || {
        let conn = state.db.telemetry_db.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT
                timestamp, dst_ip, dst_port, process_name, pid,
                mitre_tactic, interval, cv, outbound_ratio, entropy,
                cmd_snippet, process_tree, masquerade_detected,
                ml_result, score, reasons, mitre_technique, mitre_name,
                description, uid, process_hash, dns_query, dns_flags, event_type
             FROM flows
             WHERE score >= ?1 AND suppressed = 0
             ORDER BY timestamp DESC
             LIMIT ?2"
        ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let row_iter = stmt.query_map([min_score as u32, limit as u32], |row| {
            let ts: f64 = row.get(0)?;
            let timestamp = chrono::DateTime::from_timestamp(ts as i64, 0)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default();

            let reasons_str: String = row.get(15).unwrap_or_else(|_| "[]".to_string());
            let reasons: Vec<String> = serde_json::from_str(&reasons_str).unwrap_or_default();

            Ok(Detection {
                timestamp,
                dst_ip: row.get(1).unwrap_or_else(|_| "0.0.0.0".to_string()),
                dst_port: row.get(2).unwrap_or(0),
                process: row.get(3).unwrap_or_else(|_| "unknown".to_string()),
                pid: row.get(4).unwrap_or(0),
                mitre_tactic: row.get(5).unwrap_or_else(|_| "Unknown".to_string()),
                avg_interval_sec: row.get(6).unwrap_or(0.0),
                cv: row.get(7).unwrap_or(0.0),
                outbound_ratio: row.get(8).unwrap_or(0.0),
                entropy: row.get(9).unwrap_or(0.0),
                cmd_snippet: row.get(10).unwrap_or_else(|_| "".to_string()),
                process_tree: row.get(11).unwrap_or_else(|_| "".to_string()),
                masquerade_detected: row.get(12).unwrap_or(false),
                ml_result: row.get(13).ok(),
                score: row.get(14).unwrap_or(0),
                reasons,
                mitre_technique: row.get(16).unwrap_or_else(|_| "".to_string()),
                mitre_name: row.get(17).unwrap_or_else(|_| "".to_string()),
                description: row.get(18).unwrap_or_else(|_| "".to_string()),
                uid: row.get(19).unwrap_or(0),
                process_hash: row.get(20).unwrap_or_else(|_| "".to_string()),
                dns_query: row.get(21).unwrap_or_else(|_| "".to_string()),
                dns_flags: row.get(22).unwrap_or(0),
                event_type: row.get(23).unwrap_or_else(|_| "unknown".to_string()),
            })
        }).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut results = Vec::new();
        for detection in row_iter {
            if let Ok(d) = detection {
                results.push(d);
            }
        }
        Ok(results)
    })
    .await
    .unwrap_or_else(|_| Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(anomalies))
}