use axum::{extract::State, Json, http::StatusCode};
use shared_models::api_models::{MetricsResponse, HourlyMetric};
use std::sync::Arc;
use crate::AppState;

pub async fn get_metrics(State(state): State<Arc<AppState>>) -> Result<Json<MetricsResponse>, StatusCode> {
    let metrics = tokio::task::spawn_blocking(move || {
        let conn = state.db.telemetry_db.lock().unwrap();

        // 1. Total Events
        let total: u64 = conn.query_row("SELECT COUNT(*) FROM flows", [], |row| row.get(0)).unwrap_or(0);

        // 2. Critical Anomalies (Score >= 90)
        let crit: u32 = conn.query_row("SELECT COUNT(*) FROM flows WHERE score >= 90", [], |row| row.get(0)).unwrap_or(0);

        // 3. Active Mitigations (from persisted mitigations table)
        let mitigations: u32 = conn.query_row(
            "SELECT COUNT(*) FROM mitigations", [], |row| row.get(0)
        ).unwrap_or(0);

        // 4. Hourly Distribution (SQLite aggregation for the bar chart)
        let mut distribution = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT strftime('%H:00', timestamp, 'unixepoch', 'localtime') as hour, COUNT(*)
             FROM flows
             WHERE timestamp >= unixepoch() - 86400
             GROUP BY hour ORDER BY hour ASC"
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok(HourlyMetric {
                    hour: row.get(0)?,
                    count: row.get(1)?,
                })
            }) {
                for row in rows.flatten() {
                    distribution.push(row);
                }
            }
        }

        MetricsResponse {
            total_events: total,
            critical_anomalies: crit,
            active_mitigations: mitigations,
            status: "ONLINE".to_string(),
            hourly_distribution: distribution,
        }
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(metrics))
}