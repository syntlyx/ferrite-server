//! `GET /api/logs` — recent log records from the in-memory ring (no log file).

use axum::Json;
use axum::extract::Query;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::logbuf;

#[derive(Deserialize)]
pub struct LogQuery {
    /// Delta cursor: return only records with a greater id.
    #[serde(default)]
    after_id: u64,
    /// Minimum severity to include: `error` | `warn` | `info` | `debug` | `trace`.
    level: Option<String>,
    limit: Option<usize>,
}

pub async fn get_logs(Query(q): Query<LogQuery>) -> Json<Value> {
    let min_rank = q.level.as_deref().map(logbuf::rank_of).unwrap_or(0);
    let limit = q.limit.unwrap_or(500).min(2000);
    let logs = logbuf::global().recent(q.after_id, min_rank, limit);
    Json(json!({ "logs": logs }))
}
