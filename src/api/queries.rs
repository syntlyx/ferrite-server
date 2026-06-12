use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::ApiError;
use crate::app::AppState;
use crate::clients::{parse_ip, ClientRegistry};
use crate::dns::types::QueryEntry;
use crate::storage::QueryFilter;

#[derive(Deserialize, Default)]
pub struct ListQueriesParams {
    pub from_ts: Option<i64>,
    pub to_ts: Option<i64>,
    pub domain: Option<String>,
    pub client_ip: Option<String>,
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub before_id: Option<u64>,
    pub before_ts: Option<i64>,
    pub after_id: Option<u64>,
}

/// `QueryEntry` enriched with a resolved client hostname.
#[derive(Serialize)]
struct QueryEntryResponse {
    #[serde(flatten)]
    entry: QueryEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
}

/// GET /api/queries
///
/// Without filters or pagination: served from the in-memory ring buffer (always live).
/// With `after_id`: delta poll — only ring-buffer entries newer than the cursor
/// (all other filters are ignored; if the response hits `limit`, the client
/// should fall back to a full refresh because older unseen entries may exist).
/// With any filter, offset, or before_* cursor: falls through to storage for historical queries.
pub async fn list_queries(
    State(state): State<AppState>,
    Query(params): Query<ListQueriesParams>,
) -> Result<Json<Value>, ApiError> {
    if let Some(after_id) = params.after_id {
        let limit = params.limit.unwrap_or(100).min(1000);
        let entries = state
            .inner
            .live_stats
            .recent_queries
            .recent_after(after_id, limit);
        return Ok(Json(serde_json::to_value(enrich(&state, entries))?));
    }

    let has_filters = params.from_ts.is_some()
        || params.to_ts.is_some()
        || params.domain.is_some()
        || params.client_ip.is_some()
        || params.status.is_some()
        || params.offset.unwrap_or(0) > 0
        || params.before_id.is_some()
        || params.before_ts.is_some();

    let entries: Vec<QueryEntry> = if has_filters {
        let filter = QueryFilter {
            from_ts: params.from_ts,
            to_ts: params.to_ts,
            domain: params.domain,
            client_ips: params
                .client_ip
                .map(|s| {
                    s.split(',')
                        .map(|p| p.trim().to_string())
                        .filter(|p| !p.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            status: params.status,
            limit: Some(params.limit.unwrap_or(100).min(1000)),
            offset: params.offset,
            before_id: params.before_id,
            before_ts: params.before_ts,
        };
        state.inner.storage.query_range(&filter).await?
    } else {
        let limit = params.limit.unwrap_or(100).min(1000);
        let from_ring = state.inner.live_stats.recent_queries.recent(limit);

        if from_ring.len() < limit {
            // Ring buffer doesn't have enough entries (server just started or low traffic).
            // Supplement with SQLite, deduplicating by entry ID.
            let remaining = limit - from_ring.len();
            let ring_ids: std::collections::HashSet<u64> = from_ring.iter().map(|e| e.id).collect();

            let db_entries = state
                .inner
                .storage
                .query_range(&QueryFilter {
                    limit: Some(limit),
                    ..Default::default()
                })
                .await?;

            let extra: Vec<QueryEntry> = db_entries
                .into_iter()
                .filter(|e| !ring_ids.contains(&e.id))
                .take(remaining)
                .collect();

            [from_ring, extra].concat()
        } else {
            from_ring
        }
    };

    Ok(Json(serde_json::to_value(enrich(&state, entries))?))
}

/// Trigger background PTR resolution for any IP not yet in cache, then
/// read whatever name is already available (non-blocking).
fn enrich(state: &AppState, entries: Vec<QueryEntry>) -> Vec<QueryEntryResponse> {
    entries
        .into_iter()
        .map(|entry| {
            let client_name = parse_ip(&entry.client_ip).and_then(|ip| {
                ClientRegistry::trigger_resolve(&state.inner.client_registry, ip);
                state.inner.client_registry.get_name(ip)
            });
            QueryEntryResponse { entry, client_name }
        })
        .collect()
}

/// DELETE /api/queries — purge the entire query log (SQLite + in-memory).
pub async fn delete_queries(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    state.inner.storage.delete_all_queries().await?;
    state.inner.live_stats.reset_all();
    tracing::info!("query log cleared");
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "status": "cleared" })),
    ))
}
