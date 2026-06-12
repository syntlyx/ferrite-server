use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::ApiError;
use crate::app::AppState;
use crate::clients::{parse_ip, unmap_v4, ClientRegistry};
use crate::dns::types::{QueryEntry, QueryStatus};
use crate::stats::timeseries::TimeseriesBucket;

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TopClientEntry {
    pub name: String,
    pub total: u64,
    pub ips: Vec<String>,
    pub macs: Vec<String>,
}

#[derive(Serialize)]
pub struct EnrichedEntry {
    #[serde(flatten)]
    pub entry: QueryEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
}

#[derive(Serialize)]
pub struct SummaryResponse {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub cached_queries: u64,
    pub upstream_queries: u64,
    pub block_percentage: f64,
    pub total_domains_blocked: u64,
    pub top_domains: Vec<(String, u64)>,
    pub top_blocked: Vec<(String, u64)>,
    pub top_clients: Vec<TopClientEntry>,
    pub recent_domains: Vec<EnrichedEntry>,
    pub recent_blocked: Vec<EnrichedEntry>,
    pub timeseries: Vec<TimeseriesBucket>,
}

#[derive(Deserialize, Default)]
pub struct TopStatsParams {
    pub limit: Option<usize>,
    /// How many hours back to look (default 24, max 168).
    pub hours: Option<u64>,
    /// Use all retained history instead of a rolling hour window.
    pub all_time: Option<bool>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /api/stats/summary — served entirely from in-memory counters, no storage reads.
pub async fn get_summary(State(state): State<AppState>) -> Result<Json<SummaryResponse>, ApiError> {
    let live = &state.inner.live_stats;

    let top_domains = live.top_domains.top(10);
    let top_blocked = live.top_blocked.top(10);

    let top_clients = {
        struct Agg {
            total: u64,
            ips: Vec<String>,
            macs: Vec<String>,
        }
        let mut by_name: HashMap<String, Agg> = HashMap::new();
        for (ip, count) in live.top_clients.top(50) {
            let parsed = parse_ip(&ip).map(unmap_v4);
            if let Some(addr) = parsed {
                ClientRegistry::trigger_resolve(&state.inner.client_registry, addr);
            }
            let name = parsed
                .and_then(|addr| state.inner.client_registry.get_name(addr))
                .unwrap_or_else(|| ip.clone());
            let mac = parsed.and_then(|addr| state.inner.client_registry.get_mac(addr));
            let agg = by_name.entry(name).or_insert(Agg {
                total: 0,
                ips: vec![],
                macs: vec![],
            });
            agg.total += count;
            agg.ips.push(ip);
            if let Some(mac) = mac {
                push_unique(&mut agg.macs, mac);
            }
        }
        let mut merged: Vec<TopClientEntry> = by_name
            .into_iter()
            .map(|(name, agg)| TopClientEntry {
                name,
                total: agg.total,
                ips: agg.ips,
                macs: agg.macs,
            })
            .collect();
        merged.sort_unstable_by_key(|b| std::cmp::Reverse(b.total));
        merged.truncate(10);
        merged
    };

    let enrich = |entries: Vec<QueryEntry>| -> Vec<EnrichedEntry> {
        entries
            .into_iter()
            .map(|entry| {
                let client_name = parse_ip(&entry.client_ip).and_then(|ip| {
                    ClientRegistry::trigger_resolve(&state.inner.client_registry, ip);
                    state.inner.client_registry.get_name(ip)
                });
                EnrichedEntry { entry, client_name }
            })
            .collect()
    };

    let recent_domains = enrich(live.recent_queries.recent(20));
    let recent_blocked = enrich(
        live.recent_queries
            .recent_filtered(20, 500, |e| e.status == QueryStatus::Blocked),
    );

    Ok(Json(SummaryResponse {
        total_queries: live.total(),
        blocked_queries: live.blocked(),
        cached_queries: live.total_cached.load(std::sync::atomic::Ordering::Relaxed),
        upstream_queries: live
            .total_upstream
            .load(std::sync::atomic::Ordering::Relaxed),
        block_percentage: live.block_percentage(),
        total_domains_blocked: state.inner.blocklist.blocked_count(),
        top_domains,
        top_blocked,
        top_clients,
        recent_domains,
        recent_blocked,
        timeseries: live.timeseries.buckets_24h(),
    }))
}

/// GET /api/stats/timeseries — rolling 24-hour window, 10-minute buckets.
pub async fn get_timeseries(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let buckets = state.inner.live_stats.timeseries.buckets_24h();
    Ok(Json(serde_json::to_value(buckets)?))
}

/// GET /api/stats/top-domains
pub async fn get_top_domains(
    State(state): State<AppState>,
    Query(params): Query<TopStatsParams>,
) -> Result<Json<Value>, ApiError> {
    let (now, from, limit) = time_window(&params);
    let rows = state.inner.storage.top_domains(from, now, limit).await?;
    Ok(Json(domains_json(rows, from, now)))
}

/// GET /api/stats/top-blocked
pub async fn get_top_blocked(
    State(state): State<AppState>,
    Query(params): Query<TopStatsParams>,
) -> Result<Json<Value>, ApiError> {
    let (now, from, limit) = time_window(&params);
    let rows = state
        .inner
        .storage
        .top_blocked_domains(from, now, limit)
        .await?;
    Ok(Json(domains_json(rows, from, now)))
}

/// GET /api/stats/top-clients
pub async fn get_top_clients(
    State(state): State<AppState>,
    Query(params): Query<TopStatsParams>,
) -> Result<Json<Value>, ApiError> {
    let (now, from, limit) = time_window(&params);

    let clients = state
        .inner
        .storage
        .top_clients(from, now, limit * 5)
        .await?;
    struct Agg {
        total: u64,
        ips: Vec<String>,
        macs: Vec<String>,
    }
    let mut by_name: HashMap<String, Agg> = HashMap::new();
    for cs in clients {
        let parsed = parse_ip(&cs.client_ip).map(unmap_v4);
        if let Some(addr) = parsed {
            ClientRegistry::trigger_resolve(&state.inner.client_registry, addr);
        }
        let name = parsed
            .and_then(|addr| state.inner.client_registry.get_name(addr))
            .unwrap_or_else(|| cs.client_ip.clone());
        let mac = parsed.and_then(|addr| state.inner.client_registry.get_mac(addr));
        let agg = by_name.entry(name).or_insert(Agg {
            total: 0,
            ips: vec![],
            macs: vec![],
        });
        agg.total += cs.total;
        agg.ips.push(cs.client_ip);
        if let Some(mac) = mac {
            push_unique(&mut agg.macs, mac);
        }
    }
    let mut merged: Vec<TopClientEntry> = by_name
        .into_iter()
        .map(|(name, agg)| TopClientEntry {
            name,
            total: agg.total,
            ips: agg.ips,
            macs: agg.macs,
        })
        .collect();
    merged.sort_unstable_by_key(|b| std::cmp::Reverse(b.total));
    merged.truncate(limit);

    Ok(Json(
        serde_json::json!({ "clients": merged, "from_ts": from, "to_ts": now }),
    ))
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn time_window(params: &TopStatsParams) -> (i64, i64, usize) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let limit = params.limit.unwrap_or(20).min(200);
    let all_time = params.all_time.unwrap_or(false) || params.hours == Some(0);
    if all_time {
        return (now, 0, limit);
    }

    let hours = params.hours.unwrap_or(24).clamp(1, 168) as i64;
    (now, now - hours * 3600, limit)
}

fn domains_json(rows: Vec<(String, u64)>, from: i64, to: i64) -> Value {
    let entries: Vec<_> = rows
        .into_iter()
        .map(|(domain, count)| serde_json::json!({ "domain": domain, "count": count }))
        .collect();
    serde_json::json!({ "domains": entries, "from_ts": from, "to_ts": to })
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|v| v == &value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_window_supports_explicit_all_time() {
        let params = TopStatsParams {
            all_time: Some(true),
            limit: Some(25),
            ..Default::default()
        };

        let (_now, from, limit) = time_window(&params);

        assert_eq!(from, 0);
        assert_eq!(limit, 25);
    }

    #[test]
    fn time_window_treats_zero_hours_as_all_time() {
        let params = TopStatsParams {
            hours: Some(0),
            ..Default::default()
        };

        let (_now, from, _limit) = time_window(&params);

        assert_eq!(from, 0);
    }
}
