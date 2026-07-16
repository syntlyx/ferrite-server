//! Egress-down alerting.
//!
//! A single sequential watcher task samples every enabled egress's health on an
//! interval and turns the *transitions* into alerts: an egress that stays down
//! past [`ALERT_GRACE`] logs a WARN (visible on the Logs page) and optionally
//! POSTs a JSON event to the configured webhook; recovery logs an INFO and
//! POSTs the matching `egress_up` event. The grace period absorbs routine blips
//! (a WireGuard rekey, a breaker cooldown) so alerts mean a real outage.
//!
//! The transition state machine lives in [`ProxyState::note_health`] (pure map
//! manipulation, injectable clock) so it's unit-testable; this module owns the
//! loop and the webhook side effects. The same state feeds `down_since_secs` /
//! `alerting` in `GET /api/proxy/stats`.

use std::time::{Duration, Instant};

use serde::Serialize;

use super::AlertEvent;
use crate::app::AppState;

/// How long an egress must stay unhealthy before a down alert fires. Recovery
/// is reported immediately (but only if the down alert fired).
pub(super) const ALERT_GRACE: Duration = Duration::from_secs(60);

/// Health sampling cadence. Cheap: a handful of atomic loads per egress.
const WATCH_INTERVAL: Duration = Duration::from_secs(5);

/// Timeout for a single webhook delivery. Best-effort: a failure is logged and
/// the event is dropped (the log line itself is the fallback alert channel).
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// The JSON body POSTed to the webhook.
#[derive(Serialize)]
struct WebhookPayload<'a> {
    /// `egress_down` | `egress_up`.
    event: &'a str,
    /// Egress id (stable machine name).
    egress: &'a str,
    /// Egress display name.
    name: &'a str,
    /// How long the egress has been (or was, for `egress_up`) down, seconds.
    down_secs: u64,
    /// RFC 3339 UTC timestamp of the event.
    timestamp: String,
}

/// The watcher loop. Spawned at startup; reads the live config each tick so
/// egress edits and webhook changes apply without a restart. Runs for the life
/// of the process.
pub async fn watch(state: AppState) {
    let mut interval = tokio::time::interval(WATCH_INTERVAL);
    // One lazily-built client reused for every delivery.
    let mut client: Option<reqwest::Client> = None;
    loop {
        interval.tick().await;

        // Snapshot the bits of config we need, never holding the lock across
        // an await. Proxy disabled → tunnels are intentionally idle: no alerts.
        let (enabled, webhook, egresses): (bool, Option<String>, Vec<(String, String)>) = {
            let cfg = &state.live_config.read().proxy;
            (
                cfg.enabled,
                cfg.alert_webhook.clone(),
                cfg.egresses
                    .iter()
                    .filter(|e| e.enabled)
                    .map(|e| (e.id.clone(), e.name.clone()))
                    .collect(),
            )
        };
        let proxy = &state.inner.proxy;
        if !enabled {
            proxy.clear_health_watch();
            continue;
        }
        proxy.retain_health_watch(|id| egresses.iter().any(|(eid, _)| eid == id));

        let now = Instant::now();
        for (id, name) in &egresses {
            let healthy = proxy.is_egress_healthy(id);
            let Some(event) = proxy.note_health(id, healthy, now) else {
                continue;
            };
            let (kind, down_for) = match event {
                AlertEvent::Down { down_for } => {
                    tracing::warn!(
                        "proxy: egress '{id}' has been down for {}s",
                        down_for.as_secs()
                    );
                    ("egress_down", down_for)
                }
                AlertEvent::Up { down_for } => {
                    tracing::info!(
                        "proxy: egress '{id}' recovered after {}s down",
                        down_for.as_secs()
                    );
                    ("egress_up", down_for)
                }
            };
            if let Some(url) = webhook.as_deref() {
                let client = client.get_or_insert_with(build_client);
                deliver(client, url, kind, id, name, down_for).await;
            }
        }
    }
}

fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .build()
        // Falls back to default settings; only fails on broken TLS backends.
        .unwrap_or_default()
}

async fn deliver(
    client: &reqwest::Client,
    url: &str,
    event: &str,
    egress: &str,
    name: &str,
    down_for: Duration,
) {
    let payload = WebhookPayload {
        event,
        egress,
        name,
        down_secs: down_for.as_secs(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    match client.post(url).json(&payload).send().await {
        Ok(resp) if !resp.status().is_success() => {
            tracing::warn!(
                "proxy: alert webhook returned {} for {event} '{egress}'",
                resp.status()
            );
        }
        Ok(_) => tracing::debug!("proxy: alert webhook delivered {event} '{egress}'"),
        Err(e) => tracing::warn!("proxy: alert webhook failed for {event} '{egress}': {e}"),
    }
}
