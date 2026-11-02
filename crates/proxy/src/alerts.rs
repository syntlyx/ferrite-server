//! Egress-down alerting.
//!
//! A single sequential watcher task samples every enabled egress's health on an
//! interval and turns the *transitions* into alerts: an egress that stays down
//! past [`ALERT_GRACE`] logs a WARN (visible on the Logs page) and, when
//! `[notifications] tunnel_alerts` is on, POSTs a JSON event to the webhook;
//! recovery logs an INFO and POSTs the matching `egress_up` event. The grace period absorbs routine blips
//! (a WireGuard rekey, a breaker cooldown) so alerts mean a real outage.
//!
//! The transition state machine lives in [`ProxyState::note_health`] (pure map
//! manipulation, injectable clock) so it's unit-testable; this module owns the
//! loop and the webhook side effects. The same state feeds `down_since_secs` /
//! `alerting` in `GET /api/proxy/stats`.

use std::time::{Duration, Instant};

use serde::Serialize;

use super::{AlertEvent, ProxyCtx};

/// How long an egress must stay unhealthy before a down alert fires. Recovery
/// is reported immediately (but only if the down alert fired).
pub(super) const ALERT_GRACE: Duration = Duration::from_secs(60);

/// Health sampling cadence. Cheap: a handful of atomic loads per egress.
const WATCH_INTERVAL: Duration = Duration::from_secs(5);

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
    /// One line for receivers that show text, not fields.
    message: String,
    /// RFC 3339 UTC timestamp of the event.
    timestamp: String,
}

/// The watcher loop. Spawned at startup; reads the live config each tick so
/// egress edits and webhook changes apply without a restart. Runs for the life
/// of the process.
pub async fn watch(ctx: ProxyCtx) {
    let mut interval = tokio::time::interval(WATCH_INTERVAL);
    // One lazily-built client reused for every delivery.
    let mut client: Option<reqwest::Client> = None;
    loop {
        interval.tick().await;

        // Snapshot the bits of config we need, never holding the lock across
        // an await. Proxy disabled → tunnels are intentionally idle: no alerts.
        let (enabled, webhook, egresses): (bool, Option<String>, Vec<(String, String)>) = {
            let live = ctx.live_config.read();
            let cfg = &live.proxy;
            let notify = &live.notifications;
            (
                cfg.enabled,
                notify
                    .tunnel_alerts
                    .then(|| notify.webhook.clone())
                    .flatten(),
                cfg.egresses
                    .iter()
                    .filter(|e| e.enabled)
                    .map(|e| (e.id.clone(), e.name.clone()))
                    .collect(),
            )
        };
        let proxy = &ctx.proxy;
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
                let client = client.get_or_insert_with(ferrite_core::notify::client);
                deliver(client, url, kind, id, name, down_for).await;
            }
        }
    }
}

async fn deliver(
    client: &reqwest::Client,
    url: &str,
    event: &str,
    egress: &str,
    name: &str,
    down_for: Duration,
) {
    let secs = down_for.as_secs();
    let message = if event == "egress_down" {
        format!("Tunnel {name} has been down for {secs}s")
    } else {
        format!("Tunnel {name} is back up after {secs}s down")
    };
    let payload = WebhookPayload {
        event,
        egress,
        name,
        down_secs: secs,
        message,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    match ferrite_core::notify::post(client, url, &payload).await {
        Ok(()) => tracing::debug!("proxy: alert webhook delivered {event} '{egress}'"),
        Err(e) => tracing::warn!("proxy: alert webhook for {event} '{egress}': {e}"),
    }
}
