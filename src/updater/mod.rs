pub mod checksum;
pub mod github;
pub mod server;
pub mod web;

use std::time::Duration;

use crate::app::AppState;

/// How often to poll for updates.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60); // 6 hours

/// Background task that periodically checks for server and web UI updates.
pub async fn check_loop(_state: AppState) -> anyhow::Result<()> {
    tracing::info!(
        "updater check loop started (interval: {:?})",
        CHECK_INTERVAL
    );

    let mut ticker = tokio::time::interval(CHECK_INTERVAL);
    // Skip the immediate first tick.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        tracing::debug!("running update check");

        let current = env!("CARGO_PKG_VERSION");
        match server::check(current).await {
            Ok(Some(info)) => {
                tracing::info!("server update available: {} → {}", current, info.version);
                // Note: auto-apply is opt-in; for now just log.
            }
            Ok(None) => {
                tracing::debug!("server is up-to-date ({})", current);
            }
            Err(e) => {
                tracing::warn!("update check failed: {}", e);
            }
        }
    }
}
