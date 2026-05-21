pub mod checksum;
pub mod github;
pub mod server;
pub mod web;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::app::AppState;
use crate::error::Result;

/// How often to poll for updates.
const CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// How long an update-check result stays fresh for API reads.
pub const CHECK_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Debug, Serialize)]
pub struct AvailableUpdate {
    pub version: String,
    pub download_url: String,
    pub release_notes: String,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateCheckSnapshot {
    pub current_server_version: String,
    pub current_server_sha256: Option<String>,
    pub current_web_version: String,
    pub current_web_sha256: Option<String>,
    pub server_update: Option<AvailableUpdate>,
    pub web_update: Option<AvailableUpdate>,
    pub checked_at: Option<i64>,
    pub cache_ttl_seconds: u64,
    pub stale: bool,
    pub check_pending: bool,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
struct CachedUpdateCheck {
    snapshot: UpdateCheckSnapshot,
    stored_at: Instant,
}

#[derive(Debug)]
pub struct UpdateCheckCache {
    current: Option<CachedUpdateCheck>,
}

impl UpdateCheckCache {
    pub fn new() -> Self {
        Self { current: None }
    }

    pub fn clear(&mut self) {
        self.current = None;
    }

    pub fn latest(&self) -> Option<UpdateCheckSnapshot> {
        self.current.as_ref().map(|entry| entry.snapshot())
    }

    pub fn fresh(&self, ttl: Duration) -> Option<UpdateCheckSnapshot> {
        let entry = self.current.as_ref()?;
        (entry.stored_at.elapsed() < ttl).then(|| entry.snapshot())
    }

    pub fn store(&mut self, mut snapshot: UpdateCheckSnapshot) {
        snapshot.stale = false;
        snapshot.check_pending = false;
        self.current = Some(CachedUpdateCheck {
            snapshot,
            stored_at: Instant::now(),
        });
    }

    pub fn store_error(&mut self, fallback: UpdateCheckSnapshot) {
        let snapshot = match self.current.as_ref() {
            Some(entry) => {
                let mut snapshot = entry.snapshot();
                snapshot.stale = true;
                snapshot.check_pending = false;
                snapshot.last_error = fallback.last_error;
                snapshot
            }
            None => fallback,
        };

        self.current = Some(CachedUpdateCheck {
            snapshot,
            stored_at: Instant::now()
                .checked_sub(CHECK_CACHE_TTL)
                .unwrap_or_else(Instant::now),
        });
    }
}

impl Default for UpdateCheckCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CachedUpdateCheck {
    fn snapshot(&self) -> UpdateCheckSnapshot {
        let mut snapshot = self.snapshot.clone();
        snapshot.stale = self.stored_at.elapsed() >= CHECK_CACHE_TTL;
        snapshot.check_pending = false;
        snapshot
    }
}

/// Return the cached update state without contacting GitHub unless `force` is set.
pub async fn cached_update_check(state: &AppState, force: bool) -> Result<UpdateCheckSnapshot> {
    if force {
        return refresh_update_check_cache(state).await;
    }

    if let Some(snapshot) = state.update_check_cache.lock().await.fresh(CHECK_CACHE_TTL) {
        return Ok(snapshot);
    }

    if let Some(snapshot) = state.update_check_cache.lock().await.latest() {
        return Ok(snapshot);
    }

    Ok(installed_versions_snapshot(state, None, true).await)
}

/// Perform a network update check, store it in the shared cache, and return it.
pub async fn refresh_update_check_cache(state: &AppState) -> Result<UpdateCheckSnapshot> {
    match live_update_check(state).await {
        Ok(snapshot) => {
            state
                .update_check_cache
                .lock()
                .await
                .store(snapshot.clone());
            Ok(snapshot)
        }
        Err(err) => {
            let error = err.to_string();
            let snapshot = installed_versions_snapshot(state, Some(error), false).await;
            state.update_check_cache.lock().await.store_error(snapshot);
            Err(err)
        }
    }
}

async fn live_update_check(state: &AppState) -> Result<UpdateCheckSnapshot> {
    let current = installed_versions_snapshot(state, None, false).await;

    let (server_info, web_info) = tokio::join!(
        server::check(&current.current_server_version),
        web::check_web_update(
            &current.current_web_version,
            current.current_web_sha256.as_deref()
        ),
    );

    let server_update = server_info?.map(AvailableUpdate::from);
    let web_update = web_info?.map(AvailableUpdate::from);

    Ok(UpdateCheckSnapshot {
        server_update,
        web_update,
        checked_at: Some(now_ts()),
        ..current
    })
}

async fn installed_versions_snapshot(
    state: &AppState,
    last_error: Option<String>,
    check_pending: bool,
) -> UpdateCheckSnapshot {
    let current_server_version = env!("CARGO_PKG_VERSION").to_string();
    let current_server_sha256 = server::installed_sha256().await.ok().flatten();

    let web_dir = state
        .live_config
        .read()
        .web_dir
        .clone()
        .unwrap_or_else(|| crate::config::data_dir().join("web"));
    let current_web_version = tokio::fs::read_to_string(web_dir.with_extension("version"))
        .await
        .unwrap_or_else(|_| "0.0.0".to_string())
        .trim()
        .to_string();
    let current_web_sha256 = web::installed_sha256(&web_dir).await.ok().flatten();

    UpdateCheckSnapshot {
        current_server_version,
        current_server_sha256,
        current_web_version,
        current_web_sha256,
        server_update: None,
        web_update: None,
        checked_at: None,
        cache_ttl_seconds: CHECK_CACHE_TTL.as_secs(),
        stale: check_pending,
        check_pending,
        last_error,
    }
}

impl From<server::UpdateInfo> for AvailableUpdate {
    fn from(info: server::UpdateInfo) -> Self {
        Self {
            version: info.version,
            download_url: info.download_url,
            release_notes: info.release_notes,
            sha256: info.sha256,
        }
    }
}

impl From<web::WebUpdateInfo> for AvailableUpdate {
    fn from(info: web::WebUpdateInfo) -> Self {
        Self {
            version: info.version,
            download_url: info.download_url,
            release_notes: info.release_notes,
            sha256: info.sha256,
        }
    }
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Background task that periodically checks for server and web UI updates.
pub async fn check_loop(state: AppState) -> anyhow::Result<()> {
    tracing::info!(
        "updater check loop started (interval: {:?})",
        CHECK_INTERVAL
    );

    let mut ticker = tokio::time::interval(CHECK_INTERVAL);

    loop {
        ticker.tick().await;
        tracing::debug!("running update check");

        match refresh_update_check_cache(&state).await {
            Ok(snapshot) => {
                if let Some(info) = snapshot.server_update {
                    tracing::info!(
                        "server update available: {} → {}",
                        snapshot.current_server_version,
                        info.version
                    );
                } else {
                    tracing::debug!("server is up-to-date ({})", snapshot.current_server_version);
                }

                if let Some(info) = snapshot.web_update {
                    tracing::info!(
                        "web UI update available: {} → {}",
                        snapshot.current_web_version,
                        info.version
                    );
                } else {
                    tracing::debug!("web UI is up-to-date ({})", snapshot.current_web_version);
                }
            }
            Err(e) => {
                tracing::warn!("update check failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> UpdateCheckSnapshot {
        UpdateCheckSnapshot {
            current_server_version: "0.1.0".to_string(),
            current_server_sha256: None,
            current_web_version: "0.1.0".to_string(),
            current_web_sha256: None,
            server_update: None,
            web_update: None,
            checked_at: Some(123),
            cache_ttl_seconds: CHECK_CACHE_TTL.as_secs(),
            stale: true,
            check_pending: true,
            last_error: None,
        }
    }

    #[test]
    fn update_check_cache_returns_fresh_snapshot() {
        let mut cache = UpdateCheckCache::new();
        cache.store(snapshot());

        let cached = cache.fresh(Duration::from_secs(60)).unwrap();
        assert!(!cached.stale);
        assert!(!cached.check_pending);
        assert_eq!(cached.current_server_version, "0.1.0");
    }

    #[test]
    fn update_check_cache_can_be_cleared() {
        let mut cache = UpdateCheckCache::new();
        cache.store(snapshot());
        cache.clear();

        assert!(cache.latest().is_none());
    }

    #[test]
    fn update_check_cache_preserves_previous_snapshot_on_error() {
        let mut cache = UpdateCheckCache::new();
        let mut previous = snapshot();
        previous.server_update = Some(AvailableUpdate {
            version: "0.2.0".to_string(),
            download_url: "https://example.test/ferrite.tar.gz".to_string(),
            release_notes: String::new(),
            sha256: None,
        });
        cache.store(previous);

        let mut fallback = snapshot();
        fallback.last_error = Some("rate limited".to_string());
        cache.store_error(fallback);

        let cached = cache.latest().unwrap();
        assert_eq!(
            cached.server_update.as_ref().map(|u| u.version.as_str()),
            Some("0.2.0")
        );
        assert!(cached.stale);
        assert_eq!(cached.last_error.as_deref(), Some("rate limited"));
    }
}
