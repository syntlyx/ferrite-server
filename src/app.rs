use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, Notify, Semaphore};

use crate::blocklist::Blocklist;
use crate::clients::ClientRegistry;
use crate::config::{Config, CustomRecordConfig};
use crate::dns::cache::DnsCache;
use crate::dns::custom::CustomRecords;
use crate::dns::types::QueryEntry;
use crate::error::Result;
use crate::stats::live::LiveStats;
use crate::stats::CpuSampler;
use crate::storage::{SqliteStorage, Storage};
use crate::upstream::{UpstreamPool, ZoneRouter};

/// Capacity of the query channel (DNS handler → stats writer).
const QUERY_CHANNEL_CAPACITY: usize = 8_192;

/// Max in-flight DNS queries. Prevents memory exhaustion when upstream is slow.
pub const MAX_CONCURRENT_QUERIES: usize = 256;

const BUILTIN_PANEL_TTL: u32 = 60;

/// All shared application state stored inside the `Arc`.
pub struct AppStateInner {
    pub config: Config,
    pub dns_cache: Arc<DnsCache>,
    pub blocklist: Arc<Blocklist>,
    pub live_stats: Arc<LiveStats>,
    pub storage: Arc<dyn Storage>,
    pub upstream_pool: Arc<ZoneRouter>,
    pub custom_records: Arc<CustomRecords>,
    pub client_registry: Arc<ClientRegistry>,
    /// Path to the warm-restart snapshot file.
    pub snapshot_path: std::path::PathBuf,
    /// Hot-patchable list of domain patterns to suppress from the query log.
    pub log_ignore: Arc<RwLock<Vec<String>>>,
    /// Limits in-flight DNS queries to prevent memory exhaustion under slow upstream.
    pub query_semaphore: Arc<Semaphore>,
}

/// Cheaply-cloneable application state handle, backed by `Arc<AppStateInner>`.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
    /// Sender side of the query pipeline.  Cloned into every DNS handler task.
    pub query_tx: mpsc::Sender<QueryEntry>,
    /// Receiver side — wrapped in a Mutex so the stats writer can take it once.
    pub query_rx: Arc<Mutex<Option<mpsc::Receiver<QueryEntry>>>>,
    /// Mutable runtime config (api_key changes take effect immediately).
    pub live_config: Arc<RwLock<Config>>,
    /// Path of the config file we loaded from (for saving patches).
    pub config_path: Arc<Option<std::path::PathBuf>>,
    /// Active sessions: token → expiry Instant.
    pub sessions: Arc<DashMap<String, Instant>>,
    /// Signals the stats writer to flush its current batch immediately (used on shutdown).
    pub flush_notify: Arc<Notify>,
    /// Signalled by the stats writer once its final flush is complete.
    pub flush_done: Arc<Notify>,
    /// CPU sampler for process CPU usage.
    pub cpu_sampler: Arc<CpuSampler>,
    /// Cached result of the last /api/stats/system call (value + timestamp).
    /// Prevents concurrent sysinfo spawns when the dashboard polls frequently.
    pub system_stats_cache: Arc<Mutex<Option<(Instant, serde_json::Value)>>>,
    /// Cached result of update checks. Prevents the web UI from hitting GitHub
    /// every time a user opens the app.
    pub update_check_cache: Arc<tokio::sync::Mutex<crate::updater::UpdateCheckCache>>,
}

impl AppState {
    /// Construct the full application state from configuration.
    pub async fn init(config: &Config, persistent_config: Config) -> Result<Self> {
        // Storage
        let storage: Arc<dyn Storage> = SqliteStorage::open(&config.storage.path).await?;

        let data_dir = crate::config::data_dir();

        // DNS cache
        let dns_cache = Arc::new(DnsCache::new(
            config.dns.cache_size,
            config.dns.min_ttl,
            config.dns.max_ttl,
        ));

        // Blocklist engine
        let fst_path = data_dir.join("blocklist.fst");
        let blocklist = Arc::new(Blocklist::new(config.blocklist.clone(), fst_path));

        // Load persisted whitelist/blacklist from storage.
        match storage.load_custom_entries().await {
            Ok(entries) => {
                for (domain, entry_type) in entries {
                    match entry_type.as_str() {
                        "whitelist" => {
                            if let Err(e) = blocklist.add_whitelist(&domain) {
                                tracing::warn!("invalid whitelist entry '{}': {}", domain, e);
                            }
                        }
                        "blacklist" => {
                            if let Err(e) = blocklist.add_blacklist(&domain) {
                                tracing::warn!("invalid blacklist entry '{}': {}", domain, e);
                            }
                        }
                        other => {
                            tracing::warn!("unknown custom entry type '{}' for '{}'", other, domain)
                        }
                    }
                }
                tracing::info!("custom whitelist/blacklist loaded from storage");
            }
            Err(e) => tracing::warn!("failed to load custom entries: {}", e),
        }

        // Live stats
        let live_stats = LiveStats::new();

        // Seed in-memory stats from retained storage so dashboards keep their
        // all-time counters/top lists after restart without polling storage.
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let all_time_from_ts = 0;

        match storage.timeseries(600).await {
            Ok(b) => {
                tracing::info!("seeded timeseries with {} buckets from storage", b.len());
                live_stats.timeseries.seed(&b);
            }
            Err(e) => tracing::warn!("failed to seed timeseries: {}", e),
        }

        match storage.summary_counts(all_time_from_ts, now_ts).await {
            Ok(counts) => {
                tracing::info!("seeded query counters from storage: {} total", counts.total);
                let allowed = counts
                    .total
                    .saturating_sub(counts.blocked)
                    .saturating_sub(counts.cached)
                    .saturating_sub(counts.upstream);
                live_stats
                    .total_queries
                    .store(counts.total, std::sync::atomic::Ordering::Relaxed);
                live_stats
                    .total_blocked
                    .store(counts.blocked, std::sync::atomic::Ordering::Relaxed);
                live_stats
                    .total_cached
                    .store(counts.cached, std::sync::atomic::Ordering::Relaxed);
                live_stats
                    .total_upstream
                    .store(counts.upstream, std::sync::atomic::Ordering::Relaxed);
                live_stats
                    .total_allowed
                    .store(allowed, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => tracing::warn!("failed to seed query counters: {}", e),
        }

        match storage.top_domains(all_time_from_ts, now_ts, 1_000).await {
            Ok(rows) => {
                tracing::info!("seeded top_domains with {} entries", rows.len());
                live_stats.top_domains.seed(&rows);
            }
            Err(e) => tracing::warn!("failed to seed top_domains: {}", e),
        }

        match storage
            .top_blocked_domains(all_time_from_ts, now_ts, 1_000)
            .await
        {
            Ok(rows) => {
                tracing::info!("seeded top_blocked with {} entries", rows.len());
                live_stats.top_blocked.seed(&rows);
            }
            Err(e) => tracing::warn!("failed to seed top_blocked: {}", e),
        }

        match storage.top_clients(all_time_from_ts, now_ts, 500).await {
            Ok(rows) => {
                tracing::info!("seeded top_clients with {} entries", rows.len());
                let pairs: Vec<(String, u64)> =
                    rows.into_iter().map(|c| (c.client_ip, c.total)).collect();
                live_stats.top_clients.seed(&pairs);
            }
            Err(e) => tracing::warn!("failed to seed top_clients: {}", e),
        }

        match storage
            .query_range(&crate::storage::QueryFilter {
                limit: Some(2_000),
                ..Default::default()
            })
            .await
        {
            Ok(mut entries) => {
                tracing::info!("seeded recent_queries with {} entries", entries.len());
                if let Some(max_id) = entries.iter().map(|e| e.id).max() {
                    crate::dns::handler::seed_query_counter(max_id);
                }
                entries.reverse(); // query_range returns newest-first; ring buffer needs oldest-first
                live_stats.recent_queries.seed(entries);
            }
            Err(e) => tracing::warn!("failed to seed recent_queries: {}", e),
        }

        // Upstream pool + zone router
        let default_pool = UpstreamPool::from_config(&config.upstream)?;
        let upstream_pool = ZoneRouter::new(&config.zones, default_pool)?;

        // Custom DNS records — load from config, then append from DB.
        let custom_records = CustomRecords::new();
        custom_records.load_from_config(&config.custom_records);
        match storage.load_custom_records().await {
            Ok(db_records) => {
                for cfg in &db_records {
                    if let Err(e) = custom_records.add(cfg) {
                        tracing::warn!("invalid custom record in DB '{}': {}", cfg.domain, e);
                    }
                }
                tracing::info!("loaded {} custom DNS records from DB", db_records.len());
            }
            Err(e) => tracing::warn!("failed to load custom DNS records: {}", e),
        }
        let builtin_records = builtin_panel_records(config);
        if let Some(record) = builtin_records.first() {
            custom_records.load_builtin(&builtin_records);
            let panel_url = panel_url(config, &record.domain);
            tracing::info!(
                "built-in panel DNS record enabled: {} A {} ({})",
                record.domain,
                record.value,
                panel_url
            );
            if config.api.bind_addr.ip().is_loopback()
                && record
                    .value
                    .parse::<Ipv4Addr>()
                    .map(|ip| !ip.is_loopback())
                    .unwrap_or(false)
            {
                tracing::warn!(
                    "{} resolves to {}, but api.bind_addr is loopback-only ({}); set api.bind_addr to 0.0.0.0:{} for LAN access",
                    record.domain,
                    record.value,
                    config.api.bind_addr,
                    config.api.bind_addr.port()
                );
            }
        }

        // Client registry — PTR resolver + manual aliases.
        let client_registry =
            ClientRegistry::new(Arc::clone(&upstream_pool), Arc::clone(&storage)).await;

        // Query channel
        let (query_tx, query_rx) = mpsc::channel(QUERY_CHANNEL_CAPACITY);

        let snapshot_path = data_dir.join("state.bin");

        let inner = Arc::new(AppStateInner {
            config: config.clone(),
            dns_cache,
            blocklist,
            live_stats,
            storage,
            upstream_pool,
            custom_records,
            client_registry,
            snapshot_path,
            log_ignore: Arc::new(RwLock::new(config.dns.log_ignore.clone())),
            query_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES)),
        });

        // Determine where to save config changes.
        let config_path = Config::config_candidates().into_iter().find(|p| p.exists());

        Ok(Self {
            inner,
            query_tx,
            query_rx: Arc::new(Mutex::new(Some(query_rx))),
            live_config: Arc::new(RwLock::new(persistent_config)),
            config_path: Arc::new(config_path),
            sessions: Arc::new(DashMap::new()),
            flush_notify: Arc::new(Notify::new()),
            flush_done: Arc::new(Notify::new()),
            cpu_sampler: Arc::new(CpuSampler::new()),
            system_stats_cache: Arc::new(Mutex::new(None)),
            update_check_cache: Arc::new(tokio::sync::Mutex::new(
                crate::updater::UpdateCheckCache::new(),
            )),
        })
    }
}

fn builtin_panel_records(config: &Config) -> Vec<CustomRecordConfig> {
    if !config.panel.enabled {
        tracing::info!("built-in panel DNS record disabled by config");
        return Vec::new();
    }

    let domain = panel_domain(config);
    let Some(ip) = panel_ipv4(config) else {
        tracing::warn!(
            "built-in panel DNS record disabled: could not detect a local IPv4 address for {}",
            domain
        );
        return Vec::new();
    };

    vec![CustomRecordConfig {
        domain,
        record_type: "A".to_string(),
        value: ip.to_string(),
        ttl: BUILTIN_PANEL_TTL,
    }]
}

fn panel_ipv4(config: &Config) -> Option<Ipv4Addr> {
    env_panel_ipv4()
        .or(config.panel.ipv4)
        .filter(|ip| !ip.is_unspecified())
        .or_else(|| non_loopback_ipv4(config.api.bind_addr))
        .or_else(|| non_loopback_ipv4(config.dns.bind_addr))
        .or_else(crate::setup::local_ipv4_for_internet)
        .or_else(|| loopback_ipv4(config.api.bind_addr))
        .or_else(|| loopback_ipv4(config.dns.bind_addr))
}

fn env_panel_ipv4() -> Option<Ipv4Addr> {
    let value = trim_env("FERRITE_PANEL_IP")?;
    match value.parse::<Ipv4Addr>() {
        Ok(ip) => Some(ip),
        Err(_) => {
            tracing::warn!("ignoring invalid FERRITE_PANEL_IP value: {}", value);
            None
        }
    }
}

fn panel_domain(config: &Config) -> String {
    trim_env("FERRITE_PANEL_DOMAIN").unwrap_or_else(|| config.panel.domain.clone())
}

fn non_loopback_ipv4(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

fn loopback_ipv4(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_loopback() => Some(ip),
        IpAddr::V6(ip) if ip.is_loopback() => Some(Ipv4Addr::LOCALHOST),
        _ => None,
    }
}

fn panel_url(config: &Config, domain: &str) -> String {
    if let Some(url) = trim_env("FERRITE_PANEL_URL").or_else(|| config.panel.url.clone()) {
        return url;
    }

    let port = config.api.bind_addr.port();
    if port == 80 {
        format!("http://{}", domain)
    } else {
        format!("http://{}:{}", domain, port)
    }
}

fn trim_env(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.trim_end_matches('.').to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamConfig;
    use crate::dns::types::{QueryEntry, QueryStatus};
    use crate::storage::{SqliteStorage, Storage};

    #[test]
    fn panel_record_uses_configured_ipv4_and_domain() {
        let mut cfg = Config::default();
        cfg.panel.domain = "panel.home".to_string();
        cfg.panel.ipv4 = Some("192.168.1.5".parse().unwrap());

        let records = builtin_panel_records(&cfg);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "panel.home");
        assert_eq!(records[0].value, "192.168.1.5");
        assert_eq!(records[0].ttl, BUILTIN_PANEL_TTL);
    }

    #[test]
    fn panel_record_can_be_disabled() {
        let mut cfg = Config::default();
        cfg.panel.enabled = false;

        assert!(builtin_panel_records(&cfg).is_empty());
    }

    #[test]
    fn panel_url_uses_configured_url() {
        let mut cfg = Config::default();
        cfg.panel.url = Some("http://fe.te:8031".to_string());

        assert_eq!(panel_url(&cfg, "fe.te"), "http://fe.te:8031");
    }

    #[tokio::test]
    async fn live_top_clients_seed_from_all_retained_history() {
        let db_path = crate::test_support::temp_path("app-seed-all-clients", "db");
        let storage = SqliteStorage::open(&db_path).await.unwrap();
        let old_ts = chrono::Utc::now().timestamp() - 2 * 86400;
        storage
            .write_batch(&[
                query_entry(old_ts, "old.test", "192.168.1.10", QueryStatus::Upstream),
                query_entry(old_ts + 1, "old.test", "192.168.1.10", QueryStatus::Blocked),
            ])
            .await
            .unwrap();
        drop(storage);

        let mut cfg = Config::default();
        cfg.storage.path = db_path.clone();
        cfg.blocklist.lists.clear();
        cfg.upstream = vec![UpstreamConfig::Plain {
            address: "127.0.0.1".to_string(),
            port: 53,
        }];

        let state = AppState::init(&cfg, cfg.clone()).await.unwrap();

        assert_eq!(state.inner.live_stats.total(), 2);
        assert_eq!(state.inner.live_stats.blocked(), 1);
        assert_eq!(
            state.inner.live_stats.top_clients.top(1),
            vec![("192.168.1.10".to_string(), 2)]
        );

        drop(state);
        crate::test_support::cleanup_sqlite(&db_path);
    }

    fn query_entry(ts: i64, domain: &str, client_ip: &str, status: QueryStatus) -> QueryEntry {
        // Unique monotonic ids: write_batch persists entry ids verbatim,
        // and queries.id is a PRIMARY KEY.
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        QueryEntry {
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            timestamp: chrono::DateTime::from_timestamp(ts, 0).unwrap(),
            domain: domain.to_string(),
            query_type: 1,
            client_ip: client_ip.to_string(),
            status,
            latency_ms: 1,
            upstream: None,
            rcode: 0,
        }
    }
}
