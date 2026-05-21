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
use crate::error::{FeriteError, Result};
use crate::stats::live::LiveStats;
use crate::stats::CpuSampler;
#[cfg(feature = "storage-redis")]
use crate::storage::RedisStorage;
use crate::storage::{SqliteStorage, Storage};
use crate::upstream::{UpstreamPool, ZoneRouter};

/// Capacity of the query channel (DNS handler → stats writer).
const QUERY_CHANNEL_CAPACITY: usize = 8_192;

/// Max in-flight DNS queries. Prevents memory exhaustion when upstream is slow.
pub const MAX_CONCURRENT_QUERIES: usize = 256;

const BUILTIN_PANEL_DOMAIN: &str = "fe.te";
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
        let storage: Arc<dyn Storage> = match config.storage.backend.as_str() {
            "sqlite" | "" => SqliteStorage::open(&config.storage.path).await?,
            #[cfg(feature = "storage-redis")]
            "redis" | "valkey" => {
                RedisStorage::connect(&config.storage.url, &config.storage.key_prefix).await?
            }
            #[cfg(not(feature = "storage-redis"))]
            "redis" | "valkey" => {
                return Err(FeriteError::Config(
                    "storage backend 'redis'/'valkey' requires --features storage-redis".into(),
                ));
            }
            other => {
                return Err(FeriteError::Config(format!(
                    "unknown storage backend: {}",
                    other
                )));
            }
        };

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

        // Seed all in-memory stats from SQLite (last 24 h) so dashboards aren't blank after restart.
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let from_ts = now_ts - 86400;

        match storage.timeseries(600).await {
            Ok(b) => {
                tracing::info!("seeded timeseries with {} buckets from storage", b.len());
                live_stats.timeseries.seed(&b);
            }
            Err(e) => tracing::warn!("failed to seed timeseries: {}", e),
        }

        match storage.top_domains(from_ts, now_ts, 1_000).await {
            Ok(rows) => {
                tracing::info!("seeded top_domains with {} entries", rows.len());
                live_stats.top_domains.seed(&rows);
            }
            Err(e) => tracing::warn!("failed to seed top_domains: {}", e),
        }

        match storage.top_blocked_domains(from_ts, now_ts, 1_000).await {
            Ok(rows) => {
                tracing::info!("seeded top_blocked with {} entries", rows.len());
                live_stats.top_blocked.seed(&rows);
            }
            Err(e) => tracing::warn!("failed to seed top_blocked: {}", e),
        }

        match storage.top_clients(from_ts, now_ts, 500).await {
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
            let panel_url = panel_url(config.api.bind_addr.port());
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
    let Some(ip) = panel_ipv4(config) else {
        tracing::warn!(
            "built-in panel DNS record disabled: could not detect a local IPv4 address for {}",
            BUILTIN_PANEL_DOMAIN
        );
        return Vec::new();
    };

    vec![CustomRecordConfig {
        domain: BUILTIN_PANEL_DOMAIN.to_string(),
        record_type: "A".to_string(),
        value: ip.to_string(),
        ttl: BUILTIN_PANEL_TTL,
    }]
}

fn panel_ipv4(config: &Config) -> Option<Ipv4Addr> {
    non_loopback_ipv4(config.api.bind_addr)
        .or_else(|| non_loopback_ipv4(config.dns.bind_addr))
        .or_else(crate::setup::local_ipv4_for_internet)
        .or_else(|| loopback_ipv4(config.api.bind_addr))
        .or_else(|| loopback_ipv4(config.dns.bind_addr))
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

fn panel_url(port: u16) -> String {
    if port == 80 {
        format!("http://{}", BUILTIN_PANEL_DOMAIN)
    } else {
        format!("http://{}:{}", BUILTIN_PANEL_DOMAIN, port)
    }
}
