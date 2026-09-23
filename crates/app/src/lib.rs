//! Composition layer: the shared `AppState`, its construction from config, the
//! warm-restart snapshot, and the per-subsystem context builders that hand each
//! task exactly the state it needs.

pub mod snapshot;

#[cfg(any(test, feature = "testutil"))]
pub mod test_support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{Notify, Semaphore, mpsc};

use ferrite_blocklist::Blocklist;
use ferrite_clients::ClientRegistry;
use ferrite_core::config::{ClientAliasConfig, Config, CustomRecordConfig, StorageBackend};
use ferrite_core::error::Result;
use ferrite_core::recording::RecordSwitches;
use ferrite_core::types::QueryEntry;
use ferrite_dns::cache::DnsCache;
use ferrite_dns::custom::CustomRecords;
use ferrite_stats::CpuSampler;
use ferrite_stats::live::LiveStats;
use ferrite_storage::{LegacyConfigRows, MemoryStorage, SqliteStorage, Storage};
use ferrite_upstream::{UpstreamPool, ZoneRouter};

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
    /// Selective per-domain routing (egresses + rules + listeners).
    pub proxy: Arc<ferrite_proxy::ProxyState>,
    /// Host names that resolve to the local admin panel. The shared HTTP listener
    /// serves the panel for these and hands everything else to the proxy.
    pub panel_hosts: std::collections::HashSet<String>,
    /// Hot-patchable list of domain patterns to suppress from the query log.
    pub log_ignore: Arc<RwLock<Vec<String>>>,
    /// Hot-patchable ceiling on the TTL handed to client devices (seconds).
    pub client_ttl: Arc<AtomicU32>,
    /// Hot-patchable privacy switches: whether queries are logged and whether
    /// statistics are kept. Shared with the DNS handler and the stats writer.
    pub record_switches: Arc<RecordSwitches>,
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
    /// Where the warm-restart snapshot lives. On the outer handle rather than
    /// `AppStateInner` so a test can point it at a temp file instead of writing
    /// over the operator's real `state.bin`.
    pub snapshot_path: Arc<std::path::PathBuf>,
    /// Serializes every writer of [`Self::snapshot_path`]. See
    /// [`AppState::save_snapshot`].
    snapshot_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes every writer of [`Self::config_path`]. See
    /// [`AppState::persist_config`].
    config_lock: Arc<tokio::sync::Mutex<()>>,
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
    pub update_check_cache: Arc<tokio::sync::Mutex<ferrite_updater::UpdateCheckCache>>,
}

impl AppState {
    /// Write the warm-restart snapshot, serialized against every other writer
    /// of the same file.
    ///
    /// Three callers reach this: the five-minute saver, the shutdown/restart
    /// paths, and the settings handler when the operator switches recording
    /// off. The lock is what makes the last one trustworthy — the recording
    /// scope is read *inside* it, so a save that began while recording was
    /// still on cannot finish after the scrub and put the cached domains back
    /// on disk. It also stops two savers colliding over the temp file.
    pub async fn save_snapshot(&self) -> Result<()> {
        let _guard = self.snapshot_lock.lock().await;
        let dns_cache = Arc::clone(&self.inner.dns_cache);
        let live = Arc::clone(&self.inner.live_stats);
        let path = self.snapshot_path.as_ref().clone();
        let scope = self.inner.record_switches.scope();
        // spawn_blocking: save() ends in std::fs::write, a blocking syscall that
        // would stall a runtime worker on slow storage (SD card, NFS).
        tokio::task::spawn_blocking(move || snapshot::save::save(&dns_cache, &live, &path, scope))
            .await
            .map_err(|e| {
                ferrite_core::error::FeriteError::Internal(format!("snapshot task failed: {e}"))
            })?
    }

    /// Write `live_config` to the config file, serialized against every other
    /// writer of it.
    ///
    /// The config file is now the only copy of everything an operator authored
    /// — settings, subscriptions, manual block/allow entries, custom records,
    /// client aliases, tunnels — so every API handler that changes any of it
    /// ends here. The lock is what makes concurrent edits safe: `Config::save`
    /// writes `config.toml.tmp` and renames it over the target, and two of
    /// those interleaving would race on the same temp path.
    ///
    /// Returns the path written, or `None` if there was nowhere to write or the
    /// write failed — callers report that as "applied, but not persisted"
    /// rather than failing the request, because the change is already live.
    pub async fn persist_config(&self) -> Option<String> {
        let _guard = self.config_lock.lock().await;
        let cfg = self.live_config.read().clone();
        let path = self.config_path.as_ref().clone().or_else(|| {
            ferrite_core::config::Config::config_candidates()
                .into_iter()
                .next()
        })?;

        let path_clone = path.clone();
        // spawn_blocking: save() ends in std::fs::write + rename, blocking
        // syscalls that would stall a runtime worker on slow storage.
        match tokio::task::spawn_blocking(move || cfg.save(&path_clone)).await {
            Ok(Ok(())) => {
                tracing::info!("config saved to {}", path.display());
                Some(path.display().to_string())
            }
            Ok(Err(e)) => {
                tracing::error!("failed to save config to {}: {}", path.display(), e);
                None
            }
            Err(e) => {
                tracing::error!("config save task panicked: {}", e);
                None
            }
        }
    }

    /// The slice of state the stats writer consumes (everything but the
    /// pipeline receiver, which `main` takes out of `query_rx` once).
    pub fn writer_ctx(&self) -> ferrite_stats::writer::WriterCtx {
        ferrite_stats::writer::WriterCtx {
            live_stats: Arc::clone(&self.inner.live_stats),
            client_registry: Arc::clone(&self.inner.client_registry),
            storage: Arc::clone(&self.inner.storage),
            switches: Arc::clone(&self.inner.record_switches),
            flush_notify: Arc::clone(&self.flush_notify),
            flush_done: Arc::clone(&self.flush_done),
        }
    }

    /// The slice of state the updater consumes.
    pub fn updater_ctx(&self) -> ferrite_updater::UpdaterCtx {
        ferrite_updater::UpdaterCtx {
            cache: Arc::clone(&self.update_check_cache),
            live_config: Arc::clone(&self.live_config),
        }
    }

    /// The slice of state the DNS pipeline consumes (UDP/TCP servers + the
    /// per-query handler).
    pub fn dns_ctx(&self) -> ferrite_dns::ctx::DnsCtx {
        // Bind as a concrete Arc first so the unsized coercion to the trait
        // object happens at the field, not inside `Arc::clone`'s inference.
        let interceptor = Arc::clone(&self.inner.proxy);
        ferrite_dns::ctx::DnsCtx {
            dns_config: self.inner.config.dns.clone(),
            dns_cache: Arc::clone(&self.inner.dns_cache),
            blocklist: Arc::clone(&self.inner.blocklist),
            custom_records: Arc::clone(&self.inner.custom_records),
            client_registry: Arc::clone(&self.inner.client_registry),
            upstream_pool: Arc::clone(&self.inner.upstream_pool),
            interceptor,
            live_stats: Arc::clone(&self.inner.live_stats),
            log_ignore: Arc::clone(&self.inner.log_ignore),
            client_ttl: Arc::clone(&self.inner.client_ttl),
            record_switches: Arc::clone(&self.inner.record_switches),
            query_semaphore: Arc::clone(&self.inner.query_semaphore),
            query_tx: self.query_tx.clone(),
        }
    }

    /// The slice of state the proxy subsystem's tasks consume (listener
    /// supervisor, alert watcher, active prober, panel :80 demux).
    pub fn proxy_ctx(&self) -> ferrite_proxy::ProxyCtx {
        ferrite_proxy::ProxyCtx {
            proxy: Arc::clone(&self.inner.proxy),
            blocklist: Arc::clone(&self.inner.blocklist),
            client_registry: Arc::clone(&self.inner.client_registry),
            upstream_pool: Arc::clone(&self.inner.upstream_pool),
            live_config: Arc::clone(&self.live_config),
            api_port: self.inner.config.api.bind_addr.port(),
        }
    }

    /// Construct the full application state from configuration.
    pub async fn init(config: &Config, persistent_config: Config) -> Result<Self> {
        let max_bytes = config.storage.log_max_mb as u64 * ferrite_core::config::BYTES_PER_MB;

        // Storage. `memory` writes nothing to disk, so it does not create the
        // database file — but if one is already there it may still hold
        // authored state from before that moved to `config.toml`, and losing
        // that silently because of a backend switch would be its own bug. So
        // the hand-off below runs against whichever store can answer for it.
        let storage: Arc<dyn Storage> = match config.storage.backend {
            StorageBackend::Sqlite => SqliteStorage::open(&config.storage.path).await?,
            StorageBackend::Memory => MemoryStorage::open(max_bytes),
        };
        let legacy_source: Arc<dyn Storage> = match config.storage.backend {
            StorageBackend::Sqlite => Arc::clone(&storage),
            StorageBackend::Memory if config.storage.path.exists() => {
                tracing::info!(
                    "memory backend, but {} exists — checking it for configuration to migrate",
                    config.storage.path.display()
                );
                SqliteStorage::open(&config.storage.path).await?
            }
            StorageBackend::Memory => Arc::clone(&storage),
        };

        // Determine where config changes are saved.
        let config_path = Config::config_candidates().into_iter().find(|p| p.exists());

        // Authored state used to live in the database next to the query log.
        // Fold anything a pre-v9 database still holds into the config and hand
        // the file back, so everything below seeds from one source.
        let (config, persistent_config) = migrate_legacy_config(
            &legacy_source,
            config.clone(),
            persistent_config,
            config_path.as_deref(),
        )
        .await;
        let config = &config;
        drop(legacy_source);

        let data_dir = ferrite_core::config::data_dir();

        // DNS cache
        let dns_cache = Arc::new(DnsCache::new(
            config.dns.cache_size,
            config.dns.cache_max_mb.saturating_mul(1024 * 1024),
            config.dns.min_ttl,
            config.dns.max_ttl,
        ));

        // Blocklist engine
        let fst_path = config.storage.blocklist_fst_path();
        let blocklist = Arc::new(Blocklist::new(
            config.blocklist.clone(),
            config.allowlist.clone(),
            fst_path,
        ));
        // Configured zone suffixes are local infrastructure — exempt from any
        // profile's default-deny, like *.arpa and the built-in local suffixes.
        let zone_names: Vec<String> = config.zones.iter().map(|z| z.name.clone()).collect();
        blocklist.set_local_zones(&zone_names);

        // Live stats
        let live_stats = LiveStats::new();

        // Seed in-memory stats from retained storage so dashboards keep their
        // all-time counters/top lists after restart without polling storage.
        //
        // The privacy switches gate this, or they would not survive a reboot:
        // `forget_history()`/`forget_recent()` empty these very structures when
        // the operator switches recording off, and seeding them back out of
        // `ferrite.db` would hand the same domains and devices straight back to
        // the dashboard. The lifetime counters below are the exception — they
        // carry no domain or device identity and are what the dashboard falls
        // back to, so they are always restored.
        let scope = config.storage.record_scope();
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let all_time_from_ts = 0;

        if scope.stats {
            match storage.timeseries(600).await {
                Ok(b) => {
                    tracing::info!("seeded timeseries with {} buckets from storage", b.len());
                    live_stats.timeseries.seed(&b);
                }
                Err(e) => tracing::warn!("failed to seed timeseries: {}", e),
            }
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

        if scope.stats {
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
                        rows.into_iter().map(|c| (c.device, c.total)).collect();
                    live_stats.top_clients.seed(&pairs);
                }
                Err(e) => tracing::warn!("failed to seed top_clients: {}", e),
            }
        }

        // Always: the id counter has to resume above every stored row, whether
        // or not the log is on, or a later insert would collide with one written
        // before the restart.
        match storage.max_query_id().await {
            Ok(max_id) => ferrite_dns::handler::seed_query_counter(max_id),
            Err(e) => tracing::warn!("failed to read the highest query id: {}", e),
        }

        // The ring itself is the query log's in-memory half, so it follows the
        // switch: with logging off nothing is read back and no domain or client
        // address returns to RAM.
        if scope.queries {
            match storage
                .query_range(&ferrite_storage::QueryFilter {
                    limit: Some(2_000),
                    ..Default::default()
                })
                .await
            {
                Ok(mut entries) => {
                    tracing::info!("seeded recent_queries with {} entries", entries.len());
                    entries.reverse(); // query_range returns newest-first; the ring needs oldest-first
                    live_stats.recent_queries.seed(entries);
                }
                Err(e) => tracing::warn!("failed to seed recent_queries: {}", e),
            }
        }

        // Upstream pool + zone router. The pool is built before the proxy (the
        // proxy resolves through it), but an upstream may itself tunnel through an
        // egress — so the pool gets a late-bound handle to the proxy, filled in
        // once the proxy exists below. Empty until then → such upstreams resolve
        // direct, which is also the steady-state fallback when the tunnel is down.
        let proxy_handle: ferrite_upstream::ProxyHandle = ferrite_upstream::no_proxy();
        let default_pool = UpstreamPool::from_config(&config.upstream, Arc::clone(&proxy_handle))?;
        let upstream_pool = ZoneRouter::new(&config.zones, default_pool)?;

        // Custom DNS records — the config file is the only source.
        let custom_records = CustomRecords::new();
        custom_records.load_from_config(&config.custom_records);
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

        // The privacy switches are built before anything they gate: the proxy's
        // per-egress routed-domain table, the stats writer, the DNS handler —
        // and the client registry, whose device inventory is written down only
        // while something is being recorded.
        let record_switches = RecordSwitches::new(config.storage.record_scope());

        // Client registry — PTR resolver + manual aliases.
        let client_registry = ClientRegistry::new(
            Arc::clone(&upstream_pool),
            Arc::clone(&storage),
            Arc::clone(&record_switches),
            &config.client_aliases,
        )
        .await;

        // Selective routing / proxy. Egresses resolve real hosts through this
        // same upstream pool (never the OS resolver, which would loop back into
        // ferrite's own DNS for routed names).
        let proxy = ferrite_proxy::ProxyState::from_config(
            &config.proxy,
            Arc::clone(&upstream_pool),
            Arc::clone(&record_switches),
        );
        // Now that the proxy exists, let tunneled upstreams reach its egresses.
        // (`set` only fails when already set — impossible for a handle created
        // a few lines above.)
        let connector = Arc::clone(&proxy);
        let _ = proxy_handle.set(connector);

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
            proxy,
            panel_hosts: panel_hosts(config),
            log_ignore: Arc::new(RwLock::new(config.dns.log_ignore.clone())),
            client_ttl: Arc::new(AtomicU32::new(config.dns.client_ttl)),
            record_switches,
            query_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES)),
        });

        Ok(Self {
            inner,
            query_tx,
            query_rx: Arc::new(Mutex::new(Some(query_rx))),
            live_config: Arc::new(RwLock::new(persistent_config)),
            config_path: Arc::new(config_path),
            snapshot_path: Arc::new(snapshot_path),
            snapshot_lock: Arc::new(tokio::sync::Mutex::new(())),
            config_lock: Arc::new(tokio::sync::Mutex::new(())),
            sessions: Arc::new(DashMap::new()),
            flush_notify: Arc::new(Notify::new()),
            flush_done: Arc::new(Notify::new()),
            cpu_sampler: Arc::new(CpuSampler::new()),
            system_stats_cache: Arc::new(Mutex::new(None)),
            update_check_cache: Arc::new(tokio::sync::Mutex::new(
                ferrite_updater::UpdateCheckCache::new(),
            )),
        })
    }
}

/// Fold authored state out of a pre-v9 database into the config file, once.
///
/// Manual block/allow entries, custom DNS records and client aliases used to be
/// written to SQLite while the rest of the configuration went to `config.toml`.
/// That split meant the database held state no backup of the config file
/// carried, and an entry written in the file could not be deleted through the
/// UI (the delete cleared a database row that was never there, and the file
/// re-seeded it on the next boot). The file is now the only copy.
///
/// The tables are dropped only after the config has been written, so a failed
/// write leaves them for the next boot to retry. Returns the two configs with
/// the recovered entries merged in either way, so this run behaves correctly
/// even if the file could not be updated.
async fn migrate_legacy_config(
    storage: &Arc<dyn Storage>,
    mut config: Config,
    mut persistent_config: Config,
    config_path: Option<&std::path::Path>,
) -> (Config, Config) {
    let rows = match storage.load_legacy_config_rows().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("could not read legacy configuration rows: {}", e);
            return (config, persistent_config);
        }
    };

    if rows.is_empty() {
        // Nothing to carry over: either this has already run, or the database
        // was created after the tables were removed. Dropping is idempotent and
        // clears the two tables that never had a reader at all.
        if let Err(e) = storage.drop_legacy_config_tables().await {
            tracing::warn!("could not drop legacy configuration tables: {}", e);
        }
        return (config, persistent_config);
    }

    tracing::info!(
        "migrating {} block/allow entr{}, {} custom record(s) and {} client alias(es) \
         from the database into the config file",
        rows.custom_entries.len(),
        if rows.custom_entries.len() == 1 {
            "y"
        } else {
            "ies"
        },
        rows.custom_records.len(),
        rows.client_aliases.len(),
    );

    fold_legacy_rows(&mut config, &rows);
    fold_legacy_rows(&mut persistent_config, &rows);

    let Some(path) = config_path
        .map(|p| p.to_path_buf())
        .or_else(|| Config::config_candidates().into_iter().next())
    else {
        tracing::warn!("nowhere to write the config file — keeping the legacy tables for now");
        return (config, persistent_config);
    };

    let to_save = persistent_config.clone();
    let save_path = path.clone();
    let saved = tokio::task::spawn_blocking(move || to_save.save(&save_path)).await;
    match saved {
        Ok(Ok(())) => {
            tracing::info!("legacy configuration written to {}", path.display());
            if let Err(e) = storage.drop_legacy_config_tables().await {
                tracing::warn!("could not drop legacy configuration tables: {}", e);
            }
        }
        Ok(Err(e)) => tracing::error!(
            "failed to write recovered configuration to {} ({}) — keeping the legacy tables, \
             will retry on the next start",
            path.display(),
            e
        ),
        Err(e) => tracing::error!("config save task panicked during legacy migration: {}", e),
    }

    (config, persistent_config)
}

/// Merge recovered rows into `cfg`, skipping anything the file already says.
/// The file wins on a conflict: it is what the operator can see and edit.
fn fold_legacy_rows(cfg: &mut Config, rows: &LegacyConfigRows) {
    for (domain, entry_type) in &rows.custom_entries {
        let target = match entry_type.as_str() {
            "blacklist" => &mut cfg.blocklist.domains,
            "whitelist" => &mut cfg.allowlist.domains,
            other => {
                tracing::warn!("unknown custom entry type '{}' for '{}'", other, domain);
                continue;
            }
        };
        if !target.iter().any(|d| d == domain) {
            target.push(domain.clone());
        }
    }

    for record in &rows.custom_records {
        let dup = cfg
            .custom_records
            .iter()
            .any(|r| r.domain == record.domain && r.record_type == record.record_type);
        if !dup {
            cfg.custom_records.push(record.clone());
        }
    }

    for (key, key_type, name) in &rows.client_aliases {
        let (ip, mac) = if key_type == "mac" {
            (None, Some(key.clone()))
        } else {
            (Some(key.clone()), None)
        };
        let dup = cfg
            .client_aliases
            .iter()
            .any(|a| a.ip == ip && a.mac == mac);
        if !dup {
            cfg.client_aliases.push(ClientAliasConfig {
                ip,
                mac,
                name: name.clone(),
            });
        }
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
        .or_else(ferrite_core::net::local_ipv4_for_internet)
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

/// Host names (lowercased, no port) that the shared HTTP listener serves locally
/// as the admin panel: the panel domain, the panel IP, and loopback. Anything
/// else arriving on the listener is handed to the proxy.
fn panel_hosts(config: &Config) -> std::collections::HashSet<String> {
    let mut hosts = std::collections::HashSet::new();
    hosts.insert("localhost".to_string());
    hosts.insert(Ipv4Addr::LOCALHOST.to_string());
    hosts.insert("::1".to_string());
    let domain = panel_domain(config)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !domain.is_empty() {
        hosts.insert(domain);
    }
    if let Some(ip) = panel_ipv4(config) {
        hosts.insert(ip.to_string());
    }
    hosts
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
    use ferrite_core::config::UpstreamConfig;
    use ferrite_core::types::{QueryEntry, QueryStatus};
    use ferrite_storage::{SqliteStorage, Storage};

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

    /// The switches have to survive a reboot. Startup re-seeds every in-memory
    /// history surface out of SQLite, so without a gate there the operator's
    /// choice would last exactly until the next restart and the dashboard would
    /// hand back the domains and devices `forget_history()` had just dropped.
    #[tokio::test]
    async fn recording_switched_off_survives_a_restart() {
        let db_path = crate::test_support::temp_path("app-seed-privacy", "db");
        let storage = SqliteStorage::open(&db_path).await.unwrap();
        let ts = chrono::Utc::now().timestamp();
        storage
            .write_batch(
                vec![
                    query_entry(ts, "private.test", "192.168.1.10", QueryStatus::Upstream),
                    query_entry(ts + 1, "private.test", "192.168.1.10", QueryStatus::Blocked),
                ],
                ferrite_core::recording::RecordScope::ALL,
            )
            .await
            .unwrap();
        drop(storage);

        let mut cfg = Config::default();
        cfg.storage.path = db_path.clone();
        cfg.storage.log_queries = false;
        cfg.storage.keep_stats = false;
        cfg.blocklist.lists.clear();
        cfg.upstream = vec![UpstreamConfig::Plain {
            address: "127.0.0.1".to_string(),
            port: 53,
            egress: None,
        }];

        let state = AppState::init(&cfg, cfg.clone()).await.unwrap();
        let live = &state.inner.live_stats;

        // Nothing carrying a domain or a device came back…
        assert!(live.top_domains.top(10).is_empty());
        assert!(live.top_blocked.top(10).is_empty());
        assert!(live.top_clients.top(10).is_empty());
        assert!(live.recent_queries.recent(10).is_empty());
        assert!(live.timeseries.buckets_24h().iter().all(|b| b.total == 0));

        // …but the anonymous lifetime counters did, so the dashboard still has
        // something honest to show after the restart.
        assert_eq!(live.total(), 2);
        assert_eq!(live.blocked(), 1);

        drop(state);
        crate::test_support::cleanup_sqlite(&db_path);
    }

    #[tokio::test]
    async fn live_top_clients_seed_from_all_retained_history() {
        let db_path = crate::test_support::temp_path("app-seed-all-clients", "db");
        let storage = SqliteStorage::open(&db_path).await.unwrap();
        let old_ts = chrono::Utc::now().timestamp() - 2 * 86400;
        storage
            .write_batch(
                vec![
                    query_entry(old_ts, "old.test", "192.168.1.10", QueryStatus::Upstream),
                    query_entry(old_ts + 1, "old.test", "192.168.1.10", QueryStatus::Blocked),
                ],
                ferrite_core::recording::RecordScope::ALL,
            )
            .await
            .unwrap();
        drop(storage);

        let mut cfg = Config::default();
        cfg.storage.path = db_path.clone();
        cfg.blocklist.lists.clear();
        cfg.upstream = vec![UpstreamConfig::Plain {
            address: "127.0.0.1".to_string(),
            port: 53,
            egress: None,
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

    /// The whole point of the move: a box upgrading from a build that kept
    /// authored state in SQLite must end up with that state in `config.toml`,
    /// and the tables must be gone so it can never be read from two places.
    #[tokio::test]
    async fn legacy_database_configuration_lands_in_the_config_file() {
        let db_path = crate::test_support::temp_path("app-legacy-config", "db");
        let cfg_path = crate::test_support::temp_path("app-legacy-config", "toml");

        let storage = SqliteStorage::open(&db_path).await.unwrap();
        storage
            .seed_legacy_config_tables(&LegacyConfigRows {
                custom_entries: vec![
                    ("ads.test".to_string(), "blacklist".to_string()),
                    ("safe.test".to_string(), "whitelist".to_string()),
                ],
                custom_records: vec![CustomRecordConfig {
                    domain: "router.lan".to_string(),
                    record_type: "A".to_string(),
                    value: "192.168.1.1".to_string(),
                    ttl: 60,
                }],
                client_aliases: vec![(
                    "aa:bb:cc:dd:ee:ff".to_string(),
                    "mac".to_string(),
                    "Phone".to_string(),
                )],
            })
            .await
            .unwrap();

        let storage: Arc<dyn Storage> = storage;
        let base = Config::default();
        let (runtime, persistent) =
            migrate_legacy_config(&storage, base.clone(), base, Some(cfg_path.as_path())).await;

        // Both configs carry the recovered entries: the runtime one so this
        // boot behaves, the persistent one because it is what was written.
        for cfg in [&runtime, &persistent] {
            assert_eq!(cfg.blocklist.domains, vec!["ads.test".to_string()]);
            assert_eq!(cfg.allowlist.domains, vec!["safe.test".to_string()]);
            assert_eq!(cfg.custom_records.len(), 1);
            assert_eq!(cfg.custom_records[0].domain, "router.lan");
            assert_eq!(cfg.client_aliases.len(), 1);
            assert_eq!(
                cfg.client_aliases[0].mac.as_deref(),
                Some("aa:bb:cc:dd:ee:ff")
            );
            assert_eq!(cfg.client_aliases[0].name, "Phone");
        }

        // It really reached disk, in a shape that loads back.
        let written = std::fs::read_to_string(&cfg_path).unwrap();
        let reloaded: Config = toml::from_str(&written).unwrap();
        assert_eq!(reloaded.blocklist.domains, vec!["ads.test".to_string()]);
        assert_eq!(reloaded.client_aliases[0].name, "Phone");

        // And the tables are gone, so a second boot finds nothing to migrate
        // and cannot resurrect a deleted entry from a stale row.
        assert!(storage.load_legacy_config_rows().await.unwrap().is_empty());

        drop(storage);
        crate::test_support::cleanup_sqlite(&db_path);
        let _ = std::fs::remove_file(&cfg_path);
    }

    /// The file wins on a conflict, and nothing is duplicated.
    #[test]
    fn folding_legacy_rows_skips_what_the_file_already_says() {
        let mut cfg = Config::default();
        cfg.blocklist.domains = vec!["ads.test".to_string()];
        cfg.client_aliases = vec![ClientAliasConfig {
            ip: None,
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            name: "Renamed in the file".to_string(),
        }];

        fold_legacy_rows(
            &mut cfg,
            &LegacyConfigRows {
                custom_entries: vec![
                    ("ads.test".to_string(), "blacklist".to_string()),
                    ("new.test".to_string(), "blacklist".to_string()),
                ],
                custom_records: vec![],
                client_aliases: vec![(
                    "aa:bb:cc:dd:ee:ff".to_string(),
                    "mac".to_string(),
                    "Phone".to_string(),
                )],
            },
        );

        assert_eq!(cfg.blocklist.domains, vec!["ads.test", "new.test"]);
        assert_eq!(cfg.client_aliases.len(), 1);
        assert_eq!(cfg.client_aliases[0].name, "Renamed in the file");
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
            device: client_ip.to_string(),
            status,
            latency_ms: 1,
            upstream: None,
            rcode: 0,
        }
    }
}
