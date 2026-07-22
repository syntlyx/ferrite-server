//! The slice of app state the DNS pipeline sees.

use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::{Semaphore, mpsc};

use crate::dns::cache::DnsCache;
use crate::dns::custom::CustomRecords;
use crate::dns::intercept::DnsInterceptor;
use crate::stats::live::LiveStats;
use ferrite_blocklist::Blocklist;
use ferrite_clients::ClientRegistry;
use ferrite_core::config::DnsConfig;
use ferrite_core::types::QueryEntry;
use ferrite_upstream::ZoneRouter;

/// Everything the DNS servers and the per-query pipeline need. Built once at
/// startup by the composition root; shared as one `Arc` per query task.
pub struct DnsCtx {
    /// Static DNS settings (bind address, DNSSEC, ECS stripping).
    pub dns_config: DnsConfig,
    pub dns_cache: Arc<DnsCache>,
    pub blocklist: Arc<Blocklist>,
    pub custom_records: Arc<CustomRecords>,
    pub client_registry: Arc<ClientRegistry>,
    pub upstream_pool: Arc<ZoneRouter>,
    /// Selective-routing hook (step 2 of the pipeline), implemented by the proxy.
    pub interceptor: Arc<dyn DnsInterceptor>,
    pub live_stats: Arc<LiveStats>,
    /// Hot-patchable list of domain patterns to suppress from the query log.
    pub log_ignore: Arc<RwLock<Vec<String>>>,
    /// Limits in-flight queries to prevent memory exhaustion under slow upstream.
    pub query_semaphore: Arc<Semaphore>,
    /// Sender side of the query pipeline (handler → stats writer).
    pub query_tx: mpsc::Sender<QueryEntry>,
}
