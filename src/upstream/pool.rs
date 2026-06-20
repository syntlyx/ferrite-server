use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::UpstreamConfig;
use crate::error::{FeriteError, Result};
use crate::upstream::{doh::DohResolver, doq::DoqResolver, dot::DotResolver, plain::PlainResolver};

/// A single upstream entry, wrapping one of the protocol variants.
pub enum UpstreamEntry {
    Plain(PlainResolver),
    Tls(Box<DotResolver>),
    Https(DohResolver),
    Quic(Box<DoqResolver>),
}

impl UpstreamEntry {
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        match self {
            UpstreamEntry::Plain(r) => r.resolve_raw(raw).await,
            UpstreamEntry::Tls(r) => r.resolve_raw(raw).await,
            UpstreamEntry::Https(r) => r.resolve_raw(raw).await,
            UpstreamEntry::Quic(r) => r.resolve_raw(raw).await,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            UpstreamEntry::Plain(r) => r.label(),
            UpstreamEntry::Tls(r) => r.label(),
            UpstreamEntry::Https(r) => r.label(),
            UpstreamEntry::Quic(r) => r.label(),
        }
    }
}

/// Round-robin pool of upstream resolvers.
pub struct UpstreamPool {
    upstreams: Vec<UpstreamEntry>,
    counter: AtomicUsize,
}

impl UpstreamPool {
    /// Build a pool from a list of `UpstreamConfig` entries.
    pub fn from_config(configs: &[UpstreamConfig]) -> Result<Arc<Self>> {
        if configs.is_empty() {
            return Err(FeriteError::Config("no upstreams configured".to_string()));
        }

        let mut upstreams = Vec::with_capacity(configs.len());
        for cfg in configs {
            let entry = match cfg {
                UpstreamConfig::Plain { address, port } => {
                    UpstreamEntry::Plain(PlainResolver::new(address, *port)?)
                }
                UpstreamConfig::Tls {
                    address,
                    port,
                    tls_name,
                } => UpstreamEntry::Tls(Box::new(DotResolver::new(address, *port, tls_name)?)),
                UpstreamConfig::Https { url, bootstrap_ip } => {
                    UpstreamEntry::Https(DohResolver::new(url, bootstrap_ip.as_deref())?)
                }
                UpstreamConfig::Quic {
                    address,
                    port,
                    tls_name,
                } => UpstreamEntry::Quic(Box::new(DoqResolver::new(address, *port, tls_name)?)),
            };
            upstreams.push(entry);
        }

        Ok(Arc::new(Self {
            upstreams,
            counter: AtomicUsize::new(0),
        }))
    }

    /// Select the next upstream using round-robin and forward the raw query.
    ///
    /// On failure, tries the remaining upstreams before returning an error.
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        let n = self.upstreams.len();
        let start = self.counter.fetch_add(1, Ordering::Relaxed) % n;

        let mut last_err = FeriteError::Dns("no upstreams available".to_string());

        for i in 0..n {
            let idx = (start + i) % n;
            let upstream = &self.upstreams[idx];
            match upstream.resolve_raw(raw.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::warn!("upstream {} failed: {}", upstream.label(), e);
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }
}
