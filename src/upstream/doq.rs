use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
};

use crate::error::{FeriteError, Result};
use crate::upstream::hickory_util;

/// DNS-over-QUIC upstream resolver (RFC 9250).
///
/// Uses hickory-resolver with quinn + rustls. The `address` must be an IP;
/// `tls_name` is used for TLS SNI and certificate verification.
///
/// QUIC opens a single multiplexed connection and reuses it for concurrent
/// queries via separate QUIC streams (`num_concurrent_reqs`).
pub struct DoqResolver {
    resolver: TokioResolver,
    label: String,
}

impl DoqResolver {
    pub fn new(address: &str, port: u16, tls_name: &str) -> Result<Self> {
        let addr: SocketAddr = format!("{}:{}", address, port)
            .parse()
            .map_err(|e| FeriteError::Config(format!("invalid DoQ address: {}", e)))?;

        let mut name_server = NameServerConfig::quic(addr.ip(), Arc::from(tls_name.to_owned()));
        if let Some(connection) = name_server.connections.first_mut() {
            connection.port = addr.port();
        }

        let mut config = ResolverConfig::default();
        config.add_name_server(name_server);

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(8);
        opts.attempts = 2;
        // Allow multiple concurrent queries over one QUIC connection (streams).
        opts.num_concurrent_reqs = 16;
        // Keep intermediate CNAME records in answers.
        opts.preserve_intermediates = true;
        // Ferrite has its own DNS cache — disable hickory's to avoid TTL drift.
        opts.cache_size = 0;

        let resolver = TokioResolver::builder_with_config(config, Default::default())
            .with_options(opts)
            .build()?;

        Ok(Self {
            resolver,
            label: format!("doq://{}:{}#{}", address, port, tls_name),
        })
    }

    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        hickory_util::resolve_raw(&self.resolver, &self.label, raw).await
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}
