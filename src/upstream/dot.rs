use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
};

use crate::error::{FeriteError, Result};
use crate::upstream::hickory_util;

/// DNS-over-TLS upstream resolver.
///
/// Uses hickory-resolver with rustls. The `address` must be an IP (no DNS
/// lookup needed); `tls_name` is used only for TLS SNI and certificate
/// verification.
///
/// hickory keeps a persistent TLS connection and multiplexes concurrent
/// queries over it via `num_concurrent_reqs`.
pub struct DotResolver {
    resolver: TokioResolver,
    label: String,
}

impl DotResolver {
    pub fn new(address: &str, port: u16, tls_name: &str) -> Result<Self> {
        let addr: SocketAddr = format!("{}:{}", address, port)
            .parse()
            .map_err(|e| FeriteError::Config(format!("invalid DoT address: {}", e)))?;

        let mut name_server = NameServerConfig::tls(addr.ip(), Arc::from(tls_name.to_owned()));
        if let Some(connection) = name_server.connections.first_mut() {
            connection.port = addr.port();
        }

        let mut config = ResolverConfig::default();
        config.add_name_server(name_server);

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(8);
        opts.attempts = 2;
        // Allow multiple in-flight queries over one TLS connection.
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
            label: format!("dot://{}:{}#{}", address, port, tls_name),
        })
    }

    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        hickory_util::resolve_raw(&self.resolver, &self.label, raw).await
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}
