use hickory_resolver::{
    TokioResolver,
    config::{ResolverConfig, ResolverOpts},
    proto::rr::RData,
};
use std::net::IpAddr;

use crate::error::Result;

/// Thin wrapper around `hickory_resolver::TokioResolver`.
#[allow(dead_code)]
pub struct UpstreamResolver {
    inner: TokioResolver,
}

#[allow(dead_code)]
impl UpstreamResolver {
    /// Build a resolver from the system configuration.
    pub fn from_system_conf() -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()?.build();
        Ok(Self { inner: resolver? })
    }

    /// Build a resolver with explicit config.
    pub fn new(config: ResolverConfig, opts: ResolverOpts) -> Result<Self> {
        let resolver = TokioResolver::builder_with_config(config, Default::default())
            .with_options(opts)
            .build()?;
        Ok(Self { inner: resolver })
    }

    /// Resolve A records for `name`, returning all IP addresses.
    pub async fn resolve_a(&self, name: &str) -> Result<Vec<IpAddr>> {
        let resp = self.inner.lookup_ip(name).await?;
        Ok(resp.iter().collect())
    }

    /// Resolve AAAA records for `name`, returning IPv6 addresses.
    pub async fn resolve_aaaa(&self, name: &str) -> Result<Vec<IpAddr>> {
        let resp = self.inner.ipv6_lookup(name).await?;
        Ok(resp
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
                _ => None,
            })
            .collect())
    }

    /// Generic resolve returning the raw lookup response.
    pub async fn resolve(
        &self,
        name: &str,
        record_type: hickory_resolver::proto::rr::RecordType,
    ) -> Result<hickory_resolver::lookup::Lookup> {
        let resp = self.inner.lookup(name, record_type).await?;
        Ok(resp)
    }

    pub fn inner(&self) -> &TokioResolver {
        &self.inner
    }
}
