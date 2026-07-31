pub mod doh;
pub mod doq;
pub mod egress;
pub mod hickory_util;
pub mod plain;
pub mod pool;
pub mod stream;
pub mod tunneled;
pub mod zone_router;

pub use egress::{
    EgressConn, EgressConnectError, EgressConnectFuture, EgressConnector, ProxyHandle, no_proxy,
};
pub use pool::UpstreamPool;
pub use zone_router::ZoneRouter;

/// Install *ring* as the process-wide rustls crypto provider. Must run before
/// the first TLS connection is built.
///
/// Every rustls user in the tree is compiled without a built-in provider, so
/// that only one crypto stack (ring, already required by hickory's `*-ring`
/// features) ends up in the binary instead of aws-lc alongside it. The cost of
/// that is exactly this call: `reqwest` resolves its provider from the process
/// default, and would fail to build a client if nothing installed one.
///
/// Idempotent — a second call (or a provider installed by someone else) is
/// ignored rather than treated as an error.
pub fn install_default_crypto() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}
