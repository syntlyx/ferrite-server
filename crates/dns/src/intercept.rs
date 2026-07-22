//! The selective-routing hook the DNS pipeline sees.
//!
//! Step 2 of the query pipeline asks "should this query be answered with the
//! proxy's advertise IP so the client connects to the proxy listeners?". The
//! proxy owns that decision, but the proxy also consumes DNS types — so the
//! DNS side owns this narrow contract ([`DnsInterceptor`]), the proxy
//! implements it, and the composition root wires the two together.

use hickory_proto::op::Message;

use crate::types::DnsResponse;

/// A decision to route a query: the synthetic DNS answer plus which egress the
/// connection will eventually be sent through (for logging).
pub struct Intercept {
    pub response: DnsResponse,
    pub egress_id: String,
}

/// DNS hot-path routing hook, implemented by the proxy's `ProxyState`.
pub trait DnsInterceptor: Send + Sync {
    /// Does any rule restrict to specific clients? The DNS handler resolves the
    /// client MAC for routing only when this is true (otherwise it's free).
    fn has_client_rules(&self) -> bool;

    /// Returns an answer pointing at the proxy's advertise IP when `name`
    /// should be routed for this client, else `None`. Hot path: one lock-free
    /// snapshot load, nothing held across an `.await`.
    fn maybe_intercept(
        &self,
        query: &Message,
        name: &str,
        qtype: u16,
        client_ip: &str,
        client_mac: Option<&str>,
    ) -> Option<Intercept>;
}
