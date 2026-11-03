use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

use crate::{UpstreamPool, plain::PlainResolver};
use ferrite_core::config::ZoneConfig;
use ferrite_core::error::{FeriteError, Result};

/// Routes DNS queries to zone-specific upstreams or the default pool.
///
/// Zones are matched by suffix (longest match wins):
/// - `"foo.1.168.192.in-addr.arpa"` → zone `"1.168.192.in-addr.arpa"`
/// - `"host.localdomain"`           → zone `"localdomain"`
/// - anything else                  → default upstream pool
///
/// Zone resolvers are plain UDP/TCP only (local routers don't speak DoH/DoQ).
/// Zone failures are returned as-is — no fallback to the default pool, because
/// routing local PTR queries to Cloudflare would produce wrong answers.
///
/// The routes can be replaced while ferrite runs ([`ZoneRouter::replace`]):
/// everyone holding the router sees the new upstreams from the next query on,
/// and a query already on its way finishes on the routes it started with.
pub struct ZoneRouter {
    routes: ArcSwap<Routes>,
}

struct Routes {
    /// Zone entries, sorted longest-name-first so the most specific match wins.
    zones: Vec<ZoneEntry>,
    /// Default pool for queries not matched by any zone.
    default: Arc<UpstreamPool>,
}

struct ZoneEntry {
    /// Lowercased zone name, without trailing dot.
    name: String,
    resolver: PlainResolver,
}

impl ZoneRouter {
    pub fn new(zones: &[ZoneConfig], default: Arc<UpstreamPool>) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            routes: ArcSwap::from_pointee(Routes::new(zones, default)?),
        }))
    }

    /// Swap in new zones and a new default pool. Built in full before the
    /// swap, so a zone that doesn't parse leaves the running routes as they
    /// were and comes back as the error.
    pub fn replace(&self, zones: &[ZoneConfig], default: Arc<UpstreamPool>) -> Result<()> {
        self.routes.store(Arc::new(Routes::new(zones, default)?));
        Ok(())
    }

    /// Forward a raw DNS query, routing by zone if applicable.
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        // Held across the await: a swap mid-query doesn't pull the routes out
        // from under it.
        let routes = self.routes.load_full();
        if let Some(resolver) = routes.route(&raw) {
            return resolver.resolve_raw(raw).await;
        }
        routes.default.resolve_raw(raw).await
    }
}

impl Routes {
    fn new(zones: &[ZoneConfig], default: Arc<UpstreamPool>) -> Result<Self> {
        let mut entries: Vec<ZoneEntry> = zones
            .iter()
            .map(|z| {
                let addr: SocketAddr = z.upstream.parse().map_err(|e| {
                    FeriteError::Config(format!(
                        "zone '{}': invalid upstream '{}': {}",
                        z.name, z.upstream, e
                    ))
                })?;
                let resolver = PlainResolver::new(&addr.ip().to_string(), addr.port())?;
                Ok(ZoneEntry {
                    name: z.name.trim_end_matches('.').to_ascii_lowercase(),
                    resolver,
                })
            })
            .collect::<Result<_>>()?;

        // Longest (most specific) zone first.
        entries.sort_by_key(|b| std::cmp::Reverse(b.name.len()));

        if !entries.is_empty() {
            tracing::info!(
                "zone routing: {} zone(s) configured ({})",
                entries.len(),
                entries
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        Ok(Self {
            zones: entries,
            default,
        })
    }

    /// Look up the zone resolver for the first question in `raw`, if any.
    fn route(&self, raw: &[u8]) -> Option<&PlainResolver> {
        if self.zones.is_empty() {
            return None;
        }
        let name = query_name(raw)?;
        self.zones
            .iter()
            .find(|e| matches_zone(&name, &e.name))
            .map(|e| &e.resolver)
    }
}

/// Extract the query name from raw DNS wire bytes.
fn query_name(raw: &[u8]) -> Option<String> {
    let msg = Message::from_bytes(raw).ok()?;
    let q = msg.queries.first()?;
    let name = q.name().to_utf8();
    Some(name.trim_end_matches('.').to_ascii_lowercase())
}

/// Returns true if `name` is within `zone` (exact match or subdomain).
fn matches_zone(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{}", zone))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::no_proxy;
    use ferrite_core::config::UpstreamConfig;

    fn pool() -> Arc<UpstreamPool> {
        UpstreamPool::from_config(
            &[UpstreamConfig::Plain {
                address: "127.0.0.1".to_string(),
                port: 53,
                egress: None,
            }],
            no_proxy(),
        )
        .unwrap()
    }

    fn zone(name: &str, upstream: &str) -> ZoneConfig {
        ZoneConfig {
            name: name.into(),
            upstream: upstream.into(),
        }
    }

    #[test]
    fn replace_swaps_routes_and_a_bad_zone_changes_nothing() {
        let router = ZoneRouter::new(&[], pool()).unwrap();
        assert_eq!(router.routes.load().zones.len(), 0);

        router
            .replace(
                &[
                    zone("lan", "192.168.1.1:53"),
                    zone("1.168.192.in-addr.arpa", "192.168.1.1:53"),
                ],
                pool(),
            )
            .unwrap();
        let routes = router.routes.load();
        assert_eq!(routes.zones.len(), 2);
        assert_eq!(
            routes.zones[0].name, "1.168.192.in-addr.arpa",
            "longest first"
        );
        drop(routes);

        assert!(router.replace(&[zone("lan", "nope")], pool()).is_err());
        assert_eq!(
            router.routes.load().zones.len(),
            2,
            "the running routes stay"
        );
    }
}
