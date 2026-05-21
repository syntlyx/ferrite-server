use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

use crate::config::ZoneConfig;
use crate::error::{FeriteError, Result};
use crate::upstream::{plain::PlainResolver, UpstreamPool};

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
pub struct ZoneRouter {
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

        Ok(Arc::new(Self {
            zones: entries,
            default,
        }))
    }

    /// Forward a raw DNS query, routing by zone if applicable.
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        if let Some(resolver) = self.route(&raw) {
            return resolver.resolve_raw(raw).await;
        }
        self.default.resolve_raw(raw).await
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
