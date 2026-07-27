//! Tunnel-side DNS resolution, shared by both WireGuard backends.
//!
//! A routed hostname is resolved by querying the `.conf`'s DNS server *through*
//! the tunnel (DNS-over-TCP), so the lookup neither leaks to the local resolver
//! nor geo-mismatches the exit (a CDN sees the VPN's location). The backends
//! differ only in how a TCP stream to that resolver is opened — a virtual
//! smoltcp socket (userspace) vs. a real socket bound to the tunnel address
//! (kernel) — so the whole orchestration lives here, generic over that `open`
//! step. Resolutions are cached per egress by DNS TTL; if the `.conf` set no
//! DNS we fall back to ferrite's upstream.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use ferrite_core::error::{FeriteError, Result};
use ferrite_upstream::ZoneRouter;

use super::super::ConnectError;

/// Timeout for a single tunnel-DNS lookup (connect + query round-trip).
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Clamp DNS-provided TTLs into a sane caching window.
pub(super) const DNS_MIN_TTL: Duration = Duration::from_secs(30);
const DNS_MAX_TTL: Duration = Duration::from_secs(3600);
/// Soft cap on the per-egress resolution cache (bounds memory; evicts expired).
const DNS_CACHE_CAP: usize = 1024;

/// Host → IP resolution through the tunnel, with TTL caching and upstream
/// fallback. One per egress; owns the DNS server list from the `.conf`.
pub(super) struct TunnelResolver {
    /// Egress id, for log attribution only.
    id: String,
    /// DNS servers from the `.conf`, queried *through* the tunnel.
    dns: Vec<IpAddr>,
    /// Per-egress resolution cache (host → IP), expired by DNS TTL.
    cache: DnsCache,
    /// Fallback resolver used when the `.conf` configured no DNS server (or the
    /// tunnel DNS hiccuped).
    upstream: Arc<ZoneRouter>,
}

impl TunnelResolver {
    pub(super) fn new(id: String, dns: Vec<IpAddr>, upstream: Arc<ZoneRouter>) -> Self {
        Self {
            id,
            dns,
            cache: DnsCache::default(),
            upstream,
        }
    }

    /// Resolve `host` to an IP by querying the `.conf` DNS server through the
    /// tunnel (DNS-over-TCP over a stream produced by `open`). Cached by TTL.
    /// Falls back to ferrite's upstream only when the `.conf` configured no DNS
    /// server or the tunnel lookup hiccuped.
    pub(super) async fn resolve<O, F, S>(&self, host: &str, open: O) -> Result<IpAddr>
    where
        O: Fn(SocketAddr) -> F,
        F: Future<Output = std::result::Result<S, ConnectError>>,
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        match self.cache.get(&key) {
            Cached::Hit(ip) => return Ok(ip),
            Cached::Negative => {
                return Err(FeriteError::Dns(format!(
                    "{host} does not resolve (cached)"
                )));
            }
            Cached::Miss => {}
        }
        // Prefer the tunnel's DNS (no leak, geo-correct). Prefer A, then AAAA.
        if let Some(&dns) = self.dns.first() {
            for rtype in [RecordType::A, RecordType::AAAA] {
                match self.lookup(&open, dns, host, rtype).await {
                    Ok(DnsAnswer::Found(ip, ttl)) => {
                        self.cache.put(&key, Some(ip), ttl);
                        return Ok(ip);
                    }
                    Ok(DnsAnswer::NoData) => {} // no record of this type — try the next
                    Ok(DnsAnswer::NxDomain) => {
                        // The name genuinely doesn't exist. Negative-cache it and
                        // fail fast — ferrite's upstream would only say the same, so
                        // there's no point falling back and re-hammering it.
                        self.cache.put(&key, None, DNS_MIN_TTL);
                        return Err(FeriteError::Dns(format!(
                            "{host} does not exist (NXDOMAIN)"
                        )));
                    }
                    Err(e) => {
                        // A tunnel-DNS hiccup must NOT fail the connection (that
                        // shows up as a page loading "every other time"). Fall back
                        // to ferrite's upstream; the traffic still goes through the
                        // tunnel, only the lookup didn't.
                        tracing::debug!(
                            "wg '{}': tunnel DNS for {host} failed ({e}); using upstream",
                            self.id
                        );
                        break;
                    }
                }
            }
        }
        // Fallback: resolve via ferrite's upstream (no tunnel DNS configured, it
        // hiccuped, or it returned NODATA for both A and AAAA). Cache a positive
        // answer by its short TTL, but do NOT negative-cache a *failure* here: an
        // upstream timeout/SERVFAIL is transient, and caching it would blackhole the
        // host for the whole DNS_MIN_TTL (a hard outage under fail-closed, a direct
        // leak under fail-open) off a single blip. Only an authoritative NXDOMAIN
        // from the tunnel DNS above is negative-cached.
        let ip = super::super::direct::resolve_host(&self.upstream, host).await?;
        self.cache.put(&key, Some(ip), DNS_MIN_TTL);
        Ok(ip)
    }

    /// One DNS-over-TCP query to `dns:53` routed through the tunnel. Classifies the
    /// reply by RCODE so the caller can negative-cache a non-existent name instead
    /// of re-querying it. No txid/anti-spoof dance is needed: the query rides an
    /// authenticated, encrypted tunnel to a fixed resolver — there is no off-path
    /// attacker to inject a forgery.
    async fn lookup<O, F, S>(
        &self,
        open: &O,
        dns: IpAddr,
        host: &str,
        rtype: RecordType,
    ) -> Result<DnsAnswer>
    where
        O: Fn(SocketAddr) -> F,
        F: Future<Output = std::result::Result<S, ConnectError>>,
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let name = Name::from_str(&format!("{}.", host.trim_end_matches('.')))
            .map_err(|e| FeriteError::Dns(format!("invalid host '{host}': {e}")))?;
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name, rtype));
        let query = msg
            .to_bytes()
            .map_err(|e| FeriteError::Dns(format!("encode dns query: {e}")))?;

        let resp = timeout(DNS_TIMEOUT, async {
            let mut s = open(SocketAddr::new(dns, 53))
                .await
                .map_err(|e| e.into_inner())?;
            let mut framed = Vec::with_capacity(query.len() + 2);
            framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
            framed.extend_from_slice(&query);
            s.write_all(&framed).await.map_err(io_dns)?;
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.map_err(io_dns)?;
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).await.map_err(io_dns)?;
            Ok::<_, FeriteError>(buf)
        })
        .await
        .map_err(|_| FeriteError::Dns(format!("tunnel DNS lookup of '{host}' timed out")))??;

        let parsed = Message::from_bytes(&resp)
            .map_err(|e| FeriteError::Dns(format!("parse dns response: {e}")))?;

        // A name that doesn't exist is authoritative and worth negative-caching;
        // SERVFAIL and friends are transient, so surface them as an error and let
        // the caller fall back to ferrite's upstream.
        match parsed.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => return Ok(DnsAnswer::NxDomain),
            other => {
                return Err(FeriteError::Dns(format!(
                    "tunnel DNS for '{host}' returned {other}"
                )));
            }
        }

        let found = parsed.answers.iter().find_map(|rr| {
            let ttl = Duration::from_secs(u64::from(rr.ttl)).clamp(DNS_MIN_TTL, DNS_MAX_TTL);
            match &rr.data {
                RData::A(a) => Some((IpAddr::V4(a.0), ttl)),
                RData::AAAA(a) => Some((IpAddr::V6(a.0), ttl)),
                _ => None,
            }
        });
        Ok(match found {
            Some((ip, ttl)) => DnsAnswer::Found(ip, ttl),
            None => DnsAnswer::NoData, // NOERROR but no A/AAAA of this type
        })
    }
}

/// The classified result of a single tunnel-DNS query.
enum DnsAnswer {
    /// An address record and its (clamped) TTL.
    Found(IpAddr, Duration),
    /// NOERROR with no address record of the queried type (try the other type).
    NoData,
    /// The name does not exist (NXDOMAIN) — safe to negative-cache.
    NxDomain,
}

/// Map an I/O error from the tunneled DNS exchange into a DNS error.
fn io_dns(e: std::io::Error) -> FeriteError {
    FeriteError::Dns(format!("tunnel DNS io: {e}"))
}

/// A small bounded TTL cache for tunnel DNS resolutions, holding both positive
/// answers and negative (NXDOMAIN / "no address") results so a name that doesn't
/// resolve isn't re-queried on every connection. Evicts expired entries on insert,
/// and hard-evicts the soonest-to-expire entry when full of live ones so it can't
/// grow past its cap. Locks are never held across an `.await`.
#[derive(Default)]
struct DnsCache {
    map: Mutex<HashMap<String, CacheEntry>>,
}

struct CacheEntry {
    /// `Some(ip)` for a resolved name; `None` for a cached negative result.
    result: Option<IpAddr>,
    expires: Instant,
}

/// The outcome of a cache lookup.
enum Cached {
    /// A live positive answer.
    Hit(IpAddr),
    /// A live negative answer (the name is known not to resolve).
    Negative,
    /// Not cached (or expired).
    Miss,
}

impl DnsCache {
    fn get(&self, key: &str) -> Cached {
        let mut map = self.map.lock();
        match map.get(key) {
            Some(e) if e.expires > Instant::now() => match e.result {
                Some(ip) => Cached::Hit(ip),
                None => Cached::Negative,
            },
            Some(_) => {
                map.remove(key);
                Cached::Miss
            }
            None => Cached::Miss,
        }
    }

    fn put(&self, key: &str, result: Option<IpAddr>, ttl: Duration) {
        let mut map = self.map.lock();
        if map.len() >= DNS_CACHE_CAP {
            let now = Instant::now();
            map.retain(|_, e| e.expires > now);
            // Still full of live entries → drop the one expiring soonest so the map
            // is strictly bounded even under a flood of fresh names (e.g. a wildcard
            // rule fronting many subdomains).
            while map.len() >= DNS_CACHE_CAP {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                } else {
                    break;
                }
            }
        }
        map.insert(
            key.to_string(),
            CacheEntry {
                result,
                expires: Instant::now() + ttl,
            },
        );
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn caches_live_entries_and_misses_expired() {
        let cache = DnsCache::default();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        cache.put("example.com", Some(ip), Duration::from_secs(3600));
        assert!(
            matches!(cache.get("example.com"), Cached::Hit(got) if got == ip),
            "fresh entry should hit"
        );

        // A negative result is remembered so the name isn't re-queried.
        cache.put("nope.example", None, Duration::from_secs(3600));
        assert!(
            matches!(cache.get("nope.example"), Cached::Negative),
            "negative entry should be remembered"
        );

        // A zero-TTL entry is already expired the instant we read it back.
        cache.put("stale.example", Some(ip), Duration::ZERO);
        assert!(
            matches!(cache.get("stale.example"), Cached::Miss),
            "expired entry should miss"
        );

        assert!(
            matches!(cache.get("never-stored"), Cached::Miss),
            "unknown key should miss"
        );
    }

    #[test]
    fn hard_evicts_when_full_of_live_entries() {
        let cache = DnsCache::default();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        // Insert well past the cap, all long-lived so `retain` frees nothing — the
        // hard-evict path must still keep the map bounded.
        for i in 0..(DNS_CACHE_CAP + 50) {
            cache.put(
                &format!("host{i}.example"),
                Some(ip),
                Duration::from_secs(3600),
            );
        }
        assert!(
            cache.map.lock().len() <= DNS_CACHE_CAP,
            "cache must stay within its cap even when full of fresh entries"
        );
    }
}
