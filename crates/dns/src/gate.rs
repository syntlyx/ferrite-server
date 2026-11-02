//! Who may ask, and how fast: the client access lists and the per-client rate
//! limit, checked before anything else in the pipeline.
//!
//! Both are off until configured, and then cost one atomic load each on the
//! query path. Loopback always passes — the box asking itself is never the
//! client to keep out.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;

use ferrite_core::config::DnsConfig;
use ferrite_core::net::{IpNetwork, unmap_v4};

/// What to do with a query, by who sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// A denied client, or one outside the allowed list: no answer at all.
    Drop,
    /// Over the rate limit: answer REFUSED.
    Refuse,
}

#[derive(Debug, Default)]
struct Acl {
    allowed: Vec<IpNetwork>,
    denied: Vec<IpNetwork>,
}

struct Bucket {
    tokens: f64,
    at: Instant,
    /// When this client was last warned about, so the log says it once a
    /// minute rather than once a query.
    warned: Option<Instant>,
}

/// How often a client over the limit is mentioned in the log.
const WARN_EVERY: Duration = Duration::from_secs(60);

pub struct ClientGate {
    has_acl: AtomicBool,
    acl: RwLock<Arc<Acl>>,
    /// Queries per client per minute; `0` = no limit.
    per_minute: AtomicU32,
    buckets: DashMap<IpAddr, Bucket>,
    refused: AtomicU64,
    dropped: AtomicU64,
}

impl ClientGate {
    pub fn new(config: &DnsConfig) -> Self {
        let gate = ClientGate {
            has_acl: AtomicBool::new(false),
            acl: RwLock::new(Arc::new(Acl::default())),
            per_minute: AtomicU32::new(config.rate_limit),
            buckets: DashMap::new(),
            refused: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        };
        gate.set_acl(&config.allowed_clients, &config.denied_clients);
        gate
    }

    /// Replace the access lists. Entries that don't parse are skipped — the
    /// API refuses them and config loading warns, so none should reach here.
    pub fn set_acl(&self, allowed: &[String], denied: &[String]) {
        let parse = |list: &[String]| -> Vec<IpNetwork> {
            list.iter().filter_map(|e| IpNetwork::parse(e)).collect()
        };
        let acl = Acl {
            allowed: parse(allowed),
            denied: parse(denied),
        };
        let any = !acl.allowed.is_empty() || !acl.denied.is_empty();
        *self.acl.write() = Arc::new(acl);
        self.has_acl.store(any, Ordering::Relaxed);
    }

    /// Change the per-client limit (queries per minute; `0` = none). Clients
    /// start again from a full allowance.
    pub fn set_rate_limit(&self, per_minute: u32) {
        self.per_minute.store(per_minute, Ordering::Relaxed);
        self.buckets.clear();
    }

    pub fn rate_limit(&self) -> u32 {
        self.per_minute.load(Ordering::Relaxed)
    }

    /// Queries answered REFUSED for going over the limit, since start.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Queries dropped by the access lists, since start.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn check(&self, ip: IpAddr) -> Verdict {
        let ip = unmap_v4(ip);
        if ip.is_loopback() {
            return Verdict::Pass;
        }
        if self.has_acl.load(Ordering::Relaxed) && !self.admits(ip) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Verdict::Drop;
        }
        let per_minute = self.per_minute.load(Ordering::Relaxed);
        if per_minute > 0 && !self.take(ip, per_minute, Instant::now()) {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return Verdict::Refuse;
        }
        Verdict::Pass
    }

    fn admits(&self, ip: IpAddr) -> bool {
        let acl = Arc::clone(&self.acl.read());
        if acl.denied.iter().any(|n| n.contains(ip)) {
            return false;
        }
        acl.allowed.is_empty() || acl.allowed.iter().any(|n| n.contains(ip))
    }

    /// Take one token from `ip`'s bucket: it holds a minute's worth and
    /// refills continuously, so a burst is fine and a steady stream above the
    /// limit is not.
    fn take(&self, ip: IpAddr, per_minute: u32, now: Instant) -> bool {
        let capacity = f64::from(per_minute);
        let mut bucket = self.buckets.entry(ip).or_insert(Bucket {
            tokens: capacity,
            at: now,
            warned: None,
        });
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * capacity / 60.0).min(capacity);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return true;
        }
        if bucket
            .warned
            .is_none_or(|w| now.saturating_duration_since(w) >= WARN_EVERY)
        {
            bucket.warned = Some(now);
            tracing::warn!(
                "{ip} is over the rate limit of {per_minute} queries a minute — answering REFUSED"
            );
        }
        false
    }

    /// Forget clients whose allowance has refilled: they cost memory and say
    /// nothing a fresh bucket wouldn't. Called by the cache janitor.
    pub fn sweep(&self) {
        let per_minute = self.per_minute.load(Ordering::Relaxed);
        if per_minute == 0 {
            self.buckets.clear();
            return;
        }
        let full_after = Duration::from_secs(60);
        let now = Instant::now();
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.at) < full_after);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(rate: u32, allowed: &[&str], denied: &[&str]) -> ClientGate {
        let config = DnsConfig {
            rate_limit: rate,
            allowed_clients: allowed.iter().map(|s| s.to_string()).collect(),
            denied_clients: denied.iter().map(|s| s.to_string()).collect(),
            ..DnsConfig::default()
        };
        ClientGate::new(&config)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn off_by_default() {
        let g = gate(0, &[], &[]);
        for _ in 0..10_000 {
            assert_eq!(g.check(ip("192.168.1.9")), Verdict::Pass);
        }
    }

    #[test]
    fn access_lists_drop_outsiders_and_denied_wins() {
        let g = gate(0, &["192.168.1.0/24"], &["192.168.1.66"]);
        assert_eq!(g.check(ip("192.168.1.9")), Verdict::Pass);
        assert_eq!(g.check(ip("::ffff:192.168.1.9")), Verdict::Pass);
        assert_eq!(g.check(ip("203.0.113.5")), Verdict::Drop);
        assert_eq!(g.check(ip("192.168.1.66")), Verdict::Drop);
        // The box itself always passes.
        assert_eq!(g.check(ip("127.0.0.1")), Verdict::Pass);
        assert_eq!(g.check(ip("::1")), Verdict::Pass);
        assert_eq!(g.dropped(), 2);

        // Denied alone: everyone else passes.
        let g = gate(0, &[], &["10.0.0.0/8"]);
        assert_eq!(g.check(ip("10.1.2.3")), Verdict::Drop);
        assert_eq!(g.check(ip("192.168.1.9")), Verdict::Pass);
    }

    #[test]
    fn rate_limit_allows_a_burst_then_refuses_then_refills() {
        let g = gate(60, &[], &[]);
        let t0 = Instant::now();
        let a = ip("192.168.1.9");
        for _ in 0..60 {
            assert!(g.take(a, 60, t0));
        }
        assert!(!g.take(a, 60, t0));
        // Another client has its own allowance.
        assert!(g.take(ip("192.168.1.10"), 60, t0));
        // One per second comes back.
        assert!(g.take(a, 60, t0 + Duration::from_secs(1)));
        assert!(!g.take(a, 60, t0 + Duration::from_secs(1)));
        // Loopback is never limited.
        for _ in 0..200 {
            assert_eq!(g.check(ip("127.0.0.1")), Verdict::Pass);
        }
    }
}
