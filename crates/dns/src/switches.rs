//! The DNS switches read on every query, which the panel flips without a
//! restart: each is an atomic, so a change reaches the very next query.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use ferrite_core::config::DnsConfig;

#[derive(Debug)]
pub struct DnsSwitches {
    strip_ecs: AtomicBool,
    dnssec: AtomicBool,
    firefox_canary: AtomicBool,
    block_private_relay: AtomicBool,
    strip_ech: AtomicBool,
}

impl DnsSwitches {
    pub fn new(cfg: &DnsConfig) -> Arc<Self> {
        let s = Self {
            strip_ecs: AtomicBool::new(false),
            dnssec: AtomicBool::new(false),
            firefox_canary: AtomicBool::new(false),
            block_private_relay: AtomicBool::new(false),
            strip_ech: AtomicBool::new(false),
        };
        s.apply(cfg);
        Arc::new(s)
    }

    /// Take every switch from `cfg`: after a settings change, a restore or a
    /// sync from a primary.
    pub fn apply(&self, cfg: &DnsConfig) {
        self.strip_ecs.store(cfg.strip_ecs, Relaxed);
        self.dnssec.store(cfg.dnssec, Relaxed);
        self.firefox_canary.store(cfg.firefox_canary, Relaxed);
        self.block_private_relay
            .store(cfg.block_private_relay, Relaxed);
        self.strip_ech.store(cfg.strip_ech, Relaxed);
    }

    /// Drop EDNS Client Subnet from upstream queries.
    pub fn strip_ecs(&self) -> bool {
        self.strip_ecs.load(Relaxed)
    }
    /// Ask upstreams for DNSSEC signatures when a client sets the DO bit.
    pub fn dnssec(&self) -> bool {
        self.dnssec.load(Relaxed)
    }
    /// Answer Firefox's DoH canary with NXDOMAIN.
    pub fn firefox_canary(&self) -> bool {
        self.firefox_canary.load(Relaxed)
    }
    /// Answer Apple's iCloud Private Relay canaries with NXDOMAIN.
    pub fn block_private_relay(&self) -> bool {
        self.block_private_relay.load(Relaxed)
    }
    /// Remove ECH from HTTPS/SVCB answers.
    pub fn strip_ech(&self) -> bool {
        self.strip_ech.load(Relaxed)
    }
}
