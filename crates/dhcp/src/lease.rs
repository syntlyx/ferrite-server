//! In-memory lease allocator for a single IPv4 pool.
//!
//! Selection is *sticky*: a client that already holds (or has a static
//! reservation for) an address keeps getting the same one, so a device's IP is
//! stable across reboots — which is what makes the IP→MAC→hostname identity fed
//! to the rest of ferrite meaningful. Time is passed in as `now` (unix seconds)
//! so the logic is deterministic under test; the server layer supplies the clock
//! and persists these leases to storage.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A bound address: which client holds it, until when, and the hostname it
/// reported (used to name the device in the UI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub hostname: Option<String>,
    /// Unix seconds at which the lease expires.
    pub expires_at: u64,
}

impl Lease {
    fn is_active(&self, now: u64) -> bool {
        self.expires_at > now
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeaseError {
    #[error("address is actively leased to a different client")]
    Conflict,
    #[error("address is outside the pool and not reserved for this client")]
    OutOfRange,
}

/// A contiguous IPv4 pool plus static reservations and the live lease table.
pub struct LeasePool {
    start: u32,
    end: u32,
    /// Static MAC → IP bindings. Always honored, take priority over dynamic
    /// allocation, and are never handed to a different client. May sit inside or
    /// outside the dynamic range.
    reservations: HashMap<[u8; 6], Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, Lease>,
    by_mac: HashMap<[u8; 6], Ipv4Addr>,
}

impl LeasePool {
    /// A pool spanning `start..=end` (inclusive). The caller is responsible for
    /// excluding the network/broadcast/gateway addresses by choosing the bounds.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            start: start.into(),
            end: end.into(),
            reservations: HashMap::new(),
            by_ip: HashMap::new(),
            by_mac: HashMap::new(),
        }
    }

    /// Add a static MAC→IP reservation.
    pub fn reserve(&mut self, mac: [u8; 6], ip: Ipv4Addr) {
        self.reservations.insert(mac, ip);
    }

    fn in_range(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        v >= self.start && v <= self.end
    }

    /// Is `ip` free to give to `mac` — i.e. unleased, leased to `mac` already, or
    /// only held by an expired lease? A reservation belonging to another MAC
    /// makes it unavailable.
    fn available_for(&self, ip: Ipv4Addr, mac: [u8; 6], now: u64) -> bool {
        if self
            .reservations
            .iter()
            .any(|(&res_mac, &res_ip)| res_ip == ip && res_mac != mac)
        {
            return false;
        }
        // Free unless an active lease for a *different* client holds it.
        !self
            .by_ip
            .get(&ip)
            .is_some_and(|l| l.is_active(now) && l.mac != mac)
    }

    /// Choose the address to OFFER `mac`, without committing it. Priority:
    /// reservation → the client's existing active lease → its requested address
    /// (if in range and free) → the lowest free address in the pool.
    pub fn offer(&self, mac: [u8; 6], requested: Option<Ipv4Addr>, now: u64) -> Option<Ipv4Addr> {
        if let Some(&ip) = self.reservations.get(&mac) {
            return Some(ip);
        }
        if let Some(&ip) = self.by_mac.get(&mac)
            && self.by_ip.get(&ip).is_some_and(|l| l.is_active(now))
        {
            return Some(ip);
        }
        if let Some(req) = requested
            && self.in_range(req)
            && self.available_for(req, mac, now)
        {
            return Some(req);
        }
        (self.start..=self.end)
            .map(Ipv4Addr::from)
            .find(|&ip| self.available_for(ip, mac, now))
    }

    /// Bind `ip` to `mac` for `lease_secs` (called on a REQUEST the server ACKs).
    /// Fails if `ip` is actively held by another client, or is out of range and
    /// not this client's reservation.
    pub fn commit(
        &mut self,
        mac: [u8; 6],
        ip: Ipv4Addr,
        hostname: Option<String>,
        now: u64,
        lease_secs: u64,
    ) -> Result<Lease, LeaseError> {
        let reserved_for_mac = self.reservations.get(&mac) == Some(&ip);
        if !reserved_for_mac && !self.in_range(ip) {
            return Err(LeaseError::OutOfRange);
        }
        if !self.available_for(ip, mac, now) {
            return Err(LeaseError::Conflict);
        }
        // Drop any prior lease this client held at a different address.
        if let Some(old_ip) = self.by_mac.get(&mac).copied()
            && old_ip != ip
        {
            self.by_ip.remove(&old_ip);
        }
        let lease = Lease {
            ip,
            mac,
            hostname,
            expires_at: now.saturating_add(lease_secs),
        };
        self.by_ip.insert(ip, lease.clone());
        self.by_mac.insert(mac, ip);
        Ok(lease)
    }

    /// Re-insert a persisted lease verbatim at startup (it was ours, so it is
    /// trusted — no range/conflict checks). Expired entries are skipped. Seeding
    /// the pool this way keeps still-valid addresses reserved across a restart.
    pub fn restore(
        &mut self,
        mac: [u8; 6],
        ip: Ipv4Addr,
        hostname: Option<String>,
        expires_at: u64,
        now: u64,
    ) {
        if expires_at <= now {
            return;
        }
        let lease = Lease {
            ip,
            mac,
            hostname,
            expires_at,
        };
        self.by_ip.insert(ip, lease);
        self.by_mac.insert(mac, ip);
    }

    /// Release the client's lease (a RELEASE message). Reservations are config,
    /// not leases, so they are untouched.
    pub fn release(&mut self, mac: [u8; 6]) {
        if let Some(ip) = self.by_mac.remove(&mac) {
            self.by_ip.remove(&ip);
        }
    }

    /// The client's current active lease, if any.
    pub fn lookup_by_mac(&self, mac: [u8; 6], now: u64) -> Option<&Lease> {
        self.by_mac
            .get(&mac)
            .and_then(|ip| self.by_ip.get(ip))
            .filter(|l| l.is_active(now))
    }

    /// Drop expired leases; returns how many were removed. Reservations stay.
    pub fn prune_expired(&mut self, now: u64) -> usize {
        let dead: Vec<Ipv4Addr> = self
            .by_ip
            .values()
            .filter(|l| !l.is_active(now))
            .map(|l| l.ip)
            .collect();
        for ip in &dead {
            if let Some(l) = self.by_ip.remove(ip) {
                self.by_mac.remove(&l.mac);
            }
        }
        dead.len()
    }

    /// All currently active leases (for the API / registry sync).
    pub fn active_leases(&self, now: u64) -> impl Iterator<Item = &Lease> {
        self.by_ip.values().filter(move |l| l.is_active(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0xaa];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0xbb];
    const C: [u8; 6] = [0x02, 0, 0, 0, 0, 0xcc];

    fn pool() -> LeasePool {
        // 192.168.1.10 .. 192.168.1.12 — a deliberately tiny pool (3 addresses).
        LeasePool::new(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 12),
        )
    }

    #[test]
    fn offers_lowest_free_address_to_a_new_client() {
        let p = pool();
        assert_eq!(p.offer(A, None, 100), Some(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn allocation_is_sticky_across_reoffers() {
        let mut p = pool();
        let ip = p.offer(A, None, 100).unwrap();
        p.commit(A, ip, None, 100, 3600).unwrap();
        // A second client takes the next address...
        let ip_b = p.offer(B, None, 100).unwrap();
        p.commit(B, ip_b, None, 100, 3600).unwrap();
        // ...and A re-offering (e.g. after reboot) still gets its original IP.
        assert_eq!(p.offer(A, None, 200), Some(ip));
    }

    #[test]
    fn reservation_wins_and_is_not_handed_to_others() {
        let mut p = pool();
        p.reserve(A, Ipv4Addr::new(192, 168, 1, 11));
        // A always gets its reserved .11 even though .10 is free.
        assert_eq!(p.offer(A, None, 100), Some(Ipv4Addr::new(192, 168, 1, 11)));
        // B never gets .11 — it skips to .10, then .12.
        let ip_b = p.offer(B, None, 100).unwrap();
        p.commit(B, ip_b, None, 100, 3600).unwrap();
        let ip_c = p.offer(C, None, 100).unwrap();
        assert_ne!(ip_c, Ipv4Addr::new(192, 168, 1, 11));
    }

    #[test]
    fn honors_a_free_requested_address_but_not_a_taken_one() {
        let mut p = pool();
        assert_eq!(
            p.offer(A, Some(Ipv4Addr::new(192, 168, 1, 12)), 100),
            Some(Ipv4Addr::new(192, 168, 1, 12))
        );
        p.commit(A, Ipv4Addr::new(192, 168, 1, 12), None, 100, 3600)
            .unwrap();
        // B asks for .12 (taken) → falls back to a free one, not .12.
        assert_ne!(
            p.offer(B, Some(Ipv4Addr::new(192, 168, 1, 12)), 100),
            Some(Ipv4Addr::new(192, 168, 1, 12))
        );
    }

    #[test]
    fn commit_conflict_when_actively_held_by_another() {
        let mut p = pool();
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        p.commit(A, ip, None, 100, 3600).unwrap();
        assert_eq!(p.commit(B, ip, None, 100, 3600), Err(LeaseError::Conflict));
    }

    #[test]
    fn out_of_range_commit_rejected_unless_reserved() {
        let mut p = pool();
        let outside = Ipv4Addr::new(192, 168, 1, 200);
        assert_eq!(
            p.commit(A, outside, None, 100, 3600),
            Err(LeaseError::OutOfRange)
        );
        // A reservation makes an out-of-range address committable for that MAC.
        p.reserve(A, outside);
        assert!(p.commit(A, outside, None, 100, 3600).is_ok());
    }

    #[test]
    fn expired_lease_is_reusable_and_pruned() {
        let mut p = pool();
        let ip = p.offer(A, None, 100).unwrap();
        p.commit(A, ip, None, 100, 100).unwrap(); // expires at 200
        assert!(p.lookup_by_mac(A, 150).is_some());
        assert!(p.lookup_by_mac(A, 250).is_none(), "expired by 250");
        // B can now take A's expired address.
        assert_eq!(p.offer(B, None, 250), Some(ip));
        assert_eq!(p.prune_expired(250), 1);
    }

    #[test]
    fn restore_seeds_active_leases_and_skips_expired() {
        let mut p = pool();
        // An active persisted lease is restored and honored (sticky + reserved).
        p.restore(
            A,
            Ipv4Addr::new(192, 168, 1, 11),
            Some("host".into()),
            500,
            100,
        );
        assert_eq!(
            p.lookup_by_mac(A, 100).unwrap().ip,
            Ipv4Addr::new(192, 168, 1, 11)
        );
        assert!(!p.available_for(Ipv4Addr::new(192, 168, 1, 11), B, 100));
        // An already-expired persisted lease is ignored.
        p.restore(B, Ipv4Addr::new(192, 168, 1, 12), None, 50, 100);
        assert!(p.lookup_by_mac(B, 100).is_none());
        assert!(p.available_for(Ipv4Addr::new(192, 168, 1, 12), C, 100));
    }

    #[test]
    fn release_frees_the_address_immediately() {
        let mut p = pool();
        let ip = p.offer(A, None, 100).unwrap();
        p.commit(A, ip, None, 100, 3600).unwrap();
        p.release(A);
        assert!(p.lookup_by_mac(A, 100).is_none());
        assert_eq!(p.offer(B, None, 100), Some(ip));
    }

    #[test]
    fn exhausted_pool_offers_nothing() {
        let mut p = pool();
        for (i, mac) in [A, B, C].iter().enumerate() {
            let ip = p.offer(*mac, None, 100).unwrap();
            p.commit(*mac, ip, None, 100, 3600).unwrap();
            assert_eq!(
                u32::from(ip),
                u32::from(Ipv4Addr::new(192, 168, 1, 10)) + i as u32
            );
        }
        // Fourth client: pool is full.
        assert_eq!(p.offer([0x02, 0, 0, 0, 0, 0xdd], None, 100), None);
    }

    #[test]
    fn commit_moves_a_client_off_its_old_address() {
        let mut p = pool();
        p.commit(A, Ipv4Addr::new(192, 168, 1, 10), None, 100, 3600)
            .unwrap();
        // A re-commits at a different in-range address; the old one frees up.
        p.commit(A, Ipv4Addr::new(192, 168, 1, 11), None, 100, 3600)
            .unwrap();
        assert!(p.available_for(Ipv4Addr::new(192, 168, 1, 10), B, 100));
        assert_eq!(
            p.lookup_by_mac(A, 100).unwrap().ip,
            Ipv4Addr::new(192, 168, 1, 11)
        );
    }
}
