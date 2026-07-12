use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::error::Result;
use crate::storage::Storage;
use crate::upstream::ZoneRouter;

use super::{
    BINDING_RETENTION, BINDING_TOUCH_INTERVAL, ClientRegistry, DashMap, DashSet, format_mac,
    parse_ip, parse_mac, unmap_v4,
};

impl ClientRegistry {
    pub async fn new(upstream: Arc<ZoneRouter>, storage: Arc<dyn Storage>) -> Arc<Self> {
        let registry = Arc::new(Self {
            ptr_cache: DashMap::new(),
            ip_aliases: DashMap::new(),
            mac_aliases: DashMap::new(),
            mac_to_name: DashMap::new(),
            ip_to_mac: DashMap::new(),
            in_flight: DashSet::new(),
            last_binding_touch: std::sync::atomic::AtomicI64::new(0),
            upstream,
            storage,
        });

        match registry.storage.load_client_aliases().await {
            Ok(entries) => {
                for (key, key_type, name) in entries {
                    match key_type.as_str() {
                        "mac" => {
                            if let Some(mac) = parse_mac(&key) {
                                registry.mac_aliases.insert(mac, name);
                            }
                        }
                        _ => {
                            if let Some(ip) = parse_ip(&key) {
                                registry.ip_aliases.insert(unmap_v4(ip), name);
                            }
                        }
                    }
                }
                tracing::info!(
                    "loaded {} IP aliases, {} MAC aliases",
                    registry.ip_aliases.len(),
                    registry.mac_aliases.len()
                );
            }
            Err(e) => tracing::warn!("failed to load client aliases: {}", e),
        }

        // Restore learned device identities. Names are inserted already-expired
        // (TTL = now) so they show instantly (stale-while-revalidate) yet still
        // trigger a background refresh on the next lookup.
        match registry.storage.load_devices().await {
            Ok(devices) => {
                let now = Instant::now();
                for (mac_s, hostname) in devices {
                    if let (Some(mac), Some(name)) = (parse_mac(&mac_s), hostname) {
                        registry.mac_to_name.insert(mac, (name, now));
                    }
                }
            }
            Err(e) => tracing::warn!("failed to load devices: {}", e),
        }

        // Restore last-known IP → MAC bindings so a historical IP (one the device
        // no longer holds) still resolves to its device after a restart.
        match registry.storage.load_ip_bindings().await {
            Ok(bindings) => {
                for (ip_s, mac_s) in bindings {
                    if let (Some(ip), Some(mac)) = (parse_ip(&ip_s), parse_mac(&mac_s)) {
                        registry.ip_to_mac.insert(unmap_v4(ip), mac);
                    }
                }
            }
            Err(e) => tracing::warn!("failed to load IP bindings: {}", e),
        }

        tracing::info!(
            "restored {} devices, {} IP bindings",
            registry.mac_to_name.len(),
            registry.ip_to_mac.len()
        );

        registry
    }

    // ── Name lookup ───────────────────────────────────────────────────────────

    /// `(ptr_cache entries, ip_to_mac entries)` — memory introspection.
    pub fn cache_sizes(&self) -> (usize, usize) {
        (self.ptr_cache.len(), self.ip_to_mac.len())
    }

    /// Return the best available name for `ip`. Never blocks.
    pub fn get_name(&self, ip: IpAddr) -> Option<String> {
        let ip = unmap_v4(ip);

        if let Some(name) = self.ip_aliases.get(&ip) {
            return Some(name.clone());
        }
        // Resolve via the device behind this IP: manual MAC alias first, then the
        // last learned hostname for that device. `mac_for_ip` covers EUI-64 IPv6
        // and the persisted IP→MAC binding, so a device's name follows it across
        // IP changes and restarts instead of being tied to the ephemeral IP.
        if let Some(mac) = self.mac_for_ip(ip) {
            if let Some(name) = self.mac_aliases.get(&mac) {
                return Some(name.clone());
            }
            if let Some(entry) = self.mac_to_name.get(&mac) {
                return Some(entry.0.clone());
            }
        }
        self.ptr_cache.get(&ip)?.name.clone()
    }

    pub(super) fn mac_for_ip(&self, ip: IpAddr) -> Option<[u8; 6]> {
        if let IpAddr::V6(v6) = ip
            && let Some(mac) = super::mac::extract_eui64_mac(v6)
        {
            return Some(mac);
        }
        self.ip_to_mac.get(&ip).map(|e| *e)
    }

    /// Return the best known MAC for `ip`, if it has been learned already.
    pub fn get_mac(&self, ip: IpAddr) -> Option<String> {
        let ip = unmap_v4(ip);
        self.mac_for_ip(ip).map(|mac| format_mac(&mac))
    }

    /// Schedule a background resolution if the cache entry is stale. Non-blocking.
    pub fn trigger_resolve(registry: &Arc<Self>, ip: IpAddr) {
        let ip = unmap_v4(ip);

        if registry.ip_aliases.contains_key(&ip) {
            return;
        }
        if let Some(mac) = registry.mac_for_ip(ip) {
            if registry.mac_aliases.contains_key(&mac) {
                return;
            }
            if let Some(entry) = registry.mac_to_name.get(&mac)
                && Instant::now() < entry.1
            {
                return;
            }
        }
        if let Some(e) = registry.ptr_cache.get(&ip)
            && Instant::now() < e.expires_at
        {
            return;
        }

        if !registry.in_flight.insert(ip) {
            return;
        }

        let reg = Arc::clone(registry);
        tokio::spawn(async move {
            reg.run_pipeline(ip).await;
            reg.in_flight.remove(&ip);
        });
    }

    // ── Alias management ──────────────────────────────────────────────────────

    pub async fn add_ip_alias(&self, ip: IpAddr, name: String) -> Result<()> {
        let ip = unmap_v4(ip);
        self.storage
            .add_client_alias(&ip.to_string(), "ip", &name)
            .await?;
        self.ptr_cache.remove(&ip);
        self.ip_aliases.insert(ip, name);
        Ok(())
    }

    pub async fn add_mac_alias(&self, mac: [u8; 6], name: String) -> Result<()> {
        self.storage
            .add_client_alias(&format_mac(&mac), "mac", &name)
            .await?;
        let to_remove: Vec<IpAddr> = self
            .ip_to_mac
            .iter()
            .filter(|e| *e.value() == mac)
            .map(|e| *e.key())
            .collect();
        for ip in to_remove {
            self.ptr_cache.remove(&ip);
        }
        self.mac_aliases.insert(mac, name);
        Ok(())
    }

    pub async fn remove_ip_alias(&self, ip: IpAddr) -> Result<()> {
        let ip = unmap_v4(ip);
        self.storage
            .remove_client_alias(&ip.to_string(), "ip")
            .await?;
        self.ip_aliases.remove(&ip);
        Ok(())
    }

    pub async fn remove_mac_alias(&self, mac: [u8; 6]) -> Result<()> {
        self.storage
            .remove_client_alias(&format_mac(&mac), "mac")
            .await?;
        self.mac_aliases.remove(&mac);
        Ok(())
    }

    pub fn list_aliases(&self) -> Vec<(String, &'static str, String)> {
        let mut result = Vec::new();
        for e in self.ip_aliases.iter() {
            result.push((e.key().to_string(), "ip", e.value().clone()));
        }
        for e in self.mac_aliases.iter() {
            result.push((format_mac(e.key()), "mac", e.value().clone()));
        }
        result
    }

    pub fn is_aliased(&self, ip: IpAddr) -> bool {
        let ip = unmap_v4(ip);
        if self.ip_aliases.contains_key(&ip) {
            return true;
        }
        if let Some(mac) = self.mac_for_ip(ip)
            && self.mac_aliases.contains_key(&mac)
        {
            return true;
        }
        false
    }

    /// Forget all auto-learned, IP-keyed state: the PTR cache and the IP → MAC
    /// bindings (in memory and in storage). Manual IP/MAC aliases and learned
    /// device names (`mac_to_name`) are intentionally preserved — they are
    /// configuration / device identity, not query-log data. Live devices
    /// repopulate `ip_to_mac` on the next neighbor scan; old, absent IPs stay
    /// forgotten. Called when the query log is cleared.
    pub async fn clear_learned_ips(&self) -> Result<()> {
        // Delete from storage first, then clear memory only on success: if the DB
        // write fails, both stay populated (consistent) rather than memory going
        // empty while the rows survive to reload on the next restart.
        self.storage.delete_all_ip_bindings().await?;
        self.ptr_cache.clear();
        self.ip_to_mac.clear();
        Ok(())
    }

    // ── Device-token helpers (MAC or IP fallback) ───────────────────────────────

    /// All IPs currently mapped to this device (for MAC tokens, every IP whose
    /// learned binding points at the MAC; for IP tokens, just that IP).
    fn ips_for_device(&self, device: &str) -> Vec<String> {
        if let Some(mac) = parse_mac(device) {
            return self
                .ip_to_mac
                .iter()
                .filter(|e| *e.value() == mac)
                .map(|e| e.key().to_string())
                .collect();
        }
        parse_ip(device)
            .map(|ip| vec![unmap_v4(ip).to_string()])
            .unwrap_or_default()
    }

    /// Full display descriptor for a device token, used by the clients API.
    pub fn describe_device(&self, device: &str) -> super::DeviceInfo {
        if let Some(mac) = parse_mac(device) {
            let name = self
                .mac_aliases
                .get(&mac)
                .map(|n| n.clone())
                .or_else(|| self.mac_to_name.get(&mac).map(|e| e.0.clone()));
            return super::DeviceInfo {
                name,
                ips: self.ips_for_device(device),
                macs: vec![format_mac(&mac)],
                is_alias: self.mac_aliases.contains_key(&mac),
            };
        }
        if let Some(ip) = parse_ip(device) {
            let ip = unmap_v4(ip);
            return super::DeviceInfo {
                name: self.get_name(ip),
                ips: vec![ip.to_string()],
                macs: self.get_mac(ip).into_iter().collect(),
                is_alias: self.is_aliased(ip),
            };
        }
        super::DeviceInfo {
            name: None,
            ips: vec![device.to_string()],
            macs: Vec::new(),
            is_alias: false,
        }
    }

    /// Schedule background resolution for every IP currently tied to a device.
    pub fn trigger_resolve_device(registry: &Arc<Self>, device: &str) {
        for ip in registry.ips_for_device(device) {
            if let Some(addr) = parse_ip(&ip) {
                Self::trigger_resolve(registry, addr);
            }
        }
    }

    /// Mirror the OS ARP + NDP neighbour tables into the in-memory IP→MAC map,
    /// persisting only new or changed bindings. Driven by a periodic background
    /// task so a MAC is warm in RAM by the time queries from a freshly-rotated
    /// address are tagged — without a subprocess per IP.
    pub async fn refresh_neighbor_table(&self) {
        let pairs = super::mac::scan_neighbors().await;
        let mut learned = 0usize;
        let mut present: Vec<IpAddr> = Vec::with_capacity(pairs.len());
        for (ip, mac) in pairs {
            let ip = unmap_v4(ip);
            present.push(ip);
            // Read-and-copy in one expression so no DashMap guard is held across
            // the `.await` below (parking_lot is not reentrant — see freeze notes).
            let changed = self.ip_to_mac.get(&ip).map(|e| *e) != Some(mac);
            if changed {
                self.ip_to_mac.insert(ip, mac);
                self.persist_binding(ip, mac).await;
                learned += 1;
            }
        }
        if learned > 0 {
            tracing::debug!("neighbor mirror: {} new/changed bindings", learned);
        }
        // Keep `last_seen` fresh for still-present devices so age-based pruning only
        // reaps long-absent bindings — a binding that never changes would otherwise
        // never be re-persisted. Throttled: the scan runs every few seconds, and the
        // prune window is measured in days, so touching once an hour is plenty.
        self.touch_present_bindings(&present).await;
    }

    /// Bump `last_seen` for the currently-present IPs, at most once per
    /// [`BINDING_TOUCH_INTERVAL`]. The only caller is the single sequential
    /// neighbor-scan loop, so no cross-task synchronization is needed; the last-touch
    /// time is advanced only *after* a successful write, so a failed write (e.g. a
    /// busy DB) simply retries on the next scan instead of skipping a whole interval.
    async fn touch_present_bindings(&self, present: &[IpAddr]) {
        if present.is_empty() {
            return;
        }
        let now = chrono::Utc::now().timestamp();
        let last = self.last_binding_touch.load(Ordering::Relaxed);
        if now - last < BINDING_TOUCH_INTERVAL.as_secs() as i64 {
            return; // touched recently — nothing to do (no allocation on the common path)
        }
        let ips: Vec<String> = present.iter().map(|ip| ip.to_string()).collect();
        match self.storage.touch_ip_bindings(&ips).await {
            Ok(()) => self.last_binding_touch.store(now, Ordering::Relaxed),
            Err(e) => tracing::debug!("failed to touch IP bindings: {}", e),
        }
    }

    /// Prune learned, IP-keyed state that has aged out: IP→MAC bindings not seen
    /// for [`BINDING_RETENTION`] (dropped from the DB and the in-memory map) and
    /// any expired PTR-cache entries. Manual aliases and learned device names are
    /// never touched. Called periodically from the retention loop so the maps
    /// (and the `ip_bindings` table) can't grow without bound as addresses churn.
    pub async fn prune_learned_ips(&self) {
        let cutoff = chrono::Utc::now().timestamp() - BINDING_RETENTION.as_secs() as i64;
        match self.storage.delete_ip_bindings_older_than(cutoff).await {
            Ok(deleted) => {
                for ip_s in &deleted {
                    if let Some(ip) = parse_ip(ip_s) {
                        self.ip_to_mac.remove(&unmap_v4(ip));
                    }
                }
                if !deleted.is_empty() {
                    tracing::info!("pruned {} stale IP bindings", deleted.len());
                }
            }
            Err(e) => tracing::warn!("failed to prune IP bindings: {}", e),
        }
        // Drop expired PTR-cache entries (keyed by IP, no persistence, so purely
        // an in-memory prune independent of the binding table above).
        let now = Instant::now();
        self.ptr_cache.retain(|_, e| e.expires_at > now);
    }
}
