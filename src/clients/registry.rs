use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::error::Result;
use crate::storage::Storage;
use crate::upstream::ZoneRouter;

use super::{format_mac, parse_ip, parse_mac, unmap_v4, ClientRegistry, DashMap, DashSet};

impl ClientRegistry {
    pub async fn new(upstream: Arc<ZoneRouter>, storage: Arc<dyn Storage>) -> Arc<Self> {
        let registry = Arc::new(Self {
            ptr_cache: DashMap::new(),
            ip_aliases: DashMap::new(),
            mac_aliases: DashMap::new(),
            mac_to_name: DashMap::new(),
            ip_to_mac: DashMap::new(),
            in_flight: DashSet::new(),
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

        registry
    }

    // ── Name lookup ───────────────────────────────────────────────────────────

    /// Return the best available name for `ip`. Never blocks.
    pub fn get_name(&self, ip: IpAddr) -> Option<String> {
        let ip = unmap_v4(ip);

        if let Some(name) = self.ip_aliases.get(&ip) {
            return Some(name.clone());
        }
        if let Some(mac) = self.mac_for_ip(ip) {
            if let Some(name) = self.mac_aliases.get(&mac) {
                return Some(name.clone());
            }
        }
        if let IpAddr::V6(v6) = ip {
            if let Some(mac) = super::mac::extract_eui64_mac(v6) {
                if let Some(entry) = self.mac_to_name.get(&mac) {
                    return Some(entry.0.clone());
                }
            }
        }
        self.ptr_cache.get(&ip)?.name.clone()
    }

    pub(super) fn mac_for_ip(&self, ip: IpAddr) -> Option<[u8; 6]> {
        if let IpAddr::V6(v6) = ip {
            if let Some(mac) = super::mac::extract_eui64_mac(v6) {
                return Some(mac);
            }
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
            if let Some(entry) = registry.mac_to_name.get(&mac) {
                if Instant::now() < entry.1 {
                    return;
                }
            }
        }
        if let Some(e) = registry.ptr_cache.get(&ip) {
            if Instant::now() < e.expires_at {
                return;
            }
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
        if let Some(mac) = self.mac_for_ip(ip) {
            if self.mac_aliases.contains_key(&mac) {
                return true;
            }
        }
        false
    }
}
