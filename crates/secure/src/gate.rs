//! Who encrypted DNS answers. At home, every device — it could ask over
//! plain DNS anyway. From the internet, only the devices named in the
//! settings: the name and its wildcard are public (certificates are logged
//! for anyone to read), and the box isn't a resolver for everyone.
//!
//! Behind a reverse proxy every connection is the proxy's, from home; the
//! proxies listed are trusted to say whom they forward for, and that address
//! is what counts.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use ferrite_core::net::{IpNetwork, unmap_v4};
use parking_lot::Mutex;
use serde::Serialize;

/// The last query turned away — for "why doesn't my phone work outside?".
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TurnedAway {
    /// The client ID it carried; `None` = none at all.
    pub device: Option<String>,
    /// Unix seconds.
    pub at: i64,
}

#[derive(Default)]
pub(crate) struct Gate {
    devices: ArcSwap<HashSet<String>>,
    proxies: ArcSwap<Vec<IpNetwork>>,
    turned_away: AtomicU64,
    last: Mutex<Option<TurnedAway>>,
}

impl Gate {
    pub fn set_devices(&self, devices: &[String]) {
        self.devices
            .store(std::sync::Arc::new(devices.iter().cloned().collect()));
    }

    /// Entries that aren't an address or a network are left out; the API
    /// refuses them before they get here.
    pub fn set_proxies(&self, proxies: &[String]) {
        self.proxies.store(std::sync::Arc::new(
            proxies.iter().filter_map(|p| IpNetwork::parse(p)).collect(),
        ));
    }

    /// Is `peer` a reverse proxy whose word on the client is taken?
    pub fn trusts(&self, peer: IpAddr) -> bool {
        let peer = unmap_v4(peer);
        self.proxies.load().iter().any(|n| n.contains(peer))
    }

    /// May a query from `peer` carrying `id` be answered? One that may not is
    /// counted.
    pub fn allows(&self, peer: IpAddr, id: Option<&str>) -> bool {
        if ferrite_core::net::is_local(peer)
            || id.is_some_and(|id| self.devices.load().contains(id))
        {
            return true;
        }
        self.turned_away.fetch_add(1, Ordering::Relaxed);
        *self.last.lock() = Some(TurnedAway {
            device: id.map(str::to_owned),
            at: crate::unix_now(),
        });
        false
    }

    pub fn turned_away(&self) -> (u64, Option<TurnedAway>) {
        (
            self.turned_away.load(Ordering::Relaxed),
            self.last.lock().clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn away_from_home_only_named_devices_are_answered() {
        let gate = Gate::default();
        gate.set_devices(&["pixel".to_string()]);
        let home: IpAddr = "192.168.1.20".parse().unwrap();
        let away: IpAddr = "198.51.100.7".parse().unwrap();

        assert!(gate.allows(home, None));
        assert!(gate.allows(home, Some("anything")));
        assert!(gate.allows(away, Some("pixel")));
        assert!(!gate.allows(away, None));
        assert!(!gate.allows(away, Some("stranger")));

        let (count, last) = gate.turned_away();
        assert_eq!(count, 2);
        assert_eq!(last.unwrap().device.as_deref(), Some("stranger"));
    }

    #[test]
    fn only_listed_proxies_are_trusted() {
        let gate = Gate::default();
        assert!(!gate.trusts("192.168.1.5".parse().unwrap()));
        gate.set_proxies(&["192.168.1.5".to_string(), "172.17.0.0/16".to_string()]);
        assert!(gate.trusts("192.168.1.5".parse().unwrap()));
        assert!(gate.trusts("::ffff:192.168.1.5".parse().unwrap()));
        assert!(gate.trusts("172.17.0.3".parse().unwrap()));
        assert!(!gate.trusts("192.168.1.6".parse().unwrap()));
    }
}
