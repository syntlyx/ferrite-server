//! ferrite's DHCP server and IPv6 DNS announcer, as one service the settings
//! switch on, off and reconfigure while running — no restart.
//!
//! The protocol lives in `ferrite-dhcp`; this is the wiring: blanks in the
//! config filled from what the box can see (its address, the router), the
//! lease table carried across a reconfigure and a restart, every lease fed to
//! the device registry (the name a device gives itself becomes its name) and
//! answered in DNS as `<name>.<domain>` and its reverse.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use ferrite_clients::ClientRegistry;
use ferrite_core::config::{DhcpConfig, RaConfig};
use ferrite_core::net::{format_mac, parse_mac};
use ferrite_dhcp::probe::Rival;
use ferrite_dhcp::server::{self, LeaseEvent, SharedPool};
use ferrite_dhcp::{LeasePool, ServerConfig, ra};
use ferrite_dns::custom::CustomRecords;
use ferrite_storage::{Storage, StoredLease};

/// TTL of the `<name>.<domain>` answers: short, a lease can move.
const LEASE_NAME_TTL: u32 = 60;
/// How often expired leases are swept from the table and the database.
const PRUNE_EVERY: Duration = Duration::from_secs(600);
/// Lease changes waiting for the database and the registry.
const EVENT_QUEUE: usize = 256;
/// The search domain when none is set.
pub const DEFAULT_DOMAIN: &str = "lan";
/// How often the neighbour table is read into the pool, so an address a device
/// is using without a lease from us isn't offered to another.
const SEEN_EVERY: Duration = Duration::from_secs(30);
/// How often, while serving, the network is asked for other DHCP servers.
const RIVALS_EVERY: Duration = Duration::from_secs(30 * 60);
/// How long a check listens for answers.
const RIVALS_WAIT: Duration = Duration::from_secs(3);

/// Placeholder owners that keep the box's own address and the router's out of
/// the pool: a reservation for a MAC no device has (locally administered,
/// all-ones), so the allocator never hands those addresses to anyone.
const HOLD_SERVER: [u8; 6] = [0xfe, 0xff, 0xff, 0xff, 0xff, 0x00];
const HOLD_GATEWAY: [u8; 6] = [0xfe, 0xff, 0xff, 0xff, 0xff, 0x01];

/// What the service is doing — the panel's status line.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DhcpStatus {
    pub running: bool,
    /// Why it isn't running though switched on.
    pub error: Option<String>,
    /// The values in force, after detection filled the blanks.
    pub server_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: String,
    pub ra_running: bool,
    pub ra_error: Option<String>,
    pub ra_interface: Option<String>,
    pub ra_rdnss: Vec<Ipv6Addr>,
}

/// The last look for other DHCP servers on the network.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RivalCheck {
    /// Servers other than this one that offered an address.
    pub servers: Vec<Rival>,
    /// Unix seconds; `None` = not looked yet.
    pub checked_at: Option<u64>,
    /// Why it couldn't look.
    pub error: Option<String>,
}

/// One lease as the panel shows it.
#[derive(Debug, Clone, Serialize)]
pub struct LeaseView {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub hostname: Option<String>,
    /// Unix seconds.
    pub expires_at: u64,
    /// The address comes from a reservation, not the pool.
    pub reserved: bool,
}

/// What the box can see of its network — the defaults the panel offers.
#[derive(Debug, Clone, Serialize)]
pub struct Detected {
    pub server_ip: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub interface: Option<String>,
    pub ipv6: Vec<Ipv6Addr>,
}

pub fn detect() -> Detected {
    let server_ip = ferrite_core::net::local_ipv4_for_internet();
    let interface = ferrite_core::net::default_route_interface();
    Detected {
        server_ip,
        subnet_mask: server_ip.and_then(ferrite_core::net::ipv4_subnet_mask),
        gateway: ferrite_core::net::default_ipv4_gateway(),
        ipv6: interface
            .as_deref()
            .map(ferrite_core::net::interface_ipv6)
            .unwrap_or_default(),
        interface,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    u32::from(a) & u32::from(mask) == u32::from(b) & u32::from(mask)
}

/// A device's self-reported name as a DNS label: lowercase letters, digits
/// and hyphens, at most 63, or nothing if none of it survives.
pub fn dns_label(name: &str) -> Option<String> {
    let mut out = String::new();
    for c in name.trim().chars() {
        match c {
            'a'..='z' | '0'..='9' => out.push(c),
            'A'..='Z' => out.push(c.to_ascii_lowercase()),
            '-' | '_' | ' ' | '.' if !out.ends_with('-') => out.push('-'),
            _ => {}
        }
    }
    let out = out.trim_matches('-');
    let out: String = out.chars().take(63).collect();
    let out = out.trim_end_matches('-').to_string();
    (!out.is_empty()).then_some(out)
}

#[derive(Default)]
struct Tasks {
    dhcp: Vec<JoinHandle<()>>,
    ra: Option<JoinHandle<()>>,
}

/// The running DHCP server and RA announcer; [`DhcpService::apply`] brings
/// them in line with the config.
pub struct DhcpService {
    storage: Arc<dyn Storage>,
    registry: Arc<ClientRegistry>,
    records: Arc<CustomRecords>,
    pool: Mutex<Option<SharedPool>>,
    /// MACs with a reservation, and the names reservations give.
    reserved: Mutex<HashSet<[u8; 6]>>,
    reserved_names: Mutex<Vec<(String, Ipv4Addr)>>,
    domain: Mutex<String>,
    tasks: Mutex<Tasks>,
    status: Mutex<DhcpStatus>,
    /// One reconfigure at a time.
    apply_lock: tokio::sync::Mutex<()>,
    rivals: Mutex<RivalCheck>,
}

impl DhcpService {
    pub fn new(
        storage: Arc<dyn Storage>,
        registry: Arc<ClientRegistry>,
        records: Arc<CustomRecords>,
    ) -> Arc<Self> {
        Arc::new(Self {
            storage,
            registry,
            records,
            pool: Mutex::new(None),
            reserved: Mutex::new(HashSet::new()),
            reserved_names: Mutex::new(Vec::new()),
            domain: Mutex::new(DEFAULT_DOMAIN.to_string()),
            tasks: Mutex::new(Tasks::default()),
            status: Mutex::new(DhcpStatus::default()),
            apply_lock: tokio::sync::Mutex::new(()),
            rivals: Mutex::new(RivalCheck::default()),
        })
    }

    pub fn status(&self) -> DhcpStatus {
        self.status.lock().clone()
    }

    /// The last look for other DHCP servers.
    pub fn rivals(&self) -> RivalCheck {
        self.rivals.lock().clone()
    }

    /// Look for other DHCP servers now (takes a few seconds).
    pub async fn check_rivals(&self) -> RivalCheck {
        let mut ours: Vec<Ipv4Addr> = ferrite_core::net::local_ipv4_for_internet()
            .into_iter()
            .collect();
        ours.extend(self.status.lock().server_ip);
        let check = match ferrite_dhcp::probe::probe(&ours, RIVALS_WAIT).await {
            Ok(servers) => {
                if !servers.is_empty() {
                    let list: Vec<String> = servers.iter().map(|r| r.server.to_string()).collect();
                    tracing::warn!(
                        "dhcp: another DHCP server answers on this network: {}",
                        list.join(", ")
                    );
                }
                RivalCheck {
                    servers,
                    checked_at: Some(now()),
                    error: None,
                }
            }
            Err(e) => RivalCheck {
                servers: Vec::new(),
                checked_at: Some(now()),
                error: Some(match e.kind() {
                    std::io::ErrorKind::PermissionDenied => {
                        "no permission for port 68 — ferrite needs CAP_NET_BIND_SERVICE".into()
                    }
                    std::io::ErrorKind::AddrInUse => {
                        "port 68 is taken by this box's own DHCP client".into()
                    }
                    _ => format!("couldn't ask the network: {e}"),
                }),
            },
        };
        *self.rivals.lock() = check.clone();
        check
    }

    /// Forget the lease `mac` holds: the address goes back to the pool and
    /// its name out of DNS. The device asks again when it next renews.
    pub async fn forget(&self, mac: [u8; 6]) -> bool {
        let Some(pool) = self.pool.lock().clone() else {
            return false;
        };
        let ip = pool.lock().lookup_by_mac(mac, now()).map(|l| l.ip);
        let Some(ip) = ip else {
            return false;
        };
        pool.lock().release(mac);
        if let Err(e) = self.storage.delete_dhcp_lease(&ip.to_string()).await {
            tracing::warn!("dhcp: couldn't drop the lease for {ip}: {e}");
        }
        self.refresh_names();
        true
    }

    /// The active leases, reservations marked.
    pub fn leases(&self) -> Vec<LeaseView> {
        let Some(pool) = self.pool.lock().clone() else {
            return Vec::new();
        };
        let reserved = self.reserved.lock().clone();
        let now = now();
        let mut out: Vec<LeaseView> = pool
            .lock()
            .active_leases(now)
            .map(|l| LeaseView {
                ip: l.ip,
                mac: format_mac(&l.mac),
                hostname: l.hostname.clone(),
                expires_at: l.expires_at,
                reserved: reserved.contains(&l.mac),
            })
            .collect();
        out.sort_by_key(|l| u32::from(l.ip));
        out
    }

    /// Bring the server and the announcer in line with `dhcp` and `ra`: stop
    /// what runs, then start what the config asks for. Leases survive — the
    /// running table is carried into the new one (on first start, the stored
    /// table is read back).
    pub async fn apply(self: &Arc<Self>, dhcp: &DhcpConfig, ra_cfg: &RaConfig) {
        let _guard = self.apply_lock.lock().await;
        self.stop().await;

        let mut status = DhcpStatus {
            domain: dhcp
                .domain
                .clone()
                .filter(|d| !d.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_DOMAIN.to_string()),
            ..DhcpStatus::default()
        };
        *self.domain.lock() = status.domain.clone();

        if dhcp.enabled {
            match self.start_dhcp(dhcp, &mut status).await {
                Ok(()) => status.running = true,
                Err(e) => {
                    tracing::warn!("dhcp: not started — {e}");
                    status.error = Some(e);
                }
            }
        } else {
            // Off: no lease names in DNS, but the table stays for next time.
            self.records.load_leases(&[], LEASE_NAME_TTL);
        }

        if ra_cfg.enabled {
            match self.start_ra(ra_cfg, &mut status) {
                Ok(()) => status.ra_running = true,
                Err(e) => {
                    tracing::warn!("ra: not started — {e}");
                    status.ra_error = Some(e);
                }
            }
        }

        *self.status.lock() = status;
        if dhcp.enabled {
            self.refresh_names();
        }
    }

    /// Stop every task and wait for them to be gone, so the port is free.
    async fn stop(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock());
        for handle in tasks.dhcp.into_iter().chain(tasks.ra) {
            handle.abort();
            let _ = handle.await;
        }
    }

    async fn start_dhcp(
        self: &Arc<Self>,
        cfg: &DhcpConfig,
        status: &mut DhcpStatus,
    ) -> Result<(), String> {
        let server_ip = cfg
            .server_ip
            .or_else(ferrite_core::net::local_ipv4_for_internet)
            .ok_or("couldn't find this box's address — set the server address")?;
        let (Some(start), Some(end)) = (cfg.pool_start, cfg.pool_end) else {
            return Err("set the first and last address of the pool".into());
        };
        let gateway = cfg.gateway.or_else(ferrite_core::net::default_ipv4_gateway);
        let dns = if cfg.dns.is_empty() {
            vec![server_ip]
        } else {
            cfg.dns.clone()
        };
        status.server_ip = Some(server_ip);
        status.gateway = gateway;
        status.dns = dns.clone();

        let server_cfg = ServerConfig {
            server_ip,
            subnet_mask: cfg.subnet_mask,
            gateway,
            dns_servers: dns,
            domain: Some(status.domain.clone()),
            lease_secs: cfg.lease_secs,
        };

        // The new table: the pool, the box and the router held out of it, the
        // reservations, and the leases still running.
        let mut pool = LeasePool::new(start, end);
        pool.reserve(HOLD_SERVER, server_ip);
        if let Some(gw) = gateway {
            pool.reserve(HOLD_GATEWAY, gw);
        }
        let mut reserved = HashSet::new();
        let mut reserved_names = Vec::new();
        for r in &cfg.reservations {
            let Some(mac) = parse_mac(&r.mac) else {
                tracing::warn!("dhcp: reservation with a bad MAC {:?} skipped", r.mac);
                continue;
            };
            pool.reserve(mac, r.ip);
            reserved.insert(mac);
            if let Some(label) = r.name.as_deref().and_then(dns_label) {
                reserved_names.push((label, r.ip));
            }
        }
        let now = now();
        let previous = self.pool.lock().clone();
        match previous {
            Some(old) => {
                for l in old.lock().active_leases(now) {
                    if same_subnet(l.ip, server_ip, cfg.subnet_mask) {
                        pool.restore(l.mac, l.ip, l.hostname.clone(), l.expires_at, now);
                    }
                }
            }
            None => match self.storage.load_dhcp_leases().await {
                Ok(stored) => {
                    for l in stored {
                        let (Ok(ip), Some(mac)) = (l.ip.parse::<Ipv4Addr>(), parse_mac(&l.mac))
                        else {
                            continue;
                        };
                        if same_subnet(ip, server_ip, cfg.subnet_mask) {
                            pool.restore(mac, ip, l.hostname, l.expires_at.max(0) as u64, now);
                        }
                    }
                }
                Err(e) => tracing::warn!("dhcp: couldn't read stored leases: {e}"),
            },
        }

        let sock = server::bind().map_err(|e| match e.kind() {
            std::io::ErrorKind::AddrInUse => {
                "port 67 is taken — another DHCP server runs on this box".to_string()
            }
            std::io::ErrorKind::PermissionDenied => {
                "no permission for port 67 — ferrite needs CAP_NET_BIND_SERVICE".to_string()
            }
            _ => format!("couldn't open port 67: {e}"),
        })?;

        let pool = server::shared(pool);
        *self.pool.lock() = Some(Arc::clone(&pool));
        *self.reserved.lock() = reserved;
        *self.reserved_names.lock() = reserved_names;

        let (tx, rx) = mpsc::channel(EVENT_QUEUE);
        let serve = {
            let this = Arc::clone(self);
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                if let Err(e) = server::serve(sock, server_cfg, pool, Some(tx)).await {
                    tracing::error!("dhcp: server stopped: {e}");
                    let mut s = this.status.lock();
                    s.running = false;
                    s.error = Some(format!("the server stopped: {e}"));
                }
            })
        };
        let events = tokio::spawn(Arc::clone(self).consume(rx));
        let prune = tokio::spawn(Arc::clone(self).prune_loop(Arc::clone(&pool)));
        let seen = tokio::spawn(seen_loop(pool, start, end));
        let rivals = tokio::spawn(Arc::clone(self).rivals_loop());
        self.tasks.lock().dhcp = vec![serve, events, prune, seen, rivals];
        tracing::info!(
            "dhcp: serving {start}–{end} as {server_ip}, router {}, domain {}",
            gateway.map_or_else(|| "none".to_string(), |g| g.to_string()),
            status.domain
        );
        Ok(())
    }

    fn start_ra(self: &Arc<Self>, cfg: &RaConfig, status: &mut DhcpStatus) -> Result<(), String> {
        let interface = cfg
            .interface
            .clone()
            .filter(|i| !i.trim().is_empty())
            .or_else(ferrite_core::net::default_route_interface)
            .ok_or("couldn't find the network interface — set it")?;
        let rdnss = if cfg.rdnss.is_empty() {
            ferrite_core::net::interface_ipv6(&interface)
        } else {
            cfg.rdnss.clone()
        };
        if rdnss.is_empty() {
            return Err(format!(
                "{interface} has no IPv6 address to announce — set one"
            ));
        }
        status.ra_interface = Some(interface.clone());
        status.ra_rdnss = rdnss.clone();
        let ifindex = ra::interface_index(&interface)
            .ok_or_else(|| format!("no interface called {interface}"))?;
        let sock = ra::open(ifindex).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                "no permission for ICMPv6 — ferrite needs CAP_NET_RAW".to_string()
            }
            _ => format!("couldn't open the ICMPv6 socket: {e}"),
        })?;
        let announce = ra::RaConfig {
            cur_hop_limit: 0,
            // DNS only: never offer this box as a router.
            router_lifetime: 0,
            mtu: None,
            prefixes: Vec::new(),
            rdnss,
            rdnss_lifetime: cfg.rdnss_lifetime,
        };
        let interval = Duration::from_secs(cfg.interval_secs.clamp(4, 1800));
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            if let Err(e) = ra::serve(sock, announce, ifindex, interval).await {
                tracing::error!("ra: stopped: {e}");
                let mut s = this.status.lock();
                s.ra_running = false;
                s.ra_error = Some(format!("the announcer stopped: {e}"));
            }
        });
        self.tasks.lock().ra = Some(handle);
        Ok(())
    }

    /// Every lease change: into the database, into the device registry, and
    /// into the names DNS answers.
    async fn consume(self: Arc<Self>, mut rx: mpsc::Receiver<LeaseEvent>) {
        while let Some(event) = rx.recv().await {
            match event {
                LeaseEvent::Committed {
                    mac,
                    ip,
                    hostname,
                    expires_at,
                } => {
                    let stored = StoredLease {
                        ip: ip.to_string(),
                        mac: format_mac(&mac),
                        hostname: hostname.clone(),
                        expires_at: expires_at as i64,
                    };
                    if let Err(e) = self.storage.upsert_dhcp_lease(&stored).await {
                        tracing::warn!("dhcp: couldn't store the lease for {ip}: {e}");
                    }
                    self.registry.record_dhcp_lease(mac, ip, hostname).await;
                }
                LeaseEvent::Released { ip } => {
                    if let Err(e) = self.storage.delete_dhcp_lease(&ip.to_string()).await {
                        tracing::warn!("dhcp: couldn't drop the lease for {ip}: {e}");
                    }
                }
            }
            self.refresh_names();
        }
    }

    /// Every so often while serving, look for other DHCP servers — a router
    /// whose own came back on after a firmware update, say.
    async fn rivals_loop(self: Arc<Self>) {
        tokio::time::sleep(Duration::from_secs(3)).await;
        loop {
            self.check_rivals().await;
            tokio::time::sleep(RIVALS_EVERY).await;
        }
    }

    async fn prune_loop(self: Arc<Self>, pool: SharedPool) {
        let mut tick = tokio::time::interval(PRUNE_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = now();
            let gone = pool.lock().prune_expired(now);
            if let Err(e) = self.storage.delete_expired_dhcp_leases(now as i64).await {
                tracing::warn!("dhcp: couldn't sweep expired leases: {e}");
            }
            if gone > 0 {
                self.refresh_names();
            }
        }
    }

    /// Answer `<name>.<domain>` for every lease that came with a name, and for
    /// every named reservation.
    fn refresh_names(&self) {
        let domain = self.domain.lock().clone();
        let mut names: Vec<(String, Ipv4Addr)> = self
            .reserved_names
            .lock()
            .iter()
            .map(|(n, ip)| (format!("{n}.{domain}"), *ip))
            .collect();
        if let Some(pool) = self.pool.lock().clone() {
            let now = now();
            for l in pool.lock().active_leases(now) {
                if let Some(label) = l.hostname.as_deref().and_then(dns_label) {
                    let name = format!("{label}.{domain}");
                    if !names.iter().any(|(n, _)| *n == name) {
                        names.push((name, l.ip));
                    }
                }
            }
        }
        self.records.load_leases(&names, LEASE_NAME_TTL);
    }
}

/// Feed the pool who the box sees at each address of the pool, so it never
/// offers one a device is using.
async fn seen_loop(pool: SharedPool, start: Ipv4Addr, end: Ipv4Addr) {
    let (lo, hi) = (u32::from(start), u32::from(end));
    loop {
        let seen: std::collections::HashMap<Ipv4Addr, [u8; 6]> = ferrite_clients::scan_neighbors()
            .await
            .into_iter()
            .filter_map(|(ip, mac)| match ip {
                std::net::IpAddr::V4(v4) if (lo..=hi).contains(&u32::from(v4)) => Some((v4, mac)),
                _ => None,
            })
            .collect();
        pool.lock().set_seen(seen);
        tokio::time::sleep(SEEN_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names_become_dns_labels() {
        assert_eq!(dns_label("Pixel-8 Pro").as_deref(), Some("pixel-8-pro"));
        assert_eq!(
            dns_label("Living_Room TV.").as_deref(),
            Some("living-room-tv")
        );
        assert_eq!(dns_label("  --iPad--  ").as_deref(), Some("ipad"));
        assert_eq!(dns_label("Кухня"), None);
        assert_eq!(dns_label(&"a".repeat(80)).map(|l| l.len()), Some(63));
    }

    #[test]
    fn subnets_compare_by_mask() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert!(same_subnet(
            "192.168.1.5".parse().unwrap(),
            "192.168.1.200".parse().unwrap(),
            mask
        ));
        assert!(!same_subnet(
            "192.168.2.5".parse().unwrap(),
            "192.168.1.200".parse().unwrap(),
            mask
        ));
    }
}
