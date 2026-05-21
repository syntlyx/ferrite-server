use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

use crate::config::{Config, ZoneConfig};

// ── Public entry point ────────────────────────────────────────────────────────

/// `ferrite setup` — detect local network and write zone config automatically.
pub fn cmd_setup() -> anyhow::Result<()> {
    println!("Detecting local network…\n");

    let net = detect_network();
    let search = read_search_domains();

    if let Some(ip) = net.local_ipv4 {
        println!("  IPv4     : {}/{}", ip, net.ipv4_prefix);
    } else {
        println!("  IPv4     : (not detected)");
    }
    for (ip, prefix) in &net.local_ipv6 {
        println!("  IPv6     : {}/{}", ip, prefix);
    }
    if let Some(ref gw) = net.gateway {
        println!("  Gateway  : {}", gw);
    } else {
        println!("  Gateway  : (not detected)");
    }
    if !search.is_empty() {
        println!("  Search   : {}", search.join(", "));
    }
    println!();

    let zones = build_zones(&net, &search);

    if zones.is_empty() {
        eprintln!("Could not detect a private local network.");
        eprintln!("Add [[zones]] entries manually — see config.toml.example.");
        return Ok(());
    }

    println!("Zones detected:");
    let width = zones.iter().map(|z| z.name.len()).max().unwrap_or(0);
    for z in &zones {
        println!("  {:<w$}  →  {}", z.name, z.upstream, w = width);
    }
    println!();

    let config_path = Config::config_candidates()
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| crate::config::config_dir().join("config.toml"));

    if config_path.exists() {
        let raw = std::fs::read_to_string(&config_path)?;
        let existing: Config = toml::from_str(&raw).unwrap_or_default();

        if !existing.zones.is_empty() {
            println!("Zones already configured in {}:", config_path.display());
            for z in &existing.zones {
                println!("  {} → {}", z.name, z.upstream);
            }
            println!("\nNo changes made.");
            return Ok(());
        }

        // Append zone sections — preserves existing comments.
        let mut toml_zones = String::from("\n# Auto-detected by `ferrite setup`\n");
        for z in &zones {
            toml_zones.push_str(&format!(
                "\n[[zones]]\nname     = {:?}\nupstream = {:?}\n",
                z.name, z.upstream
            ));
        }
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&config_path)?;
        file.write_all(toml_zones.as_bytes())?;
        println!("Appended to {}", config_path.display());
    } else {
        let cfg = Config {
            zones,
            ..Config::default()
        };
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        cfg.save(&config_path)?;
        println!("Created {}", config_path.display());
        println!("Edit it to configure upstreams, blocklists, and other settings.");
    }

    Ok(())
}

// ── Reusable detection (used at startup) ─────────────────────────────────────

/// Detect zones silently.  Returns empty Vec on failure.
pub fn detect_zones() -> Vec<ZoneConfig> {
    let net = detect_network();
    let search = read_search_domains();
    build_zones(&net, &search)
}

// ── Network detection ─────────────────────────────────────────────────────────

struct NetworkInfo {
    local_ipv4: Option<Ipv4Addr>,
    ipv4_prefix: u8,
    /// Non-link-local, non-loopback IPv6 addresses with their prefix lengths.
    local_ipv6: Vec<(Ipv6Addr, u8)>,
    gateway: Option<String>,
}

fn detect_network() -> NetworkInfo {
    let local_ipv4 = local_ipv4_for_internet();
    let ipv4_prefix = local_ipv4.and_then(detect_ipv4_prefix).unwrap_or(24);
    let local_ipv6 = detect_ipv6_addrs();
    let gateway = detect_gateway();
    NetworkInfo {
        local_ipv4,
        ipv4_prefix,
        local_ipv6,
        gateway,
    }
}

/// Local IPv4 for internet traffic via dummy UDP connect (no packets sent).
pub(crate) fn local_ipv4_for_internet() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// Default gateway IP string.
fn detect_gateway() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        s.lines()
            .find(|l| l.trim().starts_with("gateway:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .map(String::from)
    }
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        let line = s.lines().next()?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        let pos = parts.iter().position(|&p| p == "via")?;
        parts.get(pos + 1).map(|s| s.to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    None
}

/// IPv4 prefix length for the given address.
fn detect_ipv4_prefix(ip: Ipv4Addr) -> Option<u8> {
    let ip_str = ip.to_string();
    #[cfg(target_os = "linux")]
    {
        // "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"
        let out = std::process::Command::new("ip")
            .args(["addr", "show"])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        for line in s.lines() {
            let line = line.trim();
            if line.starts_with("inet ") && line.contains(&ip_str) {
                return line
                    .split_whitespace()
                    .nth(1)?
                    .split('/')
                    .nth(1)?
                    .parse()
                    .ok();
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        // "    inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255"
        let out = std::process::Command::new("ifconfig").output().ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        for line in s.lines() {
            let line = line.trim();
            if line.starts_with("inet ") && line.contains(&ip_str) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let nm_pos = parts.iter().position(|&p| p == "netmask")?;
                return netmask_to_prefix_len(parts.get(nm_pos + 1)?);
            }
        }
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = ip_str;
        None
    }
}

/// Collect non-link-local, non-loopback IPv6 addresses with their prefix lengths.
///
/// These are candidates for ip6.arpa reverse zones routed to the local gateway:
/// - ULA (`fc00::/7`) — definitely local
/// - Global unicast (`2000::/3`) — may have PTR on the local router when the
///   ISP delegates the /64 to the CPE
fn detect_ipv6_addrs() -> Vec<(Ipv6Addr, u8)> {
    #[cfg(target_os = "linux")]
    return detect_ipv6_linux().unwrap_or_default();
    #[cfg(target_os = "macos")]
    return detect_ipv6_macos().unwrap_or_default();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return vec![];
}

#[cfg(target_os = "linux")]
fn detect_ipv6_linux() -> Option<Vec<(Ipv6Addr, u8)>> {
    let out = std::process::Command::new("ip")
        .args(["addr", "show"])
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let mut result = vec![];

    for line in s.lines() {
        let line = line.trim();
        // "inet6 fd12:3456::1/64 scope global"  ← want this
        // "inet6 fe80::1/64 scope link"          ← skip (link-local)
        // "inet6 ::1/128 scope host"             ← skip (loopback)
        if !line.starts_with("inet6 ") {
            continue;
        }
        if line.contains("scope link") || line.contains("scope host") {
            continue;
        }
        let addr_prefix = line.split_whitespace().nth(1)?;
        let (addr_str, prefix_str) = addr_prefix.split_once('/')?;
        let addr: Ipv6Addr = addr_str.parse().ok()?;
        let prefix: u8 = prefix_str.parse().ok()?;
        if !addr.is_loopback() {
            result.push((addr, prefix));
        }
    }
    Some(result)
}

#[cfg(target_os = "macos")]
fn detect_ipv6_macos() -> Option<Vec<(Ipv6Addr, u8)>> {
    let out = std::process::Command::new("ifconfig").output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let mut result = vec![];

    for line in s.lines() {
        let line = line.trim();
        // "inet6 fd12:3456::1 prefixlen 64 autoconf secured"    ← want
        // "inet6 fe80::1%en0 prefixlen 64 scopeid 0x4"          ← skip (has %)
        // "inet6 ::1 prefixlen 128"                              ← skip (loopback)
        if !line.starts_with("inet6 ") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let addr_str = parts.get(1)?;

        // Link-local addresses have a scope ID like `%en0`.
        if addr_str.contains('%') {
            continue;
        }

        let addr: Ipv6Addr = addr_str.parse().ok()?;
        if addr.is_loopback() {
            continue;
        }

        let prefix_pos = parts.iter().position(|&p| p == "prefixlen")?;
        let prefix: u8 = parts.get(prefix_pos + 1)?.parse().ok()?;
        result.push((addr, prefix));
    }
    Some(result)
}

/// Parse a netmask in hex (`0xffffff00`) or dotted-decimal (`255.255.255.0`).
#[cfg(target_os = "macos")]
fn netmask_to_prefix_len(s: &str) -> Option<u8> {
    if let Some(hex) = s.strip_prefix("0x") {
        let n = u32::from_str_radix(hex, 16).ok()?;
        return Some(n.count_ones() as u8);
    }
    let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() == 4 {
        let n = u32::from_be_bytes([parts[0], parts[1], parts[2], parts[3]]);
        return Some(n.count_ones() as u8);
    }
    None
}

// ── Search domain detection ───────────────────────────────────────────────────

fn read_search_domains() -> Vec<String> {
    let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") else {
        return vec![];
    };
    content
        .lines()
        .flat_map(|line| {
            let line = line.trim();
            let rest = line
                .strip_prefix("search ")
                .or_else(|| line.strip_prefix("domain "))?;
            Some(
                rest.split_whitespace()
                    .map(String::from)
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .filter(|d| !d.is_empty())
        .collect()
}

// ── Zone generation ───────────────────────────────────────────────────────────

fn build_zones(net: &NetworkInfo, search: &[String]) -> Vec<ZoneConfig> {
    let Some(ref gateway) = net.gateway else {
        return vec![];
    };
    let upstream = format!("{}:53", gateway);
    let mut zones: Vec<ZoneConfig> = vec![];

    // IPv4 reverse zone.
    if let Some(ip) = net.local_ipv4 {
        if ip.is_private() {
            push_unique(
                &mut zones,
                ipv4_reverse_zone(ip, net.ipv4_prefix),
                &upstream,
            );
        }
    }

    // IPv6 reverse zones (one per distinct zone name).
    for (ip, prefix) in &net.local_ipv6 {
        if !is_link_local_v6(*ip) {
            push_unique(&mut zones, ipv6_reverse_zone(*ip, *prefix), &upstream);
        }
    }

    // Local search domains from /etc/resolv.conf.
    for domain in search {
        if is_local_domain(domain) {
            push_unique(&mut zones, domain.clone(), &upstream);
        }
    }

    zones
}

/// Append a zone only if its name is not already present.
fn push_unique(zones: &mut Vec<ZoneConfig>, name: String, upstream: &str) {
    if !zones.iter().any(|z| z.name == name) {
        zones.push(ZoneConfig {
            name,
            upstream: upstream.to_owned(),
        });
    }
}

/// `192.168.1.x /24` → `"1.168.192.in-addr.arpa"`
fn ipv4_reverse_zone(ip: Ipv4Addr, prefix_len: u8) -> String {
    let o = ip.octets();
    match prefix_len {
        0..=8 => format!("{}.in-addr.arpa", o[0]),
        9..=16 => format!("{}.{}.in-addr.arpa", o[1], o[0]),
        _ => format!("{}.{}.{}.in-addr.arpa", o[2], o[1], o[0]),
    }
}

/// `fd12:3456:789a:1:: /64` → `"1.0.0.0.a.9.8.7.6.5.4.3.2.1.d.f.ip6.arpa"`
///
/// Rounds the prefix up to the nearest nibble boundary before computing the zone.
fn ipv6_reverse_zone(ip: Ipv6Addr, prefix_len: u8) -> String {
    // Number of significant nibbles: round up to nibble boundary, cap at 32.
    let nibble_count = (prefix_len.min(128) as usize).div_ceil(4);
    let nibble_count = nibble_count.min(32);

    let nibbles: Vec<u8> = ip.octets().iter().flat_map(|b| [b >> 4, b & 0xf]).collect();

    let zone: String = nibbles[..nibble_count]
        .iter()
        .rev()
        .map(|n| format!("{:x}", n))
        .collect::<Vec<_>>()
        .join(".");

    format!("{}.ip6.arpa", zone)
}

fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_local_domain(domain: &str) -> bool {
    const LOCAL: &[&str] = &[
        "local",
        "localdomain",
        "lan",
        "home",
        "internal",
        "home.arpa",
        "corp",
        "intranet",
    ];
    LOCAL.contains(&domain) || LOCAL.iter().any(|s| domain.ends_with(&format!(".{}", s)))
}
