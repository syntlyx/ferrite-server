//! IP/MAC parsing and normalization utilities shared across subsystems.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// Parse a MAC address in `"aa:bb:cc:dd:ee:ff"` or `"aa-bb-cc-dd-ee-ff"` format.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let s = s.replace('-', ":");
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Format a MAC address as `"aa:bb:cc:dd:ee:ff"`.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse an IP string, stripping IPv6 scope IDs (`%eth0`).
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.split('%').next()?.parse().ok()
}

/// Normalize a client identity key accepted by policy/settings APIs.
/// Supports IP addresses and MAC addresses.
pub fn normalize_client_key(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(ip) = parse_ip(s) {
        return Some(unmap_v4(ip).to_string());
    }
    parse_mac(s).map(|mac| format_mac(&mac))
}

/// Convert IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4.
pub fn unmap_v4(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(v4);
    }
    ip
}

/// Local IPv4 for internet traffic via dummy UDP connect (no packets sent).
pub fn local_ipv4_for_internet() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}
