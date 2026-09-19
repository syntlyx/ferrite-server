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

/// An address as text, the way `to_string()` writes it — but without the
/// formatting machinery for the IPv4 case.
///
/// Every logged query formats its client address, and `Display` for an
/// `IpAddr` goes through a `Formatter` to do it (~78 ns for IPv4 here, ~167 ns
/// for IPv6) — on the DNS hot path that was the single most expensive step
/// left. IPv4 has exactly one spelling, four decimal octets, so it is written
/// digit by digit into a stack buffer instead. IPv6 keeps `Display`: RFC 5952
/// zero-compression (and the embedded-IPv4 forms) is not worth re-deriving for
/// a second spelling of the same address, and `ip_text_matches_display` holds
/// both paths to it.
pub fn ip_to_string(addr: IpAddr) -> String {
    let IpAddr::V4(v4) = addr else {
        return addr.to_string();
    };
    // "255.255.255.255" is the longest form.
    let mut out = String::with_capacity(15);
    for (i, octet) in v4.octets().iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        if *octet >= 100 {
            out.push((b'0' + octet / 100) as char);
        }
        if *octet >= 10 {
            out.push((b'0' + (octet / 10) % 10) as char);
        }
        out.push((b'0' + octet % 10) as char);
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_text_matches_display() {
        // Octet shapes: one, two and three digits, zero, and the extremes.
        for text in [
            "0.0.0.0",
            "1.2.3.4",
            "10.0.0.1",
            "192.168.1.117",
            "255.255.255.255",
            "100.64.9.90",
        ] {
            let addr: IpAddr = text.parse().unwrap();
            assert_eq!(ip_to_string(addr), addr.to_string());
            assert_eq!(ip_to_string(addr), text);
        }
        // IPv6 keeps Display, zero-compression and all.
        for text in [
            "::",
            "::1",
            "2a02:2378:1234:abcd:1:2:3:4",
            "fe80::1c2b:3aff:fe4d:5e6f",
            "2001:db8::",
        ] {
            let addr: IpAddr = text.parse().unwrap();
            assert_eq!(ip_to_string(addr), addr.to_string());
        }
    }
}
