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
/// Supports IP addresses, MAC addresses and client IDs (`id:pixel` — the
/// device name an encrypted-DNS connection carries).
pub fn normalize_client_key(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(id) = s.strip_prefix("id:").or_else(|| s.strip_prefix("ID:")) {
        return normalize_client_id(id).map(|id| format!("id:{id}"));
    }
    if let Some(ip) = parse_ip(s) {
        return Some(unmap_v4(ip).to_string());
    }
    parse_mac(s).map(|mac| format_mac(&mac))
}

/// A client ID as ferrite keys it: one DNS label — lowercase letters, digits
/// and hyphens, 1–63 long, not starting or ending with a hyphen.
pub fn normalize_client_id(s: &str) -> Option<String> {
    let id = s.trim().to_ascii_lowercase();
    let ok = (1..=63).contains(&id.len())
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    ok.then_some(id)
}

/// An address range: `192.168.1.0/24`, `fd00::/8`, or a single address (a
/// bare IP is its own /32 or /128). IPv4-mapped IPv6 addresses are compared as
/// the IPv4 they carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNetwork {
    addr: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// Parse `addr[/prefix]`; `None` for anything else. Host bits below the
    /// prefix are allowed and ignored (`192.168.1.7/24` is the /24).
    pub fn parse(s: &str) -> Option<IpNetwork> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim().parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr = unmap_v4(parse_ip(addr)?);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(IpNetwork { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, unmap_v4(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let max = if self.addr.is_ipv4() { 32 } else { 128 };
        if self.prefix == max {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
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

/// The box's default IPv4 gateway, read from the kernel's routing table
/// (`/proc/net/route` on Linux; `None` elsewhere or when there is none).
pub fn default_ipv4_gateway() -> Option<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_gateway(&table)
}

/// The gateway of the first default route in a `/proc/net/route` table.
/// Addresses there are hex in host (little-endian) byte order.
fn parse_default_gateway(table: &str) -> Option<Ipv4Addr> {
    table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (dest, gw, flags) = (cols.get(1)?, cols.get(2)?, cols.get(3)?);
        let up_and_gateway = u32::from_str_radix(flags, 16).ok()? & 0x3 == 0x3;
        if *dest != "00000000" || !up_and_gateway {
            return None;
        }
        let gw = u32::from_str_radix(gw, 16).ok()?;
        (gw != 0).then(|| Ipv4Addr::from(gw.to_le_bytes()))
    })
}

/// The interface the default IPv4 route leaves by, e.g. `eth0`.
pub fn default_route_interface() -> Option<String> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_interface(&table)
}

fn parse_default_interface(table: &str) -> Option<String> {
    table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (iface, dest, flags) = (cols.first()?, cols.get(1)?, cols.get(3)?);
        let up = u32::from_str_radix(flags, 16).ok()? & 0x1 == 0x1;
        (*dest == "00000000" && up).then(|| iface.to_string())
    })
}

/// The mask of the directly attached subnet `ip` sits in, from the kernel's
/// routing table: the on-link route (no gateway) whose network holds `ip`.
pub fn ipv4_subnet_mask(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_subnet_mask(&table, ip)
}

fn parse_subnet_mask(table: &str, ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let hex = |s: &str| {
        u32::from_str_radix(s, 16)
            .ok()
            .map(|v| Ipv4Addr::from(v.to_le_bytes()))
    };
    table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (dest, gw, mask) = (hex(cols.get(1)?)?, hex(cols.get(2)?)?, hex(cols.get(7)?)?);
        let (ip, dest, mask_bits) = (u32::from(ip), u32::from(dest), u32::from(mask));
        (gw.is_unspecified() && mask_bits != 0 && ip & mask_bits == dest).then_some(mask)
    })
}

/// The interface's stable IPv6 addresses — global and unique-local (ULA),
/// not link-local, not temporary (privacy) and not deprecated — read from
/// `/proc/net/if_inet6`. ULA first: it survives a change of the ISP's prefix.
pub fn interface_ipv6(iface: &str) -> Vec<std::net::Ipv6Addr> {
    std::fs::read_to_string("/proc/net/if_inet6")
        .map(|t| parse_if_inet6(&t, iface))
        .unwrap_or_default()
}

fn parse_if_inet6(table: &str, iface: &str) -> Vec<std::net::Ipv6Addr> {
    // IFA_F_TEMPORARY, IFA_F_DEPRECATED, IFA_F_TENTATIVE.
    const SKIP: u32 = 0x01 | 0x20 | 0x40;
    let mut out: Vec<std::net::Ipv6Addr> = table
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 || cols[5] != iface {
                return None;
            }
            let scope = u32::from_str_radix(cols[3], 16).ok()?;
            let flags = u32::from_str_radix(cols[4], 16).ok()?;
            if scope != 0 || flags & SKIP != 0 {
                return None;
            }
            u128::from_str_radix(cols[0], 16)
                .ok()
                .map(std::net::Ipv6Addr::from)
        })
        .collect();
    out.sort_by_key(|a| a.segments()[0] & 0xfe00 != 0xfc00);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn client_keys_take_ids_too() {
        assert_eq!(
            super::normalize_client_key("id:Pixel-8").as_deref(),
            Some("id:pixel-8")
        );
        assert_eq!(super::normalize_client_key("id:-bad"), None);
        assert_eq!(super::normalize_client_key("id:a.b"), None);
        assert_eq!(
            super::normalize_client_key("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(super::normalize_client_id(&"x".repeat(64)), None);
    }

    #[test]
    fn interface_and_mask_come_from_the_route_table() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(
            super::parse_default_interface(table).as_deref(),
            Some("eth0")
        );
        assert_eq!(
            super::parse_subnet_mask(table, "192.168.1.7".parse().unwrap()),
            Some(std::net::Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(
            super::parse_subnet_mask(table, "10.0.0.7".parse().unwrap()),
            None
        );
    }

    #[test]
    fn stable_ipv6_addresses_ula_first() {
        let table = "fe800000000000000211223344556677 02 40 20 80 eth0\n\
                     2a0204000000000000000000000000aa 02 40 00 00 eth0\n\
                     2a0204000000000000000000000000bb 02 40 00 01 eth0\n\
                     fd000000000000000000000000000001 02 40 00 80 eth0\n\
                     fd000000000000000000000000000002 03 40 00 80 wlan0\n";
        let got = super::parse_if_inet6(table, "eth0");
        assert_eq!(
            got,
            vec![
                "fd00::1".parse::<std::net::Ipv6Addr>().unwrap(),
                "2a02:400::aa".parse().unwrap()
            ]
        );
    }

    #[test]
    fn default_gateway_comes_from_the_route_table() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
                     eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(
            super::parse_default_gateway(table),
            Some(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(super::parse_default_gateway("Iface\tDestination\n"), None);
    }

    #[test]
    fn networks_parse_and_match() {
        let lan = IpNetwork::parse("192.168.1.7/24").unwrap();
        assert!(lan.contains("192.168.1.200".parse().unwrap()));
        assert!(lan.contains("::ffff:192.168.1.5".parse().unwrap()));
        assert!(!lan.contains("192.168.2.1".parse().unwrap()));
        assert!(!lan.contains("fd00::1".parse().unwrap()));
        assert_eq!(lan.to_string(), "192.168.1.7/24");

        let host = IpNetwork::parse(" 10.0.0.5 ").unwrap();
        assert!(host.contains("10.0.0.5".parse().unwrap()));
        assert!(!host.contains("10.0.0.6".parse().unwrap()));
        assert_eq!(host.to_string(), "10.0.0.5");

        let ula = IpNetwork::parse("fd00::/8").unwrap();
        assert!(ula.contains("fdab::1".parse().unwrap()));
        assert!(!ula.contains("2001:db8::1".parse().unwrap()));

        assert!(
            IpNetwork::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert!(IpNetwork::parse("10.0.0.0/33").is_none());
        assert!(IpNetwork::parse("not-an-ip").is_none());
        assert!(IpNetwork::parse("10.0.0.0/x").is_none());
    }

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
