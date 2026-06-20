use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Extract the original MAC address from an EUI-64-derived IPv6 interface ID.
///
/// EUI-64 embeds a 6-byte MAC as:
///   `[mac[0]^0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]]`
/// in the lower 8 octets (bytes 8–15) of the address.  The `0xff 0xfe` marker
/// at bytes 11–12 identifies EUI-64; its absence means privacy extensions or a
/// random/manually-assigned ID — we return `None` in that case.
pub fn extract_eui64_mac(v6: Ipv6Addr) -> Option<[u8; 6]> {
    let b = v6.octets();
    if b[11] != 0xff || b[12] != 0xfe {
        return None;
    }
    Some([
        b[8] ^ 0x02, // restore U/L bit
        b[9],
        b[10],
        b[13],
        b[14],
        b[15],
    ])
}

/// Parse a colon- or hyphen-separated 6-byte MAC address.
/// Returns `None` for broadcast (`ff:ff:…`) or all-zero addresses.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let sep = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return None;
    };
    let mut mac = [0u8; 6];
    let mut n = 0usize;
    for (i, part) in s.split(sep).enumerate() {
        if i >= 6 {
            return None;
        }
        mac[i] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    if n != 6 || mac == [0u8; 6] || mac == [0xff; 6] {
        return None;
    }
    Some(mac)
}

/// Return the MAC address for a specific IPv4 by querying the local ARP table.
pub async fn lookup_mac_for_ipv4(ipv4: Ipv4Addr) -> Option<[u8; 6]> {
    let text = arp_entry_text(ipv4).await?;
    text.split_whitespace().find_map(parse_mac)
}

/// Return the MAC address for a specific IP by querying the local neighbour tables.
pub async fn lookup_mac_for_ip(ip: IpAddr) -> Option<[u8; 6]> {
    match ip {
        IpAddr::V4(ipv4) => lookup_mac_for_ipv4(ipv4).await,
        IpAddr::V6(ipv6) => lookup_mac_for_ipv6(ipv6).await,
    }
}

/// Return the MAC address for a specific IPv6 by querying the local NDP table.
pub async fn lookup_mac_for_ipv6(ipv6: Ipv6Addr) -> Option<[u8; 6]> {
    let text = ndp_table_text().await?;
    parse_mac_for_ipv6(&text, ipv6)
}

/// Scan the full ARP table and return the first IPv4 that maps to `target_mac`.
pub async fn lookup_ipv4_for_mac(target_mac: [u8; 6]) -> Option<Ipv4Addr> {
    let text = arp_table_text().await?;
    parse_ipv4_for_mac(&text, target_mac)
}

/// Parse the ARP table text (either macOS `arp -an` or Linux `ip neigh show`)
/// and return the first IPv4 entry whose MAC matches `target_mac`.
pub fn parse_ipv4_for_mac(text: &str, target_mac: [u8; 6]) -> Option<Ipv4Addr> {
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();

        // macOS: `? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ...`
        if tokens.first() == Some(&"?") && tokens.len() >= 4 {
            if let Some(mac) = parse_mac(tokens[3]) {
                if mac == target_mac {
                    let ip_s = tokens[1].trim_start_matches('(').trim_end_matches(')');
                    if let Ok(ip) = ip_s.parse::<Ipv4Addr>() {
                        return Some(ip);
                    }
                }
            }
            continue;
        }

        // Linux: `192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`
        if let Some(pos) = tokens.iter().position(|&t| t == "lladdr") {
            if let Some(&mac_str) = tokens.get(pos + 1) {
                if let Some(mac) = parse_mac(mac_str) {
                    if mac == target_mac {
                        if let Ok(ip) = tokens[0].parse::<Ipv4Addr>() {
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Parse IPv6 neighbour table text (`ip -6 neigh` or `ndp -an`) and return
/// the MAC for `target_ip`.
pub fn parse_mac_for_ipv6(text: &str, target_ip: Ipv6Addr) -> Option<[u8; 6]> {
    for line in text.lines() {
        if !line_has_ipv6(line, target_ip) {
            continue;
        }
        if let Some(mac) = line.split_whitespace().find_map(parse_mac_token) {
            return Some(mac);
        }
    }
    None
}

fn line_has_ipv6(line: &str, target_ip: Ipv6Addr) -> bool {
    line.split_whitespace()
        .filter_map(parse_ipv6_token)
        .any(|ip| ip == target_ip)
}

fn parse_ipv6_token(token: &str) -> Option<Ipv6Addr> {
    let token = token
        .trim_matches(|c: char| matches!(c, '(' | ')' | '?' | ',' | ';'))
        .split('%')
        .next()?;
    token.parse().ok()
}

fn parse_mac_token(token: &str) -> Option<[u8; 6]> {
    let token = token.trim_matches(|c: char| matches!(c, '(' | ')' | ',' | ';'));
    parse_mac(token)
}

/// Parse any IP token (v4 or v6), stripping `()?,;` decoration and `%scope`.
fn parse_ip_token(token: &str) -> Option<IpAddr> {
    let token = token.trim_matches(|c: char| matches!(c, '(' | ')' | '?' | ',' | ';'));
    token.split('%').next()?.parse().ok()
}

/// Extract the first `(IP, MAC)` pair from a neighbour-table line. Works across
/// the macOS (`arp -an`, `ndp -an`) and Linux (`ip neigh show`) formats: a MAC is
/// exactly 6 colon/hyphen hex groups, so it never collides with an IP token.
fn parse_neighbor_line(line: &str) -> Option<(IpAddr, [u8; 6])> {
    let mut ip = None;
    let mut mac = None;
    for token in line.split_whitespace() {
        if mac.is_none() {
            if let Some(m) = parse_mac_token(token) {
                mac = Some(m);
                continue;
            }
        }
        if ip.is_none() {
            ip = parse_ip_token(token);
        }
    }
    Some((ip?, mac?))
}

/// Bulk-scan the full ARP + NDP neighbour tables into `(IP, MAC)` pairs.
/// One subprocess per table (each capped by the 500 ms timeout in `run`), far
/// cheaper than a per-IP lookup. Incomplete/failed entries (no MAC) are skipped.
pub async fn scan_neighbors() -> Vec<(IpAddr, [u8; 6])> {
    let mut out = Vec::new();
    if let Some(text) = arp_table_text().await {
        out.extend(text.lines().filter_map(parse_neighbor_line));
    }
    if let Some(text) = ndp_table_text().await {
        out.extend(text.lines().filter_map(parse_neighbor_line));
    }
    out
}

// ── OS-specific ARP I/O ──────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn arp_entry_text(ipv4: Ipv4Addr) -> Option<String> {
    run("arp", &["-n", &ipv4.to_string()]).await
}

#[cfg(not(target_os = "macos"))]
async fn arp_entry_text(ipv4: Ipv4Addr) -> Option<String> {
    run("ip", &["-4", "neigh", "show", &ipv4.to_string()]).await
}

#[cfg(target_os = "macos")]
async fn arp_table_text() -> Option<String> {
    run("arp", &["-an"]).await
}

#[cfg(not(target_os = "macos"))]
async fn arp_table_text() -> Option<String> {
    run("ip", &["neigh", "show"]).await
}

#[cfg(target_os = "macos")]
async fn ndp_table_text() -> Option<String> {
    run("ndp", &["-an"]).await
}

#[cfg(not(target_os = "macos"))]
async fn ndp_table_text() -> Option<String> {
    run("ip", &["-6", "neigh", "show"]).await
}

async fn run(cmd: &str, args: &[&str]) -> Option<String> {
    use tokio::time::{timeout, Duration};
    // 500 ms is more than enough for a local ARP/neighbour lookup.
    // Without a cap, a stuck `ip neigh show` would hold a tokio task indefinitely,
    // accumulating across many clients until the runtime is saturated.
    let out = timeout(
        Duration::from_millis(500),
        tokio::process::Command::new(cmd).args(args).output(),
    )
    .await
    .ok()? // Elapsed → None
    .ok()?; // io::Error → None
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn eui64_extraction() {
        // fe80::a0ce:c8ff:fe12:3456 encodes MAC a2:ce:c8:12:34:56
        let v6: Ipv6Addr = "fe80::a0ce:c8ff:fe12:3456".parse().unwrap();
        assert_eq!(
            extract_eui64_mac(v6),
            Some([0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56])
        );
    }

    #[test]
    fn eui64_privacy_extensions_rejected() {
        let v6: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
        assert!(extract_eui64_mac(v6).is_none());
    }

    #[test]
    fn parse_mac_colon() {
        assert_eq!(
            parse_mac("a2:ce:c8:12:34:56"),
            Some([0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56])
        );
    }

    #[test]
    fn parse_mac_rejects_broadcast() {
        assert!(parse_mac("ff:ff:ff:ff:ff:ff").is_none());
    }

    #[test]
    fn arp_table_macos() {
        let text = "? (192.168.1.5) at a2:ce:c8:12:34:56 on en0 ifscope [ethernet]\n\
                    ? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]\n";
        assert_eq!(
            parse_ipv4_for_mac(text, [0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56]),
            Some("192.168.1.5".parse::<Ipv4Addr>().unwrap())
        );
    }

    #[test]
    fn arp_table_linux() {
        let text = "192.168.1.5 dev eth0 lladdr a2:ce:c8:12:34:56 REACHABLE\n\
                    192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n";
        assert_eq!(
            parse_ipv4_for_mac(text, [0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56]),
            Some("192.168.1.5".parse::<Ipv4Addr>().unwrap())
        );
    }

    #[test]
    fn ndp_table_linux() {
        let text = "fe80::a0ce:c8ff:fe12:3456 dev eth0 lladdr a2:ce:c8:12:34:56 REACHABLE\n\
                    fd00::1234 dev eth0 lladdr 00:11:22:33:44:55 STALE\n";
        assert_eq!(
            parse_mac_for_ipv6(
                text,
                "fe80::a0ce:c8ff:fe12:3456".parse::<Ipv6Addr>().unwrap()
            ),
            Some([0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56])
        );
    }

    #[test]
    fn neighbor_line_parses_macos_arp() {
        assert_eq!(
            parse_neighbor_line("? (192.168.1.5) at a2:ce:c8:12:34:56 on en0 ifscope [ethernet]"),
            Some((
                "192.168.1.5".parse::<IpAddr>().unwrap(),
                [0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56]
            ))
        );
    }

    #[test]
    fn neighbor_line_parses_linux_neigh() {
        assert_eq!(
            parse_neighbor_line("192.168.1.5 dev eth0 lladdr a2:ce:c8:12:34:56 REACHABLE"),
            Some((
                "192.168.1.5".parse::<IpAddr>().unwrap(),
                [0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56]
            ))
        );
    }

    #[test]
    fn neighbor_line_parses_ipv6_ndp_with_scope() {
        assert_eq!(
            parse_neighbor_line("fe80::a0ce:c8ff:fe12:3456%en0 a2:ce:c8:12:34:56 en0 23h59m R"),
            Some((
                "fe80::a0ce:c8ff:fe12:3456".parse::<IpAddr>().unwrap(),
                [0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56]
            ))
        );
    }

    #[test]
    fn neighbor_line_without_mac_is_skipped() {
        // INCOMPLETE/FAILED neighbour entries carry no link-layer address.
        assert_eq!(parse_neighbor_line("192.168.1.9 dev eth0  INCOMPLETE"), None);
    }

    #[test]
    fn ndp_table_macos_with_scope_id() {
        let text = "fe80::a0ce:c8ff:fe12:3456%en0 a2:ce:c8:12:34:56 en0 23h59m R\n\
                    fd00::1234%en0 00:11:22:33:44:55 en0 18m S\n";
        assert_eq!(
            parse_mac_for_ipv6(
                text,
                "fe80::a0ce:c8ff:fe12:3456".parse::<Ipv6Addr>().unwrap()
            ),
            Some([0xa2, 0xce, 0xc8, 0x12, 0x34, 0x56])
        );
    }
}
