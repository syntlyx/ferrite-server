use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use socket2::{Domain, Protocol, Socket, Type};

const MDNS_V4_ADDR: &str = "224.0.0.251:5353";
const MDNS_V6_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb); // ff02::fb
const MDNS_TIMEOUT: Duration = Duration::from_millis(1500);
const MDNS_PER_IFACE_TIMEOUT: Duration = Duration::from_millis(600);

/// Perform a native mDNS reverse PTR lookup without external tools.
///
/// * **IPv4** — sends a PTR query to `224.0.0.251:5353` via UDP.
///   Per RFC 6762 §11.1, using an ephemeral source port triggers a unicast
///   response from the device, so no multicast group membership is required.
///
/// * **IPv6** — sends a PTR query to `[ff02::fb]:5353` on every local
///   link-local interface (discovered from `/proc/net/if_inet6` on Linux or
///   tried by index on other platforms).  Uses `IPV6_MULTICAST_IF` via
///   `socket2` to bind the outgoing interface correctly.  No external tools
///   (`avahi-resolve`, etc.) are required.
///
/// Returns `None` on timeout or if no mDNS-capable device responds.
pub async fn mdns_ptr_lookup(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(_) => tokio::time::timeout(MDNS_TIMEOUT, query_v4(ip))
            .await
            .ok()
            .flatten(),
        IpAddr::V6(v6) => tokio::time::timeout(MDNS_TIMEOUT, query_v6(v6))
            .await
            .ok()
            .flatten(),
    }
}

// ── IPv4 ──────────────────────────────────────────────────────────────────────

async fn query_v4(ip: IpAddr) -> Option<String> {
    let ptr_domain = ip_to_ptr_domain(ip);
    let raw = build_query(&ptr_domain)?;

    // Binding to port 0 ensures the OS assigns an ephemeral source port,
    // which triggers unicast responses as per RFC 6762 §11.1.
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let dest: SocketAddr = MDNS_V4_ADDR.parse().unwrap();
    socket.send_to(&raw, &dest).await.ok()?;

    let mut buf = vec![0u8; 512];
    let (n, _) = socket.recv_from(&mut buf).await.ok()?;
    parse_ptr_response(&buf[..n])
}

// ── IPv6 ──────────────────────────────────────────────────────────────────────

/// Try each link-local interface in sequence; stop on the first response.
async fn query_v6(v6: Ipv6Addr) -> Option<String> {
    let ptr_domain = ip_to_ptr_domain(IpAddr::V6(v6));
    let raw = build_query(&ptr_domain)?;

    for iface_idx in link_local_interface_indices().await {
        if let Some(name) = tokio::time::timeout(MDNS_PER_IFACE_TIMEOUT, send_v6(&raw, iface_idx))
            .await
            .ok()
            .flatten()
        {
            return Some(name);
        }
    }
    None
}

/// Send one mDNS PTR query on `iface_idx` and return the PTR answer if any.
async fn send_v6(raw: &[u8], iface_idx: u32) -> Option<String> {
    // socket2 gives us IPV6_MULTICAST_IF which tokio/std don't expose.
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    sock.set_nonblocking(true).ok()?;
    sock.set_only_v6(true).ok()?;
    // Outgoing multicast uses this interface.
    sock.set_multicast_if_v6(iface_idx).ok()?;
    // Ephemeral source port → unicast response (RFC 6762 §11.1).
    sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into())
        .ok()?;

    let udp = tokio::net::UdpSocket::from_std(sock.into()).ok()?;

    // Include scope_id in the destination so the kernel routes it correctly.
    let dest = SocketAddrV6::new(MDNS_V6_MULTICAST, 5353, 0, iface_idx);
    udp.send_to(raw, dest).await.ok()?;

    let mut buf = vec![0u8; 512];
    udp.recv_from(&mut buf)
        .await
        .ok()
        .and_then(|(n, _)| parse_ptr_response(&buf[..n]))
}

/// Return the deduplicated interface indices of all link-local IPv6 interfaces.
///
/// **Linux**: parsed from `/proc/net/if_inet6` (scope column `20` = link-local).
/// **Other**: falls back to `[0]` (let the OS pick; works when there is only
/// one active interface).
async fn link_local_interface_indices() -> Vec<u32> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/if_inet6").await {
            // Format: addr  iface_idx(hex)  prefix_len  scope(hex)  flags  name
            // Scope 0x20 = link-local.
            let mut seen = std::collections::HashSet::new();
            let indices: Vec<u32> = content
                .lines()
                .filter_map(|line| {
                    let mut cols = line.split_whitespace();
                    let _ = cols.next()?; // address
                    let idx = cols.next()?; // iface index (hex)
                    let _ = cols.next()?; // prefix len
                    let scope = cols.next()?; // scope
                    if scope == "20" {
                        u32::from_str_radix(idx, 16).ok()
                    } else {
                        None
                    }
                })
                .filter(|idx| seen.insert(*idx))
                .collect();

            if !indices.is_empty() {
                return indices;
            }
        }
    }

    // Fallback: index 0 means "let OS choose" on most platforms.
    vec![0]
}

// ── Shared DNS helpers ────────────────────────────────────────────────────────

// Delegate to the shared implementation in the parent module.
fn ip_to_ptr_domain(ip: IpAddr) -> String {
    super::ip_to_ptr_domain(ip)
}

fn build_query(ptr_domain: &str) -> Option<Vec<u8>> {
    let name = Name::from_ascii(ptr_domain).ok()?;

    let mut question = Query::new();
    question.set_name(name);
    question.set_query_type(RecordType::PTR);
    question.set_query_class(DNSClass::IN);

    let mut msg = Message::new(super::random_query_id()?, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = false; // mDNS does not use recursion
    msg.add_query(question);

    msg.to_bytes().ok()
}

fn parse_ptr_response(bytes: &[u8]) -> Option<String> {
    let msg = Message::from_bytes(bytes).ok()?;
    for answer in &msg.answers {
        if let RData::PTR(ptr) = &answer.data {
            let s = ptr.to_string();
            let s = s.trim_end_matches('.');
            if !s.is_empty() {
                return Some(s.to_ascii_lowercase());
            }
        }
    }
    None
}
