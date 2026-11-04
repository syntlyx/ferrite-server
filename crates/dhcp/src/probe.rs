//! Is another DHCP server answering on this network? A network takes one:
//! with two, a device gets its address (and its DNS server) from whichever
//! answers first. Before ferrite hands out addresses — and every so often
//! while it does — it asks, the way a device joining the network would: a
//! DISCOVER broadcast, then every OFFER that comes back within a few seconds.
//!
//! It asks as a made-up device (a locally administered MAC), so no real
//! device's lease is touched, and binds the client port with address reuse,
//! next to whatever DHCP client the box itself runs.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::message::{DhcpMessage, Op};
use crate::options::{DhcpOption, MessageType};

/// Another server that offered an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rival {
    /// Its server identifier — usually the router's address.
    pub server: Ipv4Addr,
    /// The address it offered the made-up device.
    pub offered: Ipv4Addr,
    /// The DNS servers it hands out.
    pub dns: Vec<Ipv4Addr>,
}

/// The DISCOVER a probe sends.
pub(crate) fn discover(xid: u32, mac: [u8; 6]) -> DhcpMessage {
    DhcpMessage {
        op: Op::BootRequest,
        xid,
        secs: 0,
        // Broadcast flag: answers come to 255.255.255.255, which we can hear.
        flags: 0x8000,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: mac,
        options: vec![
            DhcpOption::MessageType(MessageType::Discover),
            // Subnet mask, router, DNS servers.
            DhcpOption::ParameterRequestList(vec![1, 3, 6]),
        ],
    }
}

/// An answer to our DISCOVER from a server other than ours, if `msg` is one.
pub(crate) fn rival(msg: &DhcpMessage, xid: u32, ours: &[Ipv4Addr]) -> Option<Rival> {
    if msg.op != Op::BootReply || msg.xid != xid || msg.message_type() != Some(MessageType::Offer) {
        return None;
    }
    let server = msg.server_identifier()?;
    if ours.contains(&server) {
        return None;
    }
    let dns = msg
        .options
        .iter()
        .find_map(|o| match o {
            DhcpOption::DnsServers(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap_or_default();
    Some(Rival {
        server,
        offered: msg.yiaddr,
        dns,
    })
}

/// Ask the network for DHCP servers and list those that aren't in `ours`
/// (this box's addresses). Takes `wait`.
pub async fn probe(ours: &[Ipv4Addr], wait: Duration) -> io::Result<Vec<Rival>> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    let _ = sock.set_reuse_port(true);
    sock.set_broadcast(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 68)).into())?;
    sock.set_nonblocking(true)?;
    let sock = UdpSocket::from_std(sock.into())?;

    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5eed);
    let xid = (seed as u32) ^ ((seed >> 32) as u32);
    // Locally administered, unicast; the rest from the clock.
    let mac = [
        0x02,
        0xfe,
        (seed >> 8) as u8,
        (seed >> 16) as u8,
        (seed >> 24) as u8,
        seed as u8,
    ];
    let mut bytes = discover(xid, mac).encode();
    if bytes.len() < 300 {
        bytes.resize(300, 0);
    }
    sock.send_to(&bytes, SocketAddrV4::new(Ipv4Addr::BROADCAST, 67))
        .await?;

    let deadline = Instant::now() + wait;
    let mut found: Vec<Rival> = Vec::new();
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let Ok(Ok((n, _))) = tokio::time::timeout(left, sock.recv_from(&mut buf)).await else {
            break;
        };
        if let Ok(msg) = DhcpMessage::decode(&buf[..n])
            && let Some(r) = rival(&msg, xid, ours)
            && !found.iter().any(|f| f.server == r.server)
        {
            found.push(r);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(xid: u32, server: Ipv4Addr) -> DhcpMessage {
        DhcpMessage {
            op: Op::BootReply,
            xid,
            secs: 0,
            flags: 0x8000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::new(192, 168, 1, 150),
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [2, 0xfe, 1, 2, 3, 4],
            options: vec![
                DhcpOption::MessageType(MessageType::Offer),
                DhcpOption::ServerIdentifier(server),
                DhcpOption::DnsServers(vec![Ipv4Addr::new(192, 168, 1, 1)]),
            ],
        }
    }

    #[test]
    fn offers_from_other_servers_are_rivals() {
        let router = Ipv4Addr::new(192, 168, 1, 1);
        let us = Ipv4Addr::new(192, 168, 1, 10);
        let r = rival(&offer(7, router), 7, &[us]).unwrap();
        assert_eq!(r.server, router);
        assert_eq!(r.offered, Ipv4Addr::new(192, 168, 1, 150));
        assert_eq!(r.dns, vec![router]);
        // Our own server's offer, an answer to someone else, or a request.
        assert!(rival(&offer(7, us), 7, &[us]).is_none());
        assert!(rival(&offer(8, router), 7, &[us]).is_none());
        let mut req = offer(7, router);
        req.op = Op::BootRequest;
        assert!(rival(&req, 7, &[us]).is_none());
    }

    #[test]
    fn the_discover_round_trips() {
        let d = discover(9, [2, 0xfe, 0, 0, 0, 1]);
        let back = DhcpMessage::decode(&d.encode()).unwrap();
        assert_eq!(back.message_type(), Some(MessageType::Discover));
        assert!(back.broadcast());
        assert_eq!(back.xid, 9);
    }
}
