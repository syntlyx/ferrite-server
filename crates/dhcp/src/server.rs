//! The DHCPv4 UDP server loop.
//!
//! Binds `0.0.0.0:67` (so it receives the broadcast DISCOVER/REQUEST), decodes
//! each datagram, runs the [`crate::handler`] decision logic against the shared
//! lease pool, and sends the reply. Replies to a client that has no usable
//! address yet go out by **broadcast** to `255.255.255.255:68` rather than a
//! raw-socket unicast, so the server needs only `CAP_NET_BIND_SERVICE` — no
//! `CAP_NET_RAW`. See [`reply_destination`] for the exact rule.
//!
//! Scope: a single LAN interface. Limited-broadcast replies leave via the
//! interface the OS routes `255.255.255.255` to; multi-interface / relayed
//! setups (pinning the egress interface with `IP_PKTINFO`) are a later addition.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::handler::{self, ServerConfig};
use crate::lease::LeasePool;
use crate::message::DhcpMessage;
use crate::options::MessageType;

/// A lease change, emitted so the host can feed device identity into the client
/// registry and persist the lease table. Best-effort: sent on a bounded channel
/// and dropped if the consumer falls behind — it never blocks or fails the DHCP
/// exchange.
#[derive(Debug, Clone)]
pub enum LeaseEvent {
    /// An address was (re)assigned via an ACK.
    Committed {
        mac: [u8; 6],
        ip: Ipv4Addr,
        hostname: Option<String>,
        /// Unix seconds the lease expires at.
        expires_at: u64,
    },
    /// A client released its address.
    Released { ip: Ipv4Addr },
}

/// A lease pool shared between the server loop and (later) the API / client
/// registry sync. The caller builds the pool and wraps it with [`shared`].
pub type SharedPool = Arc<Mutex<LeasePool>>;

/// Wrap a [`LeasePool`] for sharing, so callers don't need to depend on
/// `parking_lot` directly.
pub fn shared(pool: LeasePool) -> SharedPool {
    Arc::new(Mutex::new(pool))
}

/// The standard DHCP ports.
const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;
/// RFC 2131 recommends messages be at least 300 octets; some clients/relays drop
/// shorter ones. We pad the reply (with zero bytes after the End option) to this.
const MIN_REPLY_LEN: usize = 300;

/// Where a reply should be sent (RFC 2131 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyDest {
    /// Through a relay agent — unicast to `giaddr:67`.
    Relay(Ipv4Addr),
    /// Directly to a client that already has a working address — `ip:68`.
    Unicast(Ipv4Addr),
    /// Limited broadcast — `255.255.255.255:68`.
    Broadcast,
}

impl ReplyDest {
    fn socket_addr(self) -> SocketAddr {
        match self {
            Self::Relay(ip) => SocketAddr::V4(SocketAddrV4::new(ip, SERVER_PORT)),
            Self::Unicast(ip) => SocketAddr::V4(SocketAddrV4::new(ip, CLIENT_PORT)),
            Self::Broadcast => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT)),
        }
    }
}

/// Decide where a reply to `req` goes. `is_nak` matters: a NAK invalidates the
/// client's address, so it can't be unicast to `ciaddr`.
///
/// Unlike a raw-socket server, we never unicast to a not-yet-configured client
/// (`yiaddr` with the broadcast flag clear) — that would need `CAP_NET_RAW` to
/// bypass ARP. We broadcast instead; every DHCP client accepts that.
pub fn reply_destination(req: &DhcpMessage, is_nak: bool) -> ReplyDest {
    // A relayed request is always answered to the relay, which re-distributes it.
    if !req.giaddr.is_unspecified() {
        return ReplyDest::Relay(req.giaddr);
    }
    if is_nak {
        // The client's notion of its address is wrong — broadcast so it hears it.
        return ReplyDest::Broadcast;
    }
    // A renewing client (unicast REQUEST from a configured address) is reachable.
    if !req.ciaddr.is_unspecified() {
        return ReplyDest::Unicast(req.ciaddr);
    }
    // Otherwise (broadcast flag set, or clear-flag client we won't ARP-inject
    // for): broadcast.
    ReplyDest::Broadcast
}

/// Bind the DHCP socket: `0.0.0.0:67`, broadcast-enabled, address-reusable.
/// Separate from [`serve`] so a caller learns at once whether the port could
/// be had (taken by another DHCP server, or no privilege) and can say so.
pub fn bind() -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, SERVER_PORT));
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run the DHCP server until an unrecoverable socket error. Decode failures and
/// per-datagram send failures are logged and skipped — one bad packet (or a
/// client that vanished) never takes the server down.
pub async fn run(
    cfg: ServerConfig,
    pool: SharedPool,
    leases: Option<mpsc::Sender<LeaseEvent>>,
) -> io::Result<()> {
    serve(bind()?, cfg, pool, leases).await
}

/// Serve DHCP on a socket from [`bind`] until an unrecoverable socket error.
pub async fn serve(
    sock: UdpSocket,
    cfg: ServerConfig,
    pool: SharedPool,
    leases: Option<mpsc::Sender<LeaseEvent>>,
) -> io::Result<()> {
    tracing::info!("dhcp: listening on 0.0.0.0:{SERVER_PORT}");
    let mut buf = [0u8; 1500];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let req = match DhcpMessage::decode(&buf[..n]) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("dhcp: dropping malformed datagram from {src}: {e}");
                continue;
            }
        };
        // Compute the reply without holding the lock across the await below.
        let now = now_unix();
        let reply = {
            let mut pool = pool.lock();
            handler::handle(&cfg, &mut pool, &req, now)
        };
        // Publish lease changes (best-effort). A RELEASE produces no reply, so it
        // is handled off the request; a commit is read off the ACK.
        if let Some(tx) = &leases {
            if req.message_type() == Some(MessageType::Release) && !req.ciaddr.is_unspecified() {
                let _ = tx.try_send(LeaseEvent::Released { ip: req.ciaddr });
            }
            if let Some(r) = &reply
                && r.message_type() == Some(MessageType::Ack)
                && !r.yiaddr.is_unspecified()
            {
                let _ = tx.try_send(LeaseEvent::Committed {
                    mac: req.chaddr,
                    ip: r.yiaddr,
                    hostname: req.hostname().map(str::to_owned),
                    expires_at: now.saturating_add(cfg.lease_secs as u64),
                });
            }
        }
        let Some(reply) = reply else { continue };
        let dest =
            reply_destination(&req, reply.message_type() == Some(MessageType::Nak)).socket_addr();
        let mut bytes = reply.encode();
        if bytes.len() < MIN_REPLY_LEN {
            bytes.resize(MIN_REPLY_LEN, 0);
        }
        if let Err(e) = sock.send_to(&bytes, dest).await {
            tracing::warn!("dhcp: failed to send reply to {dest}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Op;
    use crate::options::DhcpOption;

    fn req() -> DhcpMessage {
        DhcpMessage {
            op: Op::BootRequest,
            xid: 1,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [1, 2, 3, 4, 5, 6],
            options: vec![DhcpOption::MessageType(MessageType::Request)],
        }
    }

    #[test]
    fn relayed_request_goes_to_the_relay_on_port_67() {
        let mut r = req();
        r.giaddr = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(reply_destination(&r, false), ReplyDest::Relay(r.giaddr));
        assert_eq!(
            reply_destination(&r, false).socket_addr(),
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 67))
        );
        // Even a NAK follows the relay.
        assert_eq!(reply_destination(&r, true), ReplyDest::Relay(r.giaddr));
    }

    #[test]
    fn renewing_client_is_unicast_on_port_68() {
        let mut r = req();
        r.ciaddr = Ipv4Addr::new(192, 168, 1, 50);
        assert_eq!(reply_destination(&r, false), ReplyDest::Unicast(r.ciaddr));
        assert_eq!(
            reply_destination(&r, false).socket_addr(),
            SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 68))
        );
    }

    #[test]
    fn nak_to_a_renewing_client_is_broadcast_not_unicast() {
        let mut r = req();
        r.ciaddr = Ipv4Addr::new(192, 168, 1, 50); // would be unicast on ACK…
        assert_eq!(reply_destination(&r, true), ReplyDest::Broadcast); // …but NAK broadcasts
    }

    #[test]
    fn fresh_client_is_broadcast_regardless_of_flag() {
        // Broadcast flag set → broadcast.
        let mut r = req();
        r.flags = 0x8000;
        assert_eq!(reply_destination(&r, false), ReplyDest::Broadcast);
        // Flag clear, no ciaddr → still broadcast (we don't raw-socket unicast).
        let r2 = req();
        assert_eq!(reply_destination(&r2, false), ReplyDest::Broadcast);
        assert_eq!(
            reply_destination(&r2, false).socket_addr(),
            SocketAddr::from((Ipv4Addr::BROADCAST, 68))
        );
    }
}
