//! The DHCP decision logic: turn a parsed request + the lease pool into the
//! reply to send (if any). Pure and synchronous — the socket loop feeds it
//! parsed messages and ships whatever it returns. No I/O, so it is fully tested.
//!
//! Replies are built to be sent by broadcast (to 255.255.255.255:68) whenever
//! the client has no usable address yet, which is how the server avoids needing
//! raw packet sockets (`CAP_NET_RAW`) — see the crate/deployment notes. The
//! caller reads [`DhcpMessage::broadcast`] / `yiaddr` to pick the destination.

use std::net::Ipv4Addr;

use crate::lease::LeasePool;
use crate::message::{DhcpMessage, Op};
use crate::options::{DhcpOption, MessageType};

/// Static per-subnet settings the server hands out. The dynamic pool and
/// reservations live in [`LeasePool`]; this is everything else a client needs.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// ferrite's own address on this subnet — used as the server identifier
    /// (option 54) and `siaddr`.
    pub server_ip: Ipv4Addr,
    /// Option 1.
    pub subnet_mask: Ipv4Addr,
    /// Option 3. Often ferrite itself (gateway mode) or the real router.
    pub gateway: Option<Ipv4Addr>,
    /// Option 6 — resolvers offered to clients. Point this at ferrite so DNS
    /// filtering can't be sidestepped.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Option 15 — DNS search domain, if any.
    pub domain: Option<String>,
    /// Option 51 — lease duration, seconds.
    pub lease_secs: u32,
}

impl ServerConfig {
    /// The address-configuration options every OFFER/ACK carries, plus the
    /// renewal (T1 = 50%) and rebind (T2 = 87.5%) timers derived from the lease.
    fn config_options(&self) -> Vec<DhcpOption> {
        let mut opts = vec![
            DhcpOption::LeaseTime(self.lease_secs),
            DhcpOption::RenewalTime(self.lease_secs / 2),
            DhcpOption::RebindingTime(self.lease_secs / 8 * 7),
            DhcpOption::SubnetMask(self.subnet_mask),
        ];
        if let Some(gw) = self.gateway {
            opts.push(DhcpOption::Router(vec![gw]));
        }
        if !self.dns_servers.is_empty() {
            opts.push(DhcpOption::DnsServers(self.dns_servers.clone()));
        }
        if let Some(domain) = &self.domain {
            opts.push(DhcpOption::DomainName(domain.clone()));
        }
        opts
    }
}

/// How long an address a client declined stays out of offers.
pub const DECLINE_HOLD_SECS: u64 = 30 * 60;

/// Decide the reply to `req`, mutating `pool` on commit/release. `None` means
/// "stay silent" (not for us, pool exhausted, or a message that needs no reply).
pub fn handle(
    cfg: &ServerConfig,
    pool: &mut LeasePool,
    req: &DhcpMessage,
    now: u64,
) -> Option<DhcpMessage> {
    // Only client→server BOOTREQUESTs are ours to answer.
    if req.op != Op::BootRequest {
        return None;
    }
    match req.message_type()? {
        MessageType::Discover => handle_discover(cfg, pool, req, now),
        MessageType::Request => handle_request(cfg, pool, req, now),
        MessageType::Release => {
            pool.release(req.chaddr);
            None
        }
        MessageType::Decline => {
            // The client found the address in use (its ARP probe got an
            // answer). Drop the lease and keep the address out of offers for a
            // while, or the next DISCOVER would get the same one back.
            if let Some(ip) = req.requested_ip() {
                pool.hold(ip, now.saturating_add(DECLINE_HOLD_SECS));
            }
            pool.release(req.chaddr);
            None
        }
        MessageType::Inform => Some(handle_inform(cfg, req)),
        // Server→client types (or ones we don't originate a reply for).
        MessageType::Offer | MessageType::Ack | MessageType::Nak => None,
    }
}

fn handle_discover(
    cfg: &ServerConfig,
    pool: &LeasePool,
    req: &DhcpMessage,
    now: u64,
) -> Option<DhcpMessage> {
    // OFFER is tentative — do not commit until the client REQUESTs. `offer` is
    // sticky/deterministic, so the following REQUEST lands on the same address.
    let ip = pool.offer(req.chaddr, req.requested_ip(), now)?;
    let mut opts = vec![
        DhcpOption::MessageType(MessageType::Offer),
        DhcpOption::ServerIdentifier(cfg.server_ip),
    ];
    opts.extend(cfg.config_options());
    Some(reply(cfg, req, ip, opts))
}

fn handle_request(
    cfg: &ServerConfig,
    pool: &mut LeasePool,
    req: &DhcpMessage,
    now: u64,
) -> Option<DhcpMessage> {
    // SELECTING: the client echoes the server identifier of the offer it chose.
    // If that isn't us, the client picked another server — stay silent.
    if let Some(sid) = req.server_identifier()
        && sid != cfg.server_ip
    {
        return None;
    }

    // The address the client wants: option 50 (SELECTING / INIT-REBOOT) or its
    // current ciaddr (RENEWING / REBINDING).
    let wanted = req.requested_ip().unwrap_or(req.ciaddr);
    if wanted.is_unspecified() {
        return Some(nak(cfg, req));
    }
    let hostname = req.hostname().map(str::to_owned);
    match pool.commit(req.chaddr, wanted, hostname, now, cfg.lease_secs as u64) {
        Ok(lease) => {
            let mut opts = vec![
                DhcpOption::MessageType(MessageType::Ack),
                DhcpOption::ServerIdentifier(cfg.server_ip),
            ];
            opts.extend(cfg.config_options());
            Some(reply(cfg, req, lease.ip, opts))
        }
        // Address unavailable/out of range → tell the client to start over.
        Err(_) => Some(nak(cfg, req)),
    }
}

fn handle_inform(cfg: &ServerConfig, req: &DhcpMessage) -> DhcpMessage {
    // Client already has an address (ciaddr); it only wants config options. No
    // yiaddr, no lease time.
    let mut opts = vec![
        DhcpOption::MessageType(MessageType::Ack),
        DhcpOption::ServerIdentifier(cfg.server_ip),
        DhcpOption::SubnetMask(cfg.subnet_mask),
    ];
    if let Some(gw) = cfg.gateway {
        opts.push(DhcpOption::Router(vec![gw]));
    }
    if !cfg.dns_servers.is_empty() {
        opts.push(DhcpOption::DnsServers(cfg.dns_servers.clone()));
    }
    if let Some(domain) = &cfg.domain {
        opts.push(DhcpOption::DomainName(domain.clone()));
    }
    reply(cfg, req, Ipv4Addr::UNSPECIFIED, opts)
}

/// Build a BOOTREPLY: echo xid/flags/giaddr/chaddr, set yiaddr + siaddr.
fn reply(
    cfg: &ServerConfig,
    req: &DhcpMessage,
    yiaddr: Ipv4Addr,
    options: Vec<DhcpOption>,
) -> DhcpMessage {
    DhcpMessage {
        op: Op::BootReply,
        xid: req.xid,
        secs: 0,
        flags: req.flags,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr,
        siaddr: cfg.server_ip,
        giaddr: req.giaddr,
        chaddr: req.chaddr,
        options,
    }
}

fn nak(cfg: &ServerConfig, req: &DhcpMessage) -> DhcpMessage {
    reply(
        cfg,
        req,
        Ipv4Addr::UNSPECIFIED,
        vec![
            DhcpOption::MessageType(MessageType::Nak),
            DhcpOption::ServerIdentifier(cfg.server_ip),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

    fn cfg() -> ServerConfig {
        ServerConfig {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
            domain: Some("lan".to_string()),
            lease_secs: 3600,
        }
    }

    fn pool() -> LeasePool {
        LeasePool::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 110),
        )
    }

    fn request(mac: [u8; 6], mtype: MessageType, opts: Vec<DhcpOption>) -> DhcpMessage {
        let mut options = vec![DhcpOption::MessageType(mtype)];
        options.extend(opts);
        DhcpMessage {
            op: Op::BootRequest,
            xid: 0x42,
            secs: 0,
            flags: 0x8000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac,
            options,
        }
    }

    #[test]
    fn discover_yields_an_offer_with_config() {
        let mut p = pool();
        let reply = handle(
            &cfg(),
            &mut p,
            &request(MAC, MessageType::Discover, vec![]),
            100,
        )
        .unwrap();

        assert_eq!(reply.op, Op::BootReply);
        assert_eq!(reply.message_type(), Some(MessageType::Offer));
        assert_eq!(reply.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(reply.xid, 0x42);
        // Carries the address config.
        assert!(
            reply
                .options
                .contains(&DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert!(
            reply
                .options
                .contains(&DhcpOption::DnsServers(vec![Ipv4Addr::new(192, 168, 1, 1)]))
        );
        assert!(reply.options.contains(&DhcpOption::LeaseTime(3600)));
        // Discover must NOT commit a lease yet.
        assert!(p.lookup_by_mac(MAC, 100).is_none());
    }

    #[test]
    fn discover_offers_nothing_when_pool_exhausted() {
        // A pool of one address, already committed to someone else.
        let mut p = LeasePool::new(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 5));
        p.commit(
            [9, 9, 9, 9, 9, 9],
            Ipv4Addr::new(10, 0, 0, 5),
            None,
            100,
            3600,
        )
        .unwrap();
        assert!(
            handle(
                &cfg(),
                &mut p,
                &request(MAC, MessageType::Discover, vec![]),
                100
            )
            .is_none()
        );
    }

    #[test]
    fn request_for_offered_address_acks_and_commits() {
        let mut p = pool();
        let req = request(
            MAC,
            MessageType::Request,
            vec![
                DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)),
                DhcpOption::RequestedIp(Ipv4Addr::new(192, 168, 1, 100)),
            ],
        );
        let reply = handle(&cfg(), &mut p, &req, 100).unwrap();

        assert_eq!(reply.message_type(), Some(MessageType::Ack));
        assert_eq!(reply.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        let lease = p.lookup_by_mac(MAC, 100).expect("committed");
        assert_eq!(lease.ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(lease.expires_at, 100 + 3600);
    }

    #[test]
    fn request_for_taken_address_naks() {
        let mut p = pool();
        // .100 is taken by another client.
        p.commit(
            [7, 7, 7, 7, 7, 7],
            Ipv4Addr::new(192, 168, 1, 100),
            None,
            100,
            3600,
        )
        .unwrap();
        let req = request(
            MAC,
            MessageType::Request,
            vec![DhcpOption::RequestedIp(Ipv4Addr::new(192, 168, 1, 100))],
        );
        let reply = handle(&cfg(), &mut p, &req, 100).unwrap();
        assert_eq!(reply.message_type(), Some(MessageType::Nak));
        assert_eq!(reply.yiaddr, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn request_for_another_server_is_ignored() {
        let mut p = pool();
        let req = request(
            MAC,
            MessageType::Request,
            vec![
                DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 9, 9, 9)), // not us
                DhcpOption::RequestedIp(Ipv4Addr::new(192, 168, 1, 100)),
            ],
        );
        assert!(handle(&cfg(), &mut p, &req, 100).is_none());
        // And we must not have committed anything.
        assert!(p.lookup_by_mac(MAC, 100).is_none());
    }

    #[test]
    fn renewing_client_with_ciaddr_is_acked() {
        let mut p = pool();
        let mut req = request(MAC, MessageType::Request, vec![]);
        req.ciaddr = Ipv4Addr::new(192, 168, 1, 105);
        req.flags = 0; // unicast renew
        let reply = handle(&cfg(), &mut p, &req, 100).unwrap();
        assert_eq!(reply.message_type(), Some(MessageType::Ack));
        assert_eq!(reply.yiaddr, Ipv4Addr::new(192, 168, 1, 105));
    }

    #[test]
    fn release_frees_the_lease_without_reply() {
        let mut p = pool();
        p.commit(MAC, Ipv4Addr::new(192, 168, 1, 100), None, 100, 3600)
            .unwrap();
        let reply = handle(
            &cfg(),
            &mut p,
            &request(MAC, MessageType::Release, vec![]),
            100,
        );
        assert!(reply.is_none());
        assert!(p.lookup_by_mac(MAC, 100).is_none());
    }

    #[test]
    fn a_declined_address_goes_to_someone_else_next() {
        let mut p = pool();
        let first = handle(
            &cfg(),
            &mut p,
            &request(MAC, MessageType::Discover, vec![]),
            100,
        )
        .unwrap()
        .yiaddr;
        let decline = request(
            MAC,
            MessageType::Decline,
            vec![DhcpOption::RequestedIp(first)],
        );
        assert!(handle(&cfg(), &mut p, &decline, 100).is_none());
        let next = handle(
            &cfg(),
            &mut p,
            &request(MAC, MessageType::Discover, vec![]),
            101,
        )
        .unwrap()
        .yiaddr;
        assert_ne!(next, first);
    }

    #[test]
    fn inform_acks_config_without_a_lease() {
        let mut p = pool();
        let mut req = request(MAC, MessageType::Inform, vec![]);
        req.ciaddr = Ipv4Addr::new(192, 168, 1, 50);
        let reply = handle(&cfg(), &mut p, &req, 100).unwrap();
        assert_eq!(reply.message_type(), Some(MessageType::Ack));
        assert_eq!(
            reply.yiaddr,
            Ipv4Addr::UNSPECIFIED,
            "INFORM assigns no address"
        );
        assert!(
            reply
                .options
                .contains(&DhcpOption::DnsServers(vec![Ipv4Addr::new(192, 168, 1, 1)]))
        );
        assert!(
            !reply
                .options
                .iter()
                .any(|o| matches!(o, DhcpOption::LeaseTime(_))),
            "INFORM carries no lease time"
        );
        assert!(p.lookup_by_mac(MAC, 100).is_none());
    }

    #[test]
    fn reply_echoes_broadcast_flag_and_hostname_is_recorded() {
        let mut p = pool();
        let req = request(
            MAC,
            MessageType::Request,
            vec![
                DhcpOption::RequestedIp(Ipv4Addr::new(192, 168, 1, 100)),
                DhcpOption::Hostname("phone".to_string()),
            ],
        );
        let reply = handle(&cfg(), &mut p, &req, 100).unwrap();
        assert!(reply.broadcast(), "broadcast flag echoed");
        assert_eq!(
            p.lookup_by_mac(MAC, 100).unwrap().hostname.as_deref(),
            Some("phone")
        );
    }

    #[test]
    fn non_bootrequest_is_ignored() {
        let mut p = pool();
        let mut req = request(MAC, MessageType::Discover, vec![]);
        req.op = Op::BootReply;
        assert!(handle(&cfg(), &mut p, &req, 100).is_none());
    }
}
