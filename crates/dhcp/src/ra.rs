//! IPv6 Router Advertisement builder (RFC 4861) with the RDNSS (RFC 8106) and
//! Prefix Information options.
//!
//! This is how ferrite announces itself as the IPv6 DNS resolver: IPv6 clients
//! don't take a DNS server from DHCPv6 (Android refuses DHCPv6 entirely) — they
//! read it from the **RDNSS** option in a Router Advertisement. Two shapes:
//!
//! - **Sidecar** (ferrite next to the real router): `router_lifetime = 0` so
//!   hosts never pick ferrite as their default gateway, and no Prefix
//!   Information — the real router keeps owning SLAAC addressing; ferrite only
//!   injects RDNSS.
//! - **Gateway** (ferrite is the router): `router_lifetime > 0` plus a Prefix
//!   Information option with the Autonomous flag, so clients form addresses via
//!   SLAAC off ferrite's prefix.
//!
//! Only the RA body is built here; the ICMPv6 checksum is left zero because the
//! kernel fills it in for an `IPPROTO_ICMPV6` raw socket (RFC 3542). Pure and
//! fully unit-tested; the raw-socket sender lives elsewhere.

use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::time::Instant;

const ND_ROUTER_SOLICIT: u8 = 133;
const ND_ROUTER_ADVERT: u8 = 134;

/// Linux `ICMPV6_FILTER` setsockopt name (from `<linux/icmpv6.h>`). The `libc`
/// crate doesn't export it, so we hardcode its stable ABI value. The option's
/// argument is a `struct icmp6_filter`, whose layout is exactly `[u32; 8]`.
const ICMPV6_FILTER: libc::c_int = 1;

/// Minimum spacing between Router Advertisements emitted in response to
/// solicitations (RFC 4861 §6.2.6, `MIN_DELAY_BETWEEN_RAS`). Stops a burst of
/// solicitations — or a spoofed flood — from making us hammer the link.
const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);

/// All-nodes link-local multicast (ff02::1) — the destination for unsolicited RAs.
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// Neighbor Discovery messages MUST carry hop limit 255; receivers reject any
/// RA that arrives with a lower limit (RFC 4861 §6.1.2), which is what stops an
/// off-link attacker from spoofing them.
const ND_HOP_LIMIT: u32 = 255;

const OPT_PREFIX_INFO: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_RDNSS: u8 = 25;

/// A prefix to advertise for SLAAC (gateway mode).
#[derive(Debug, Clone)]
pub struct PrefixInfo {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    /// Seconds the prefix stays valid / preferred.
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
}

/// Everything needed to build one Router Advertisement.
#[derive(Debug, Clone)]
pub struct RaConfig {
    /// Default hop limit advertised to hosts (0 = unspecified).
    pub cur_hop_limit: u8,
    /// Seconds hosts should treat the sender as a default router. `0` in sidecar
    /// mode (RDNSS-only) so ferrite is never chosen as a gateway.
    pub router_lifetime: u16,
    /// Link MTU to advertise, if any.
    pub mtu: Option<u32>,
    /// Prefixes for SLAAC (gateway mode). Empty in sidecar mode.
    pub prefixes: Vec<PrefixInfo>,
    /// Recursive DNS servers to announce (ferrite's own IPv6 address(es)).
    pub rdnss: Vec<Ipv6Addr>,
    /// How long (seconds) hosts should use the advertised RDNSS. RFC 8106
    /// recommends at most ~2× the max RA interval.
    pub rdnss_lifetime: u32,
}

impl RaConfig {
    /// Serialize the ICMPv6 Router Advertisement body (checksum left zero).
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        // ── ICMPv6 + RA header (RFC 4861 §4.2) ────────────────────────────
        buf.push(ND_ROUTER_ADVERT); // Type
        buf.push(0); // Code
        buf.extend_from_slice(&[0, 0]); // Checksum (kernel fills for IPPROTO_ICMPV6)
        buf.push(self.cur_hop_limit); // Cur Hop Limit
        buf.push(0); // Flags (M/O both 0 — SLAAC, no DHCPv6)
        buf.extend_from_slice(&self.router_lifetime.to_be_bytes()); // Router Lifetime
        buf.extend_from_slice(&0u32.to_be_bytes()); // Reachable Time (unspecified)
        buf.extend_from_slice(&0u32.to_be_bytes()); // Retrans Timer (unspecified)

        // ── Options ───────────────────────────────────────────────────────
        if let Some(mtu) = self.mtu {
            // MTU option (RFC 4861 §4.6.4): type, len=1 (8 bytes), reserved, mtu.
            buf.push(OPT_MTU);
            buf.push(1);
            buf.extend_from_slice(&[0, 0]); // Reserved
            buf.extend_from_slice(&mtu.to_be_bytes());
        }

        for p in &self.prefixes {
            // Prefix Information (RFC 4861 §4.6.2): 32 bytes, len=4.
            buf.push(OPT_PREFIX_INFO);
            buf.push(4);
            buf.push(p.prefix_len);
            buf.push(0xC0); // Flags: L (on-link) | A (autonomous)
            buf.extend_from_slice(&p.valid_lifetime.to_be_bytes());
            buf.extend_from_slice(&p.preferred_lifetime.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes()); // Reserved2
            buf.extend_from_slice(&p.prefix.octets());
        }

        if !self.rdnss.is_empty() {
            // RDNSS (RFC 8106 §5.1): type, len=(1 + 2*N) 8-octet units, reserved,
            // lifetime, then N × 16-byte addresses.
            buf.push(OPT_RDNSS);
            buf.push(1 + 2 * self.rdnss.len() as u8);
            buf.extend_from_slice(&[0, 0]); // Reserved
            buf.extend_from_slice(&self.rdnss_lifetime.to_be_bytes());
            for addr in &self.rdnss {
                buf.extend_from_slice(&addr.octets());
            }
        }

        buf
    }
}

/// Advertise on `ifindex`: multicast an unsolicited RA every `interval`, and
/// answer Router Solicitations promptly so a client that just joined the link
/// doesn't wait up to a full interval for DNS.
///
/// Needs a raw ICMPv6 socket (`CAP_NET_RAW`). The socket is driven through
/// tokio's [`AsyncFd`] so the same fd serves both the periodic sender and the
/// solicitation listener without burning a blocking thread. Solicited replies
/// go out as multicast (RFC 4861 §6.2.6 permits it — it refreshes every host
/// and avoids parsing the solicitor's address) and are rate-limited to one per
/// [`MIN_DELAY_BETWEEN_RAS`]. Runs until an unrecoverable socket error; a single
/// failed send is logged and retried.
pub async fn run(config: RaConfig, ifindex: u32, interval: Duration) -> io::Result<()> {
    serve(open(ifindex)?, config, ifindex, interval).await
}

/// The kernel's index for interface `name`, or `None` when there is no such
/// interface.
pub fn interface_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string that outlives the call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}

/// Open the raw ICMPv6 socket the announcer sends on, on interface `ifindex`.
/// Separate from [`serve`] so a missing `CAP_NET_RAW` shows up at once.
pub fn open(ifindex: u32) -> io::Result<AsyncFd<Socket>> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    sock.set_multicast_hops_v6(ND_HOP_LIMIT)?;
    sock.set_unicast_hops_v6(ND_HOP_LIMIT)?;
    sock.set_multicast_if_v6(ifindex)?;
    // Ask the kernel to deliver only Router Solicitations; a raw ICMPv6 socket
    // would otherwise wake us on every ping and neighbor-discovery packet.
    // Best-effort — the recv loop re-checks the type byte regardless.
    filter_router_solicitations(&sock);
    sock.set_nonblocking(true)?;

    // SAFETY: a `socket2::Socket` owns its descriptor for its whole life and
    // always reports the same one; the `AsyncFd` takes ownership of it here.
    Ok(unsafe { AsyncFd::register(sock) }?)
}

/// Announce on a socket from [`open`]: every `interval`, and in answer to a
/// Router Solicitation. Runs until the task is dropped.
pub async fn serve(
    afd: AsyncFd<Socket>,
    config: RaConfig,
    ifindex: u32,
    interval: Duration,
) -> io::Result<()> {
    // Link-local multicast needs the scope id (= ifindex) in the sockaddr.
    let all_nodes: SockAddr = SocketAddrV6::new(ALL_NODES, 0, 0, ifindex).into();
    // The RA body is fixed for the lifetime of this task — build it once.
    let ra = config.build();

    tracing::info!(
        "ra: advertising on ifindex {ifindex} every {interval:?} (answers solicitations)"
    );
    let mut ticker = tokio::time::interval(interval);
    let mut recv_buf = [MaybeUninit::<u8>::uninit(); 1280];
    let mut last_sent: Option<Instant> = None;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                send_ra(&afd, &ra, &all_nodes).await;
                last_sent = Some(Instant::now());
            }
            guard = afd.readable() => {
                let mut guard = match guard {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::warn!("ra: readable poll failed: {e}");
                        continue;
                    }
                };
                // Drain everything queued so readiness doesn't relatch, noting
                // whether any of it was a solicitation.
                let mut solicited = false;
                loop {
                    match guard.try_io(|inner| inner.get_ref().recv(&mut recv_buf)) {
                        // SAFETY: `recv` initialised the first `n` bytes of the buffer.
                        Ok(Ok(n)) if n > 0 && unsafe { recv_buf[0].assume_init() } == ND_ROUTER_SOLICIT => {
                            solicited = true;
                        }
                        Ok(Ok(_)) => {} // some other ICMPv6 type slipped through the filter
                        Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Ok(Err(e)) => {
                            tracing::warn!("ra: recv failed: {e}");
                            break;
                        }
                        Err(_would_block) => break, // readiness was spurious; try again later
                    }
                }
                drop(guard);
                let due = last_sent.is_none_or(|t| t.elapsed() >= MIN_DELAY_BETWEEN_RAS);
                if solicited && due {
                    send_ra(&afd, &ra, &all_nodes).await;
                    last_sent = Some(Instant::now());
                }
            }
        }
    }
}

/// Wait for writability and send one prebuilt RA to `dest`. A transient error is
/// logged, not propagated — the next tick or solicitation retries.
async fn send_ra(afd: &AsyncFd<Socket>, ra: &[u8], dest: &SockAddr) {
    loop {
        let mut guard = match afd.writable().await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("ra: writable poll failed: {e}");
                return;
            }
        };
        match guard.try_io(|inner| inner.get_ref().send_to(ra, dest)) {
            Ok(Ok(_)) => return,
            Ok(Err(e)) => {
                tracing::warn!("ra: send failed: {e}");
                return;
            }
            Err(_would_block) => continue, // not actually writable; wait again
        }
    }
}

/// Build the `ICMP6_FILTER` bitmap that passes only `pass_type` (RFC 3542): a
/// 256-bit map of 8 × u32 where a **set** bit *blocks* the type, so we start all
/// blocked and clear the one bit to let through.
fn icmp6_filter_pass_only(pass_type: u8) -> [u32; 8] {
    let mut filt = [0xffff_ffffu32; 8];
    let t = pass_type as usize;
    filt[t >> 5] &= !(1u32 << (t & 31));
    filt
}

/// Install an `ICMP6_FILTER` on the raw socket so the kernel delivers only
/// Router Solicitations. Best-effort: on failure we log at debug and rely on the
/// recv loop's type-byte check, so the feature still works — just noisier.
fn filter_router_solicitations(sock: &Socket) {
    let filt = icmp6_filter_pass_only(ND_ROUTER_SOLICIT);
    // SAFETY: `filt` is a correctly-sized `struct icmp6_filter` ([u32; 8]) for
    // IPPROTO_ICMPV6 / ICMPV6_FILTER on the raw socket's fd; the kernel copies
    // the value in and never retains the pointer.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_ICMPV6,
            ICMPV6_FILTER,
            filt.as_ptr().cast::<libc::c_void>(),
            std::mem::size_of_val(&filt) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::debug!(
            "ra: ICMP6_FILTER not applied ({}); filtering solicitations in userspace",
            io::Error::last_os_error()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sidecar(rdnss: Vec<Ipv6Addr>) -> RaConfig {
        RaConfig {
            cur_hop_limit: 64,
            router_lifetime: 0, // sidecar: not a default router
            mtu: None,
            prefixes: Vec::new(),
            rdnss,
            rdnss_lifetime: 1800,
        }
    }

    #[test]
    fn header_is_a_router_advertisement_with_zero_checksum() {
        let ra = sidecar(vec![Ipv6Addr::LOCALHOST]).build();
        assert_eq!(ra[0], ND_ROUTER_ADVERT);
        assert_eq!(ra[1], 0, "code");
        assert_eq!(&ra[2..4], &[0, 0], "checksum left for the kernel");
        assert_eq!(ra[4], 64, "cur hop limit");
        assert_eq!(ra[5], 0, "flags: no M/O");
        assert_eq!(&ra[6..8], &[0, 0], "router lifetime 0 in sidecar mode");
    }

    #[test]
    fn rdnss_option_carries_the_servers_and_lifetime() {
        let a = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let ra = sidecar(vec![a, b]).build();

        // Find the RDNSS option (after the 16-byte header, no other options here).
        let opt = &ra[16..];
        assert_eq!(opt[0], OPT_RDNSS);
        assert_eq!(opt[1], 1 + 2 * 2, "length in 8-octet units for 2 servers");
        assert_eq!(&opt[2..4], &[0, 0], "reserved");
        assert_eq!(u32::from_be_bytes(opt[4..8].try_into().unwrap()), 1800);
        assert_eq!(&opt[8..24], &a.octets());
        assert_eq!(&opt[24..40], &b.octets());
        // Whole option is a multiple of 8 octets.
        assert_eq!(opt.len() % 8, 0);
        assert_eq!(opt.len(), 8 + 16 * 2);
    }

    #[test]
    fn no_rdnss_option_when_no_servers() {
        let ra = sidecar(vec![]).build();
        assert_eq!(ra.len(), 16, "just the RA header, no options");
    }

    #[test]
    fn gateway_mode_adds_prefix_information_with_slaac_flags() {
        let mut cfg = sidecar(vec![Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)]);
        cfg.router_lifetime = 1800; // gateway: is a default router
        cfg.prefixes = vec![PrefixInfo {
            prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            prefix_len: 64,
            valid_lifetime: 86_400,
            preferred_lifetime: 14_400,
        }];
        let ra = cfg.build();

        assert_eq!(&ra[6..8], &1800u16.to_be_bytes(), "router lifetime set");
        // Prefix Info option immediately follows the 16-byte header.
        let pio = &ra[16..48];
        assert_eq!(pio[0], OPT_PREFIX_INFO);
        assert_eq!(pio[1], 4, "32-byte option");
        assert_eq!(pio[2], 64, "prefix length");
        assert_eq!(pio[3], 0xC0, "on-link + autonomous flags");
        assert_eq!(u32::from_be_bytes(pio[4..8].try_into().unwrap()), 86_400);
        assert_eq!(u32::from_be_bytes(pio[8..12].try_into().unwrap()), 14_400);
        assert_eq!(
            &pio[16..32],
            &Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0).octets()
        );
        // RDNSS still present after the PIO.
        assert_eq!(ra[48], OPT_RDNSS);
    }

    #[test]
    fn icmp6_filter_passes_only_router_solicitations() {
        let filt = icmp6_filter_pass_only(ND_ROUTER_SOLICIT);
        // A cleared bit means "pass" (RFC 3542 ICMP6_FILTER_WILLPASS).
        let will_pass = |ty: u8| {
            let t = ty as usize;
            filt[t >> 5] & (1u32 << (t & 31)) == 0
        };
        assert!(will_pass(ND_ROUTER_SOLICIT), "RS (133) must pass");
        assert!(!will_pass(128), "echo request stays blocked");
        assert!(
            !will_pass(ND_ROUTER_ADVERT),
            "our own RAs stay blocked on recv"
        );
        assert!(!will_pass(135), "neighbor solicitation stays blocked");
        // Exactly one of all 256 types is let through.
        let passing = (0u8..=255).filter(|&ty| will_pass(ty)).count();
        assert_eq!(passing, 1);
    }

    #[test]
    fn mtu_option_is_emitted_when_set() {
        let mut cfg = sidecar(vec![]);
        cfg.mtu = Some(1500);
        let ra = cfg.build();
        let opt = &ra[16..24];
        assert_eq!(opt[0], OPT_MTU);
        assert_eq!(opt[1], 1);
        assert_eq!(u32::from_be_bytes(opt[4..8].try_into().unwrap()), 1500);
    }
}
