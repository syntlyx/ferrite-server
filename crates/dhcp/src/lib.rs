//! DHCPv4 server core + (later) an IPv6 RA/RDNSS announcer.
//!
//! This first layer is pure logic — the wire codec ([`message`], [`options`])
//! and the lease allocator ([`lease`]) — with no sockets, so it is fully unit
//! tested. The UDP server loop, the raw-socket path for replying to clients
//! that have no address yet, the IPv6 RA/RDNSS sender, and the wiring into the
//! client registry and config all come in later layers.
//!
//! Scope: IPv4 leases via DHCP; IPv6 addressing is expected to use SLAAC driven
//! by Router Advertisements (Android has no DHCPv6), so there is deliberately no
//! DHCPv6 here.

pub mod handler;
pub mod lease;
pub mod message;
pub mod options;
pub mod ra;
pub mod server;

pub use handler::{ServerConfig, handle};
pub use lease::LeasePool;
pub use message::{DhcpMessage, Op};
pub use options::{DhcpOption, MessageType};
