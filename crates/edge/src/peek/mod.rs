//! Reading the start of a connection without taking it over: the name a TLS
//! connection asks for ([`sni`]), and the client a reverse proxy says it
//! passes on ([`proxy_protocol`]). Shared by Tunnels' listener and the relay,
//! which both route connections they never decrypt.

pub mod proxy_protocol;
pub mod sni;
