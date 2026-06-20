//! Direct egress: connect straight to the real destination.
//!
//! Resolution goes through ferrite's own upstream pool, **not** the OS
//! resolver: on the ferrite host the system resolver is usually ferrite itself,
//! so `getaddrinfo("routed.example")` would re-enter the DNS pipeline, match the
//! proxy rule, and get ferrite's own IP back — an infinite loop. Resolving via
//! the upstream pool sidesteps that and avoids leaking the lookup.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{FeriteError, Result};
use crate::upstream::ZoneRouter;

use super::{enable_keepalive, EgressConn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct DirectEgress {
    id: String,
    upstream: Arc<ZoneRouter>,
}

impl DirectEgress {
    pub fn new(id: String, upstream: Arc<ZoneRouter>) -> Self {
        Self { id, upstream }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<EgressConn> {
        direct_connect(&self.upstream, host, port).await
    }
}

/// Resolve `host` via the upstream pool (or parse it as a literal IP) and open a
/// TCP connection to `host:port`. Shared by [`DirectEgress`] and the
/// "connected to us but no rule matches" forward-direct fallback.
pub async fn direct_connect(upstream: &ZoneRouter, host: &str, port: u16) -> Result<EgressConn> {
    let ip = match IpAddr::from_str(host) {
        Ok(ip) => ip,
        Err(_) => resolve_via_upstream(upstream, host).await?,
    };
    let addr = SocketAddr::new(ip, port);
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| FeriteError::Dns(format!("connect timeout to {host}:{port}")))?
        .map_err(|e| FeriteError::Dns(format!("connect {host}:{port}: {e}")))?;
    enable_keepalive(&stream);
    Ok(stream)
}

async fn resolve_via_upstream(upstream: &ZoneRouter, host: &str) -> Result<IpAddr> {
    if let Some(ip) = query_addr(upstream, host, RecordType::A).await {
        return Ok(ip);
    }
    if let Some(ip) = query_addr(upstream, host, RecordType::AAAA).await {
        return Ok(ip);
    }
    Err(FeriteError::Dns(format!("could not resolve {host}")))
}

async fn query_addr(upstream: &ZoneRouter, host: &str, rtype: RecordType) -> Option<IpAddr> {
    let name = Name::from_str(&format!("{}.", host.trim_end_matches('.'))).ok()?;
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, rtype));
    let raw = msg.to_bytes().ok()?;
    let (resp, _label) = upstream.resolve_raw(raw).await.ok()?;
    let parsed = Message::from_bytes(&resp).ok()?;
    parsed.answers.iter().find_map(|rr| match &rr.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    })
}
