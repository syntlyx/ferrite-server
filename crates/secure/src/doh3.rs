//! DNS over HTTPS over HTTP/3: QUIC, on the UDP side of the DNS over HTTPS
//! port. A device that has asked over HTTP/1.1 or HTTP/2 learns of it from
//! the `Alt-Svc` header and moves over: one UDP flow where a lost packet
//! holds up only its own query, and a reconnect that costs less — what a
//! phone on a poor mobile network notices. The requests are the ones of
//! [`crate::doh`]. QUIC doesn't pass through a reverse proxy: away from home,
//! the router sends the UDP port straight to this box.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::StatusCode;
use tokio_rustls::rustls;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::doh::{self, Query, Reply};
use crate::{Serving, client_id_from_sni, is_ours};

/// A connection with nothing to say this long is closed; the device opens
/// another when it next asks.
const IDLE: Duration = Duration::from_secs(30);
/// The handshake has this long.
const HANDSHAKE: Duration = Duration::from_secs(10);

type Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// The certificate, but only for our own name: a device sent to this
/// address for another site (a routed name, away from home) is turned down
/// in the handshake instead of shown a certificate that isn't that site's.
#[derive(Debug)]
struct OnlyOurs {
    certs: Arc<dyn ResolvesServerCert>,
    hostname: String,
}

impl ResolvesServerCert for OnlyOurs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello
            .server_name()
            .is_some_and(|sni| !is_ours(sni, &self.hostname))
        {
            return None;
        }
        self.certs.resolve(hello)
    }
}

/// QUIC with TLS 1.3, HTTP/3 only, for `hostname`.
pub(crate) fn server_config(
    certs: Arc<dyn ResolvesServerCert>,
    hostname: &str,
) -> Result<quinn::ServerConfig, String> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| format!("TLS setup failed: {e}"))?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(OnlyOurs {
        certs,
        hostname: hostname.to_string(),
    }));
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| format!("QUIC setup failed: {e}"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(IDLE.try_into().ok());
    transport.max_concurrent_bidi_streams(64u32.into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// UDP `port` on every address, both families where the box has IPv6.
pub(crate) fn bind(port: u16, cfg: quinn::ServerConfig) -> std::io::Result<quinn::Endpoint> {
    match quinn::Endpoint::server(cfg.clone(), SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))) {
        Err(e) if e.kind() != std::io::ErrorKind::AddrInUse => {
            quinn::Endpoint::server(cfg, SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        }
        other => other,
    }
}

pub(crate) async fn accept_loop(endpoint: quinn::Endpoint, serving: Arc<Serving>) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(slot) = Arc::clone(&serving.connections).try_acquire_owned() else {
            incoming.refuse(); // full
            continue;
        };
        let serving = Arc::clone(&serving);
        tokio::spawn(async move {
            connection(incoming, &serving).await;
            drop(slot);
        });
    }
}

async fn connection(incoming: quinn::Incoming, serving: &Serving) {
    let conn = match tokio::time::timeout(HANDSHAKE, incoming).await {
        Ok(Ok(conn)) => conn,
        _ => return,
    };
    let peer = conn.remote_address();
    let peer = SocketAddr::new(ferrite_core::net::unmap_v4(peer.ip()), peer.port());
    let sni_id = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.server_name)
        .and_then(|sni| client_id_from_sni(&sni, &serving.hostname));
    let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
    else {
        return;
    };
    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let (ctx, gate, sni_id) = (
                    Arc::clone(&serving.ctx),
                    Arc::clone(&serving.gate),
                    sni_id.clone(),
                );
                tokio::spawn(async move {
                    let Ok((req, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    let reply = request(&req, &mut stream, peer, sni_id, ctx, &gate).await;
                    send(&mut stream, reply).await;
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("doh3: connection from {peer} ended: {e}");
                break;
            }
        }
    }
}

async fn request(
    req: &http::Request<()>,
    stream: &mut Stream,
    peer: SocketAddr,
    sni_id: Option<String>,
    ctx: Arc<ferrite_dns::ctx::DnsCtx>,
    gate: &crate::gate::Gate,
) -> Reply {
    let (client_id, query) = match doh::read_head(req.method(), req.uri(), req.headers(), sni_id) {
        Ok(asked) => asked,
        Err(reply) => return reply,
    };
    let raw = match query {
        Query::InUrl(raw) => raw,
        Query::InBody => {
            let mut body = BytesMut::new();
            loop {
                match stream.recv_data().await {
                    Ok(Some(chunk)) => {
                        if body.len() + chunk.remaining() > doh::MAX_MESSAGE {
                            return doh::too_large();
                        }
                        body.put(chunk);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        return Reply {
                            status: StatusCode::BAD_REQUEST,
                            content_type: "text/plain; charset=utf-8",
                            body: Bytes::from_static(b"the body didn't arrive\n"),
                        };
                    }
                }
            }
            body.to_vec()
        }
    };
    doh::resolve(raw, client_id.as_deref(), peer, ctx, gate).await
}

async fn send(stream: &mut Stream, reply: Reply) {
    let Ok(head) = reply.head().body(()) else {
        return;
    };
    if stream.send_response(head).await.is_err() {
        return;
    }
    let _ = stream.send_data(reply.body).await;
    let _ = stream.finish().await;
}
