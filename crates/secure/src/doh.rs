//! DNS over HTTPS (RFC 8484): `GET /dns-query?dns=<base64url>` or `POST
//! /dns-query` with an `application/dns-message` body, over HTTP/1.1 or
//! HTTP/2. `/dns-query/<client id>` names the device.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};

use ferrite_dns::ctx::DnsCtx;

use crate::gate::Gate;

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_MESSAGE: usize = 65_535;

pub(crate) async fn serve<S>(
    stream: S,
    peer: SocketAddr,
    sni_id: Option<String>,
    ctx: Arc<DnsCtx>,
    gate: Arc<Gate>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req| {
        let (ctx, sni_id, gate) = (Arc::clone(&ctx), sni_id.clone(), Arc::clone(&gate));
        async move { Ok::<_, Infallible>(answer(req, peer, sni_id, ctx, &gate).await) }
    });
    if let Err(e) = auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!("doh: connection from {peer} ended: {e}");
    }
}

fn reply(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap_or_default()
}

/// The client ID a path names: `/dns-query` → the one from the TLS name,
/// `/dns-query/pixel` → `pixel`. `None` = not a DNS path at all.
pub(crate) fn path_id(path: &str, sni_id: Option<String>) -> Option<Option<String>> {
    let rest = path.strip_prefix("/dns-query")?;
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() {
        return Some(sni_id);
    }
    let id = rest.strip_prefix('/')?;
    ferrite_core::net::normalize_client_id(id).map(Some)
}

async fn answer(
    req: Request<Incoming>,
    peer: SocketAddr,
    sni_id: Option<String>,
    ctx: Arc<DnsCtx>,
    gate: &Gate,
) -> Response<Full<Bytes>> {
    let Some(client_id) = path_id(req.uri().path(), sni_id) else {
        return reply(StatusCode::NOT_FOUND, "not found\n");
    };
    let raw = match *req.method() {
        Method::GET => {
            let param = req.uri().query().and_then(|q| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("dns="))
                    .map(str::to_owned)
            });
            let Some(param) = param else {
                return reply(StatusCode::BAD_REQUEST, "missing dns parameter\n");
            };
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            match b64.decode(param.trim_end_matches('=')) {
                Ok(raw) => raw,
                Err(_) => return reply(StatusCode::BAD_REQUEST, "dns isn't base64url\n"),
            }
        }
        Method::POST => {
            let typed = req
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case(DNS_MESSAGE));
            if !typed {
                return reply(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "expected application/dns-message\n",
                );
            }
            match Limited::new(req.into_body(), MAX_MESSAGE).collect().await {
                Ok(body) => body.to_bytes().to_vec(),
                Err(_) => return reply(StatusCode::PAYLOAD_TOO_LARGE, "message too large\n"),
            }
        }
        _ => return reply(StatusCode::METHOD_NOT_ALLOWED, "GET or POST\n"),
    };
    if raw.len() < 12 || raw.len() > MAX_MESSAGE {
        return reply(StatusCode::BAD_REQUEST, "not a DNS message\n");
    }
    if !gate.allows(peer.ip(), client_id.as_deref()) {
        return dns_message(ferrite_dns::handler::refused(&raw));
    }
    let Ok(permit) = Arc::clone(&ctx.query_semaphore).try_acquire_owned() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, "busy\n");
    };
    let result = ferrite_dns::handler::handle_query_as(raw, peer, client_id.as_deref(), ctx).await;
    drop(permit);
    match result {
        Ok(bytes) => dns_message(bytes),
        _ => reply(StatusCode::BAD_REQUEST, "not a DNS query\n"),
    }
}

fn dns_message(bytes: Vec<u8>) -> Response<Full<Bytes>> {
    if bytes.is_empty() {
        return reply(StatusCode::BAD_REQUEST, "not a DNS query\n");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, DNS_MESSAGE)
        // Answers already carry the TTL the device may keep them for.
        .header(CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::path_id;

    #[test]
    fn paths_name_the_device() {
        let sni = Some("tv".to_string());
        assert_eq!(path_id("/dns-query", sni.clone()), Some(sni.clone()));
        assert_eq!(path_id("/dns-query/", None), Some(None));
        assert_eq!(
            path_id("/dns-query/Pixel", sni.clone()),
            Some(Some("pixel".into()))
        );
        assert_eq!(path_id("/dns-query/bad.id", None), None);
        assert_eq!(path_id("/other", None), None);
        assert_eq!(path_id("/dns-queryx", None), None);
    }
}
