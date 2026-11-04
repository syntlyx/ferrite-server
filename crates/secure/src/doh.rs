//! DNS over HTTPS (RFC 8484): `GET /dns-query?dns=<base64url>` or `POST
//! /dns-query` with an `application/dns-message` body, over HTTP/1.1 or
//! HTTP/2 here and over HTTP/3 in [`crate::doh3`], which shares the request
//! handling below. `/dns-query/<client id>` names the device. Through a
//! trusted reverse proxy, the client is the one it names.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use base64::Engine;
use bytes::Bytes;
use http::header::{ALT_SVC, CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};

use ferrite_dns::ctx::DnsCtx;

use crate::gate::Gate;

const DNS_MESSAGE: &str = "application/dns-message";
pub(crate) const MAX_MESSAGE: usize = 65_535;

pub(crate) async fn serve<S>(
    stream: S,
    peer: SocketAddr,
    sni_id: Option<String>,
    ctx: Arc<DnsCtx>,
    gate: Arc<Gate>,
    h3_port: Arc<AtomicU16>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req| {
        let (ctx, sni_id, gate) = (Arc::clone(&ctx), sni_id.clone(), Arc::clone(&gate));
        let h3 = h3_port.load(Ordering::Relaxed);
        async move {
            let mut response = answer(req, peer, sni_id, ctx, &gate).await.into_hyper();
            // Where HTTP/3 is on, say so: the device takes it from the next
            // query, over UDP, and keeps it for a day.
            if h3 != 0
                && let Ok(v) = HeaderValue::from_str(&format!("h3=\":{h3}\"; ma=86400"))
            {
                response.headers_mut().insert(ALT_SVC, v);
            }
            Ok::<_, Infallible>(response)
        }
    });
    if let Err(e) = auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!("doh: connection from {peer} ended: {e}");
    }
}

/// An answer to a DNS over HTTPS request, whichever HTTP it came over.
pub(crate) struct Reply {
    pub status: StatusCode,
    pub content_type: &'static str,
    pub body: Bytes,
}

impl Reply {
    fn text(status: StatusCode, body: &'static str) -> Self {
        Reply {
            status,
            content_type: "text/plain; charset=utf-8",
            body: Bytes::from_static(body.as_bytes()),
        }
    }

    fn dns(bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::text(StatusCode::BAD_REQUEST, "not a DNS query\n");
        }
        Reply {
            status: StatusCode::OK,
            content_type: DNS_MESSAGE,
            body: Bytes::from(bytes),
        }
    }

    /// The response head; the body goes as is.
    pub(crate) fn head(&self) -> http::response::Builder {
        let head = http::Response::builder()
            .status(self.status)
            .header(CONTENT_TYPE, self.content_type);
        // Answers already carry the TTL the device may keep them for.
        if self.status == StatusCode::OK {
            head.header(CACHE_CONTROL, "no-store")
        } else {
            head
        }
    }

    fn into_hyper(self) -> Response<Full<Bytes>> {
        self.head().body(Full::new(self.body)).unwrap_or_default()
    }
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

/// The client a reverse proxy forwards for: `X-Real-IP`, else the last
/// entry of `X-Forwarded-For` — the one the proxy added itself; anything
/// before it came from the client and proves nothing.
pub(crate) fn forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let parse = |s: &str| -> Option<IpAddr> {
        let s = s.trim();
        s.parse()
            .ok()
            .or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip()))
            .map(ferrite_core::net::unmap_v4)
    };
    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return parse(v);
    }
    let last = headers.get_all("x-forwarded-for").into_iter().next_back()?;
    parse(last.to_str().ok()?.rsplit(',').next()?)
}

/// How a request's query comes: in the URL, or as the body still to read.
pub(crate) enum Query {
    InUrl(Vec<u8>),
    InBody,
}

/// What a request asks, read from its head: the device it names and how its
/// query comes. `Err` is the answer to send instead.
pub(crate) fn read_head(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    sni_id: Option<String>,
) -> Result<(Option<String>, Query), Reply> {
    let Some(client_id) = path_id(uri.path(), sni_id) else {
        return Err(Reply::text(StatusCode::NOT_FOUND, "not found\n"));
    };
    let query = match *method {
        Method::GET => {
            let param = uri.query().and_then(|q| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("dns="))
                    .map(str::to_owned)
            });
            let Some(param) = param else {
                return Err(Reply::text(
                    StatusCode::BAD_REQUEST,
                    "missing dns parameter\n",
                ));
            };
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            match b64.decode(param.trim_end_matches('=')) {
                Ok(raw) => Query::InUrl(raw),
                Err(_) => {
                    return Err(Reply::text(
                        StatusCode::BAD_REQUEST,
                        "dns isn't base64url\n",
                    ));
                }
            }
        }
        Method::POST => {
            let typed = headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case(DNS_MESSAGE));
            if !typed {
                return Err(Reply::text(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "expected application/dns-message\n",
                ));
            }
            Query::InBody
        }
        _ => return Err(Reply::text(StatusCode::METHOD_NOT_ALLOWED, "GET or POST\n")),
    };
    Ok((client_id, query))
}

/// Answer the query `raw` from `peer`, as `client_id` — or refuse it.
pub(crate) async fn resolve(
    raw: Vec<u8>,
    client_id: Option<&str>,
    peer: SocketAddr,
    ctx: Arc<DnsCtx>,
    gate: &Gate,
) -> Reply {
    if raw.len() < 12 || raw.len() > MAX_MESSAGE {
        return Reply::text(StatusCode::BAD_REQUEST, "not a DNS message\n");
    }
    if !gate.allows(peer.ip(), client_id) {
        return Reply::dns(ferrite_dns::handler::refused(&raw));
    }
    let Ok(permit) = Arc::clone(&ctx.query_semaphore).try_acquire_owned() else {
        return Reply::text(StatusCode::SERVICE_UNAVAILABLE, "busy\n");
    };
    let result = ferrite_dns::handler::handle_query_as(raw, peer, client_id, ctx).await;
    drop(permit);
    match result {
        Ok(bytes) => Reply::dns(bytes),
        _ => Reply::text(StatusCode::BAD_REQUEST, "not a DNS query\n"),
    }
}

pub(crate) fn too_large() -> Reply {
    Reply::text(StatusCode::PAYLOAD_TOO_LARGE, "message too large\n")
}

async fn answer(
    req: Request<Incoming>,
    peer: SocketAddr,
    sni_id: Option<String>,
    ctx: Arc<DnsCtx>,
    gate: &Gate,
) -> Reply {
    let (client_id, query) = match read_head(req.method(), req.uri(), req.headers(), sni_id) {
        Ok(asked) => asked,
        Err(reply) => return reply,
    };
    // A proxy is at home; the device behind it may not be. One that doesn't
    // say who that is isn't answered as if it were the device.
    let peer = if gate.trusts(peer.ip()) {
        match forwarded_for(req.headers()) {
            Some(ip) => SocketAddr::new(ip, peer.port()),
            None => {
                return Reply::text(
                    StatusCode::BAD_REQUEST,
                    "the proxy didn't say whom it forwards for (X-Real-IP)\n",
                );
            }
        }
    } else {
        peer
    };
    let raw = match query {
        Query::InUrl(raw) => raw,
        Query::InBody => match Limited::new(req.into_body(), MAX_MESSAGE).collect().await {
            Ok(body) => body.to_bytes().to_vec(),
            Err(_) => return too_large(),
        },
    };
    resolve(raw, client_id.as_deref(), peer, ctx, gate).await
}

#[cfg(test)]
mod tests {
    use super::{forwarded_for, path_id};
    use hyper::HeaderMap;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn the_proxy_names_the_client() {
        let ip = |s: &str| Some(s.parse().unwrap());
        assert_eq!(
            forwarded_for(&headers(&[("x-real-ip", "198.51.100.7")])),
            ip("198.51.100.7")
        );
        // What the proxy added is the last entry; the rest is the client's word.
        assert_eq!(
            forwarded_for(&headers(&[("x-forwarded-for", "10.0.0.1, 198.51.100.7")])),
            ip("198.51.100.7")
        );
        assert_eq!(
            forwarded_for(&headers(&[
                ("x-forwarded-for", "10.0.0.1"),
                ("x-forwarded-for", "2001:db8::7"),
            ])),
            ip("2001:db8::7")
        );
        assert_eq!(
            forwarded_for(&headers(&[("x-real-ip", "::ffff:198.51.100.7")])),
            ip("198.51.100.7")
        );
        assert_eq!(forwarded_for(&headers(&[])), None);
        assert_eq!(forwarded_for(&headers(&[("x-real-ip", "nonsense")])), None);
    }

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
