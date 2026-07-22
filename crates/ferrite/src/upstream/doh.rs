use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;

use crate::error::{FeriteError, Result};

/// DNS-over-HTTPS upstream resolver (RFC 8484).
///
/// Sends raw DNS wire-format query as HTTP POST with
/// `Content-Type: application/dns-message` and receives the raw response.
/// This preserves all DNS flags, EDNS0 options, and answer records exactly.
///
/// A dedicated `Client` is built per resolver with connection pooling so that
/// TLS sessions and HTTP/2 multiplexed connections are reused across queries.
///
/// If `bootstrap_ip` is provided the upstream hostname is resolved to that IP
/// directly, bypassing the system DNS resolver. Required when ferrite is the
/// system resolver (bootstrap problem).
pub struct DohResolver {
    client: Client,
    /// Stored as `String` to avoid cloning a `Url` on every request.
    url: String,
    label: String,
}

impl DohResolver {
    pub fn new(url: &str, bootstrap_ip: Option<&str>) -> Result<Self> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| FeriteError::Config(format!("invalid DoH URL '{}': {}", url, e)))?;

        if parsed.scheme() != "https" {
            return Err(FeriteError::Config(format!(
                "DoH URL must use https, got '{}'",
                parsed.scheme()
            )));
        }

        let host = parsed.host_str().unwrap_or("").to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let label = format!("doh://{}", host);

        let mut builder = Client::builder()
            .user_agent(concat!("ferrite/", env!("CARGO_PKG_VERSION")))
            // Force HTTPS — TLS ALPN negotiates HTTP/2 (the `http2` feature is on).
            .https_only(true)
            // Connection pool: keep up to 5 idle connections per host.
            .pool_max_idle_per_host(5)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            // HTTP/2 keep-alive PINGs. Some DoH servers (e.g. Quad9) close idle h2
            // connections faster than our pool would, so a reused connection would
            // fail mid-send with "broken pipe" — and DoH POSTs aren't auto-retried.
            // Pinging while idle keeps healthy connections warm and detects dead
            // ones so they're evicted before reuse instead of being handed out.
            .http2_keep_alive_interval(Duration::from_secs(20))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            // Per-request timeout.
            .timeout(Duration::from_secs(10));

        if let Some(ip) = bootstrap_ip {
            let addr: std::net::IpAddr = ip.parse().map_err(|e| {
                FeriteError::Config(format!("invalid bootstrap_ip '{}': {}", ip, e))
            })?;
            let socket_addr = std::net::SocketAddr::new(addr, port);
            // Bypass DNS resolution for this hostname — use the IP directly.
            builder = builder.resolve(&host, socket_addr);
            tracing::info!("DoH {}: bootstrap IP {}", label, ip);
        }

        let client = builder
            .build()
            .map_err(|e| FeriteError::Config(format!("failed to build DoH client: {}", e)))?;

        Ok(Self {
            client,
            url: url.to_string(),
            label,
        })
    }

    /// Send the raw DNS query to the DoH endpoint (RFC 8484 GET form) and return
    /// the raw response.
    ///
    /// We use GET — the query base64url-encoded in the `dns` parameter — rather
    /// than POST: some DoH fronts (observed with Quad9) reset the HTTP/2
    /// connection mid-send on a POST ("stream closed because of a broken pipe")
    /// while answering the GET form cleanly. GET is mandatory for DoH servers
    /// (RFC 8484 §4.1) and universally supported, so this works everywhere.
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        // base64url (no padding) uses only `A-Za-z0-9-_`, all URL-safe, so it can
        // be appended to the query string without percent-encoding. DoH endpoints
        // carry no query of their own, so `?dns=` is unambiguous.
        let dns = URL_SAFE_NO_PAD.encode(&raw);
        let url = format!("{}?dns={}", self.url, dns);

        // reqwest pools HTTP/2 connections and never retries itself. Some DoH
        // fronts (Quad9) close a connection between requests, so a *reused* one
        // fails mid-send with "broken pipe" — exactly what a browser/curl dodges
        // by using a fresh connection. A DoH GET is idempotent, so retry: each
        // errored connection is dropped from the pool, so within a few attempts
        // we land on a healthy/fresh one. Timeouts aren't retried (no point
        // stacking 10s waits — the pool fails over to the next upstream instead).
        const MAX_ATTEMPTS: u32 = 3;
        let resp = {
            let mut attempt = 0;
            loop {
                match self.send(&url).await {
                    Ok(r) => break r,
                    Err(e) => {
                        attempt += 1;
                        if attempt >= MAX_ATTEMPTS || e.is_timeout() {
                            return Err(http_err(&self.label, &e));
                        }
                    }
                }
            }
        };

        if !resp.status().is_success() {
            return Err(FeriteError::Dns(format!(
                "DoH {} returned HTTP {}",
                self.label,
                resp.status()
            )));
        }

        // Validate the response Content-Type.
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct.contains("application/dns-message") {
            return Err(FeriteError::Dns(format!(
                "DoH {} unexpected content-type: {}",
                self.label, ct
            )));
        }

        let bytes = resp.bytes().await.map_err(|e| http_err(&self.label, &e))?;
        if bytes.len() > 65535 {
            return Err(FeriteError::Dns(format!(
                "DoH {} response too large ({} bytes)",
                self.label,
                bytes.len()
            )));
        }
        Ok((bytes.to_vec(), self.label.clone()))
    }

    /// One DoH GET attempt. Separated so `resolve_raw` can retry on a dropped
    /// connection without duplicating the request build.
    async fn send(&self, url: &str) -> std::result::Result<reqwest::Response, reqwest::Error> {
        self.client
            .get(url)
            .header("accept", "application/dns-message")
            .send()
            .await
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Build a descriptive error from a reqwest failure. reqwest's own `Display` is
/// deliberately terse ("error sending request for url (...)") and hides the real
/// cause in the `source()` chain — so we walk it and tag the common kinds, to
/// turn an opaque warning into something actionable (DNS lookup vs connect vs
/// TLS vs HTTP/2).
fn http_err(label: &str, e: &reqwest::Error) -> FeriteError {
    use std::error::Error;
    use std::fmt::Write;

    let mut msg = format!("DoH {label}: {e}");
    if e.is_connect() {
        msg.push_str(" [connect]");
    }
    if e.is_timeout() {
        msg.push_str(" [timeout]");
    }
    let mut src = e.source();
    while let Some(s) = src {
        let _ = write!(msg, " → {s}");
        src = s.source();
    }
    FeriteError::Dns(msg)
}
