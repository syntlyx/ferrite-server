use std::time::Duration;

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
            // Force HTTPS — TLS ALPN negotiates HTTP/2 automatically.
            .https_only(true)
            // Connection pool: keep up to 5 idle connections per host.
            .pool_max_idle_per_host(5)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
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

    /// POST the raw DNS query to the DoH endpoint and return the raw response.
    pub async fn resolve_raw(&self, raw: Vec<u8>) -> Result<(Vec<u8>, String)> {
        let resp = self
            .client
            .post(self.url.as_str())
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(raw)
            .send()
            .await
            .map_err(FeriteError::Http)?;

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

        let bytes = resp.bytes().await.map_err(FeriteError::Http)?;
        if bytes.len() > 65535 {
            return Err(FeriteError::Dns(format!(
                "DoH {} response too large ({} bytes)",
                self.label,
                bytes.len()
            )));
        }
        Ok((bytes.to_vec(), self.label.clone()))
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}
