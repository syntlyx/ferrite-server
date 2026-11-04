//! `GET /api/proxy/companions?rule=<key>` — what else a routed site pulls
//! in. A page asks for more than its own name: a CDN for its pictures, a bot
//! check, fonts. Routing only the site leaves those to go straight, and where
//! the site is blocked they usually are too — a page that hangs or comes up
//! white. So: the names a device asked in the seconds after it opened the
//! site, each tried straight and through the rule's tunnel. The ones that
//! don't open straight but do through the tunnel are what the site needs
//! routed too; the rest (the phone's own chatter, a CDN that opens anyway)
//! are shown but not offered.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::error::FeriteError;
use ferrite_core::types::QueryStatus;
use ferrite_storage::QueryFilter;

/// How far back visits to the site are looked for.
const LOOKBACK_SECS: i64 = 7 * 24 * 3600;
/// The window around a visit: a page's own names come in the first seconds.
const BEFORE_SECS: i64 = 2;
const AFTER_SECS: i64 = 20;
/// Visits looked at, newest first; one per device per minute.
const MAX_VISITS: usize = 12;
/// Names tried, the most often seen first.
const MAX_TRIED: usize = 24;
/// Each try, connection and TLS handshake together.
const PROBE: Duration = Duration::from_secs(4);
/// Tries at once.
const PROBES_AT_ONCE: usize = 8;

#[derive(Deserialize)]
pub struct CompanionsQuery {
    /// The rule: its pattern, or `service:<id>`.
    rule: String,
}

/// The site a name belongs to, as a rule would name it: the last two labels,
/// or three under a country's own second level (`news.bbc.co.uk` →
/// `bbc.co.uk`, `shop.example.com.ua` → `example.com.ua`).
pub(crate) fn site_of(name: &str) -> String {
    const SECOND_LEVEL: &[&str] = &[
        "co", "com", "net", "org", "gov", "edu", "ac", "in", "ltd", "plc", "or", "ne", "go",
    ];
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    let take = if n >= 3 && labels[n - 1].len() == 2 && SECOND_LEVEL.contains(&labels[n - 2]) {
        3
    } else {
        2
    };
    labels[n.saturating_sub(take)..].join(".")
}

/// Accepts any certificate: a try only asks whether the site answers the
/// handshake at all, and nothing is sent after it.
#[derive(Debug)]
pub(crate) struct AnyAnswer;

impl rustls::client::danger::ServerCertVerifier for AnyAnswer {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn connector() -> TlsConnector {
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AnyAnswer))
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(cfg))
}

/// Does `host` answer a TLS handshake on `conn`?
async fn answers<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &TlsConnector,
    conn: S,
    host: &str,
) -> bool {
    let Ok(name) = rustls::pki_types::ServerName::try_from(host.to_string()) else {
        return false;
    };
    tls.connect(name, conn).await.is_ok()
}

/// GET /api/proxy/companions?rule=<key>
pub async fn companions(
    State(state): State<AppState>,
    Query(q): Query<CompanionsQuery>,
) -> Result<Json<Value>, ApiError> {
    let rule = state
        .live_config
        .read()
        .proxy
        .rules
        .iter()
        .find(|r| r.hit_key() == q.rule)
        .cloned()
        .ok_or_else(|| ApiError(FeriteError::NotFound(format!("no rule {}", q.rule))))?;
    let proxy = Arc::clone(&state.inner.proxy);
    let storage = Arc::clone(&state.inner.storage);
    let now = chrono::Utc::now().timestamp();

    // The visits: routed answers for this rule's names, newest first.
    let routed = storage
        .query_range(&QueryFilter {
            from_ts: Some(now - LOOKBACK_SECS),
            status: Some("routed".into()),
            limit: Some(2000),
            ..QueryFilter::default()
        })
        .await
        .map_err(ApiError)?;
    let mut visits: Vec<(String, i64)> = Vec::new();
    for e in routed {
        if proxy.rule_key_for(&e.domain).as_deref() != Some(q.rule.as_str()) {
            continue;
        }
        let at = e.timestamp.timestamp();
        if visits
            .iter()
            .any(|(d, t)| *d == e.device && (t - at).abs() < 60)
        {
            continue;
        }
        visits.push((e.device, at));
        if visits.len() >= MAX_VISITS {
            break;
        }
    }

    // What the same device asked around each visit, not routed already.
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (device, at) in &visits {
        let around = storage
            .query_range(&QueryFilter {
                devices: vec![device.clone()],
                from_ts: Some(at - BEFORE_SECS),
                to_ts: Some(at + AFTER_SECS),
                limit: Some(500),
                ..QueryFilter::default()
            })
            .await
            .map_err(ApiError)?;
        let here: HashSet<String> = around
            .into_iter()
            .filter(|e| {
                matches!(
                    e.status,
                    QueryStatus::Upstream | QueryStatus::Cached | QueryStatus::Allowed
                )
            })
            .map(|e| e.domain.trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| {
                d.contains('.')
                    && !d.ends_with(".arpa")
                    && !d.ends_with(".local")
                    && proxy.rule_key_for(d).is_none()
            })
            .collect();
        for d in here {
            *seen.entry(d).or_default() += 1;
        }
    }
    let mut tried: Vec<(String, usize)> = seen.into_iter().collect();
    tried.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    tried.truncate(MAX_TRIED);

    // Each name, straight and through the tunnel.
    let egress = proxy.egress(&rule.egress);
    let tls = connector();
    let upstream = Arc::clone(&state.inner.upstream_pool);
    let gate = Arc::new(tokio::sync::Semaphore::new(PROBES_AT_ONCE));
    let probes = tried.into_iter().map(|(domain, count)| {
        let (tls, upstream, egress, gate) = (
            tls.clone(),
            Arc::clone(&upstream),
            egress.clone(),
            Arc::clone(&gate),
        );
        async move {
            let _slot = gate.acquire().await;
            let straight = tokio::time::timeout(PROBE, async {
                match ferrite_proxy::direct_connect(&upstream, &domain, 443).await {
                    Ok(tcp) => answers(&tls, tcp, &domain).await,
                    Err(_) => false,
                }
            });
            let tunnel = tokio::time::timeout(PROBE, async {
                let Some(egress) = &egress else {
                    return false;
                };
                match egress.connect(&domain, 443).await {
                    Ok(conn) => answers(&tls, conn, &domain).await,
                    Err(_) => false,
                }
            });
            let (straight, tunnel) = tokio::join!(straight, tunnel);
            let (straight, tunnel) = (straight.unwrap_or(false), tunnel.unwrap_or(false));
            json!({
                "domain": domain,
                "site": site_of(&domain),
                "seen": count,
                "direct": straight,
                "tunnel": tunnel,
                // Needs the tunnel, and the tunnel takes it.
                "suggested": !straight && tunnel,
            })
        }
    });
    let mut candidates = futures_util::future::join_all(probes).await;
    candidates.sort_by_key(|c| {
        (
            !c["suggested"].as_bool().unwrap_or(false),
            std::cmp::Reverse(c["seen"].as_u64().unwrap_or(0)),
        )
    });

    Ok(Json(json!({
        "rule": q.rule,
        "egress": rule.egress,
        "egress_up": egress.is_some(),
        "visits": visits.len(),
        "candidates": candidates,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ferrite_core::config::{EgressConfig, RuleConfig};
    use ferrite_core::recording::RecordScope;
    use ferrite_core::types::QueryEntry;

    fn entry(at: i64, domain: &str, device: &str, status: QueryStatus) -> QueryEntry {
        QueryEntry {
            id: 0,
            timestamp: chrono::Utc.timestamp_opt(at, 0).unwrap(),
            domain: domain.into(),
            query_type: 1,
            client_ip: "192.168.1.40".into(),
            device: device.into(),
            status,
            latency_ms: 1,
            upstream: matches!(status, QueryStatus::Routed).then(|| "proxy:t".into()),
            rcode: 0,
        }
    }

    /// What a device asked right after opening a routed site comes back —
    /// once per name, counted over visits — and nothing routed, blocked,
    /// another device's or out of the window does.
    #[tokio::test]
    async fn a_sites_companions_are_what_its_visitors_asked_next() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("companions").await;
        let mut proxy = state.live_config.read().proxy.clone();
        proxy.enabled = true;
        proxy.egresses = vec![EgressConfig {
            id: "t".into(),
            name: "t".into(),
            enabled: true,
            kind: "direct".into(),
            address: None,
            port: None,
            username: None,
            password: None,
            config: None,
            seg_position: None,
            buffer_kb: None,
            tx_buffer_kb: None,
            backend: None,
        }];
        proxy.rules = ["site.test", "other.test"]
            .into_iter()
            .map(|p| RuleConfig {
                pattern: p.into(),
                service: None,
                egress: "t".into(),
                fail_closed: false,
                clients: Vec::new(),
            })
            .collect();
        state.inner.proxy.reload(&proxy);
        state.live_config.write().proxy = proxy;

        let now = chrono::Utc::now().timestamp();
        let (a, b) = (now - 600, now - 300);
        let rows = vec![
            // Two visits by one phone, five minutes apart.
            entry(a, "www.site.test", "id:phone", QueryStatus::Routed),
            entry(
                a + 1,
                "cdn.site-cdn.test",
                "id:phone",
                QueryStatus::Upstream,
            ),
            entry(a + 2, "check.guard.test", "id:phone", QueryStatus::Upstream),
            entry(a + 3, "ads.tracker.test", "id:phone", QueryStatus::Blocked),
            entry(a + 4, "x.other.test", "id:phone", QueryStatus::Routed),
            entry(a + 60, "late.test", "id:phone", QueryStatus::Upstream),
            entry(b, "site.test", "id:phone", QueryStatus::Routed),
            entry(b + 2, "cdn.site-cdn.test", "id:phone", QueryStatus::Cached),
            // Someone else, meanwhile.
            entry(b + 1, "tv-noise.test", "id:tv", QueryStatus::Upstream),
        ];
        let rows = rows
            .into_iter()
            .enumerate()
            .map(|(i, e)| QueryEntry {
                id: i as u64 + 1,
                ..e
            })
            .collect();
        state
            .inner
            .storage
            .write_batch(rows, RecordScope::ALL)
            .await
            .unwrap();

        let Json(v) = companions(
            State(state.clone()),
            Query(CompanionsQuery {
                rule: "site.test".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(v["visits"], 2, "{v}");
        let found: Vec<(String, u64)> = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["domain"].as_str().unwrap().to_string(),
                    c["seen"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            found,
            vec![
                ("cdn.site-cdn.test".to_string(), 2),
                ("check.guard.test".to_string(), 1),
            ]
        );
        let first = &v["candidates"][0];
        assert_eq!(first["site"], "site-cdn.test");
        // Neither opens anywhere in a test: nothing to suggest.
        assert_eq!(first["suggested"], false);

        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }

    #[test]
    fn names_belong_to_their_site() {
        assert_eq!(site_of("check.ddos-guard.net"), "ddos-guard.net");
        assert_eq!(site_of("a.d-cd.net"), "d-cd.net");
        assert_eq!(site_of("drive2.ru"), "drive2.ru");
        assert_eq!(site_of("news.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(site_of("shop.example.com.ua"), "example.com.ua");
        assert_eq!(site_of("static.example.com"), "example.com");
        assert_eq!(site_of("localhost"), "localhost");
    }
}
