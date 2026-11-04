//! `/api/secure-dns`: DNS over TLS and DNS over HTTPS for devices — the
//! settings, what the listeners are doing, and what to type into a device.
//! A change applies at once, no restart.

use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::config::{CertSource, Config, SecureDnsConfig};
use ferrite_core::error::FeriteError;

fn view(state: &AppState) -> Value {
    let mut cfg = state.live_config.read().secure_dns.clone();
    // The token is never sent back; the panel learns only that there is one.
    let token_set = cfg.acme.cloudflare_token.take().is_some();
    let mut status = state.inner.secure_dns.status();
    // A shared port is only as up as Tunnels' listener on it.
    if !state.inner.proxy.https_listening() {
        let down = "Tunnels isn't listening on this port".to_string();
        if status.doh_shared {
            status.doh = false;
            status.doh_error = Some(down.clone());
        }
        if status.dot_shared {
            status.dot = false;
            status.dot_error = Some(down);
        }
    }
    let host = cfg.hostname.clone();
    let doh_url = (!host.is_empty() && cfg.doh_port != 0).then(|| {
        if cfg.doh_port == 443 {
            format!("https://{host}/dns-query")
        } else {
            format!("https://{host}:{}/dns-query", cfg.doh_port)
        }
    });
    json!({
        "config": cfg,
        "token_set": token_set,
        "status": status,
        // What a device is told: Android's Private DNS takes a name only, so
        // DNS over TLS has to be on 853 for it.
        "setup": {
            "dot_host": (!host.is_empty() && cfg.dot_port != 0).then(|| host.clone()),
            "dot_port": cfg.dot_port,
            "doh_url": doh_url,
        },
    })
}

/// GET /api/secure-dns
pub async fn get_secure_dns(State(state): State<AppState>) -> Json<Value> {
    Json(view(&state))
}

/// PUT /api/secure-dns — the whole section; checked, saved, applied at once.
/// A blank Cloudflare token keeps the one already saved.
pub async fn put_secure_dns(
    State(state): State<AppState>,
    Json(mut cfg): Json<SecureDnsConfig>,
) -> Result<Json<Value>, ApiError> {
    tidy(&mut cfg);
    let previous = {
        let live = state.live_config.read();
        if cfg.acme.cloudflare_token.is_none() {
            cfg.acme.cloudflare_token = live.secure_dns.acme.cloudflare_token.clone();
        }
        validate(&cfg, &live).map_err(|m| ApiError(FeriteError::Config(m)))?;
        live.secure_dns.hostname.clone()
    };
    state.live_config.write().secure_dns = cfg;
    state.persist_config().await;
    state.inner.dns_cache.forget_name(&previous);
    state.apply_secure_dns().await;
    Ok(Json(view(&state)))
}

/// POST /api/secure-dns/renew — ask Let's Encrypt again now, not at the next
/// try after a failure.
pub async fn renew_secure_dns(State(state): State<AppState>) -> Json<Value> {
    state.inner.secure_dns.retry_now();
    // A moment for the attempt to start, so the answer shows it working.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Json(view(&state))
}

fn tidy(cfg: &mut SecureDnsConfig) {
    cfg.hostname = cfg
        .hostname
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    for path in [&mut cfg.cert_file, &mut cfg.key_file] {
        *path = path
            .take()
            .map(|p| p.to_string_lossy().trim().to_string())
            .filter(|p| !p.is_empty())
            .map(Into::into);
    }
    cfg.acme.email = cfg.acme.email.trim().to_string();
    cfg.acme.cloudflare_token = cfg
        .acme
        .cloudflare_token
        .take()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
}

fn valid_hostname(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// What would keep the listeners from coming up, said before it is saved.
/// A port Tunnels listens on is fine: it is shared.
pub(crate) fn validate(cfg: &SecureDnsConfig, live: &Config) -> Result<(), String> {
    if !cfg.hostname.is_empty() && !valid_hostname(&cfg.hostname) {
        return Err(format!(
            "{} isn't a host name like dns.example.com",
            cfg.hostname
        ));
    }
    let email = &cfg.acme.email;
    if !email.is_empty()
        && !email
            .split_once('@')
            .is_some_and(|(user, domain)| !user.is_empty() && domain.contains('.'))
    {
        return Err(format!("{email} isn't an email address"));
    }
    if !cfg.enabled {
        return Ok(());
    }
    if cfg.hostname.is_empty() {
        return Err("set the name devices connect to, like dns.example.com".into());
    }
    match cfg.certificate {
        CertSource::Files if cfg.cert_file.is_none() || cfg.key_file.is_none() => {
            return Err("set the certificate and its key".into());
        }
        CertSource::Letsencrypt if cfg.acme.cloudflare_token.is_none() => {
            return Err("set a Cloudflare API token for Let's Encrypt".into());
        }
        _ => {}
    }
    if cfg.dot_port == 0 && cfg.doh_port == 0 {
        return Err("turn on DNS over TLS, DNS over HTTPS, or both".into());
    }
    let taken = [
        (live.dns.bind_addr.port(), "plain DNS"),
        (live.api.bind_addr.port(), "the panel"),
    ];
    for port in [cfg.dot_port, cfg.doh_port] {
        if port == 0 {
            continue;
        }
        if let Some((_, what)) = taken.iter().find(|(p, _)| *p == port) {
            return Err(format!("port {port} is {what}'s"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls;

    fn testdata(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../secure/testdata")
            .join(name)
    }

    fn on(port_dot: u16, port_doh: u16) -> SecureDnsConfig {
        SecureDnsConfig {
            enabled: true,
            hostname: "dns.test".into(),
            certificate: CertSource::Files,
            cert_file: Some(testdata("cert.pem")),
            key_file: Some(testdata("key.pem")),
            dot_port: port_dot,
            doh_port: port_doh,
            ..SecureDnsConfig::default()
        }
    }

    #[test]
    fn validation_names_the_problem() {
        let live = Config::default();
        assert_eq!(validate(&on(853, 443), &live), Ok(()));
        assert_eq!(validate(&SecureDnsConfig::default(), &live), Ok(()));

        let mut c = on(853, 443);
        c.hostname = "localhost".into();
        assert!(validate(&c, &live).unwrap_err().contains("host name"));

        let mut c = on(853, 443);
        c.cert_file = None;
        assert!(validate(&c, &live).unwrap_err().contains("certificate"));

        assert!(validate(&on(0, 0), &live).unwrap_err().contains("both"));
        assert!(
            validate(&on(53, 443), &live)
                .unwrap_err()
                .contains("plain DNS")
        );

        // Tunnels' port is shared, not a clash.
        let mut tunnels = Config::default();
        tunnels.proxy.enabled = true;
        tunnels.proxy.https_port = 443;
        assert_eq!(validate(&on(853, 443), &tunnels), Ok(()));

        let mut le = on(853, 443);
        le.certificate = CertSource::Letsencrypt;
        le.cert_file = None;
        assert!(validate(&le, &live).unwrap_err().contains("Cloudflare"));
        le.acme.cloudflare_token = Some("t".into());
        assert_eq!(validate(&le, &live), Ok(()));
        le.acme.email = "nobody".into();
        assert!(validate(&le, &live).unwrap_err().contains("email"));
    }

    #[tokio::test]
    async fn the_token_is_kept_but_never_shown() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("secure-dns-token").await;
        let mut cfg = on(0, 0);
        cfg.enabled = false;
        cfg.certificate = CertSource::Letsencrypt;
        cfg.acme.cloudflare_token = Some(" secret ".into());
        let Json(v) = put_secure_dns(State(state.clone()), Json(cfg.clone()))
            .await
            .unwrap();
        assert_eq!(v["token_set"], true);
        assert!(v["config"]["acme"]["cloudflare_token"].is_null(), "{v}");
        assert!(!v.to_string().contains("secret"));

        // Sent back blank, as the panel does: the saved one stays.
        cfg.acme.cloudflare_token = None;
        cfg.acme.email = "me@example.com".into();
        let _ = put_secure_dns(State(state.clone()), Json(cfg))
            .await
            .unwrap();
        let live = state.live_config.read().secure_dns.acme.clone();
        assert_eq!(live.cloudflare_token.as_deref(), Some("secret"));
        assert_eq!(live.email, "me@example.com");

        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }

    /// Accepts any certificate — the test one is self-signed.
    #[derive(Debug)]
    struct AnyCert;
    impl rustls::client::danger::ServerCertVerifier for AnyCert {
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

    async fn connect(
        port: u16,
        sni: &str,
        alpn: &[u8],
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
        cfg.alpn_protocols = vec![alpn.to_vec()];
        let tcp = tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(
                rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap(),
                tcp,
            )
            .await
            .unwrap()
    }

    /// A query for `home.test` A, which a custom record answers — no upstream.
    fn home_query(id: u16) -> Vec<u8> {
        let mut q = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        for label in ["home", "test"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn devices_ask_over_tls_and_https_and_are_known_by_their_id() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("secure-dns").await;
        state
            .inner
            .custom_records
            .add(&ferrite_core::config::CustomRecordConfig {
                domain: "home.test".into(),
                record_type: "A".into(),
                value: "10.0.0.7".into(),
                ttl: 60,
            })
            .unwrap();
        let mut log = state.query_rx.lock().take().unwrap();
        let (dot, doh) = (free_port(), free_port());

        let Json(v) = put_secure_dns(State(state.clone()), Json(on(dot, doh)))
            .await
            .unwrap();
        assert_eq!(v["status"]["running"], true, "{v}");
        assert_eq!(v["status"]["dot"], true);
        assert_eq!(v["status"]["doh"], true);
        assert!(v["status"]["cert_warning"].is_null(), "{v}");
        assert_eq!(v["setup"]["dot_host"], "dns.test");

        // DNS over TLS, named `kid` in the TLS name; two queries pipelined.
        let mut tls = connect(dot, "kid.dns.test", b"dot").await;
        let mut out = Vec::new();
        for id in [7u16, 8] {
            let q = home_query(id);
            out.extend_from_slice(&(q.len() as u16).to_be_bytes());
            out.extend_from_slice(&q);
        }
        tls.write_all(&out).await.unwrap();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let mut len = [0u8; 2];
            tls.read_exact(&mut len).await.unwrap();
            let mut answer = vec![0u8; u16::from_be_bytes(len) as usize];
            tls.read_exact(&mut answer).await.unwrap();
            assert_eq!(&answer[answer.len() - 4..], &[10, 0, 0, 7]);
            ids.push(u16::from_be_bytes([answer[0], answer[1]]));
        }
        ids.sort();
        assert_eq!(ids, vec![7, 8]);
        let entry = log.recv().await.unwrap();
        assert_eq!(entry.device, "id:kid");
        let _ = log.recv().await.unwrap();

        // DNS over HTTPS, GET, named `tv` in the path.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(home_query(9));
        let mut https = connect(doh, "dns.test", b"http/1.1").await;
        https
            .write_all(
                format!(
                    "GET /dns-query/tv?dns={b64} HTTP/1.1\r\nHost: dns.test\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = https.read_to_end(&mut response).await;
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&response[..split]).to_string();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("application/dns-message"), "{head}");
        assert_eq!(&response[response.len() - 4..], &[10, 0, 0, 7]);
        assert_eq!(log.recv().await.unwrap().device, "id:tv");

        // Switched off: the ports close.
        let mut off = on(dot, doh);
        off.enabled = false;
        let Json(v) = put_secure_dns(State(state.clone()), Json(off))
            .await
            .unwrap();
        assert_eq!(v["status"]["running"], false);
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", dot))
                .await
                .is_err()
        );

        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }

    async fn doh_get(port: u16, sni: &str, path: &str, id: u16) -> Vec<u8> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(home_query(id));
        let mut https = connect(port, sni, b"http/1.1").await;
        https
            .write_all(
                format!(
                    "GET {path}?dns={b64} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = https.read_to_end(&mut response).await;
        response
    }

    #[tokio::test]
    async fn https_shares_the_tunnels_port_by_name() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("secure-dns-shared").await;
        state
            .inner
            .custom_records
            .add(&ferrite_core::config::CustomRecordConfig {
                domain: "home.test".into(),
                record_type: "A".into(),
                value: "10.0.0.7".into(),
                ttl: 60,
            })
            .unwrap();
        let mut log = state.query_rx.lock().take().unwrap();

        // Tunnels on: it owns the TLS port.
        let shared = free_port();
        let mut tunnels = state.live_config.read().proxy.clone();
        tunnels.enabled = true;
        tunnels.https_port = shared;
        tunnels.http_port = free_port();
        state.inner.proxy.reload(&tunnels);
        state.live_config.write().proxy = tunnels.clone();
        tokio::spawn(ferrite_proxy::run(state.proxy_ctx()));
        for _ in 0..100 {
            if state.inner.proxy.https_listening() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let Json(v) = put_secure_dns(State(state.clone()), Json(on(free_port(), shared)))
            .await
            .unwrap();
        assert_eq!(v["status"]["doh"], true, "{v}");
        assert_eq!(v["status"]["doh_shared"], true, "{v}");

        // Our name on Tunnels' port: answered here, device named in the TLS name.
        let response = doh_get(shared, "tv.dns.test", "/dns-query", 11).await;
        let head = String::from_utf8_lossy(&response[..response.len().min(64)]).to_string();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(&response[response.len() - 4..], &[10, 0, 0, 7]);
        assert_eq!(log.recv().await.unwrap().device, "id:tv");

        // Tunnels off: encrypted DNS takes the port over itself.
        tunnels.enabled = false;
        state.inner.proxy.reload(&tunnels);
        state.live_config.write().proxy = tunnels;
        state.apply_secure_dns().await;
        let Json(v) = get_secure_dns(State(state.clone())).await;
        assert_eq!(v["status"]["doh"], true, "{v}");
        assert_eq!(v["status"]["doh_shared"], false, "{v}");
        let response = doh_get(shared, "dns.test", "/dns-query/tv", 12).await;
        assert_eq!(&response[response.len() - 4..], &[10, 0, 0, 7]);

        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }
}
