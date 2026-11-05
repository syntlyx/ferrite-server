//! `/api/relay` — this box reached through a relay: which relay (its address
//! and pin), whether it's on, the box's ID there, and how the connection is.

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::config::{CertSource, RelayConfig};
use ferrite_core::error::FeriteError;

fn view(state: &AppState) -> Value {
    let cfg = state.live_config.read().relay.clone();
    let running = state.inner.relay.lock();
    let status = running.as_ref().map(|r| r.client.status());
    // The box's ID: what it is to any relay, on or off.
    let id = match running.as_ref() {
        Some(r) => Some(r.client.id().to_string()),
        None => state.relay_identity().ok().map(|i| i.id),
    };
    json!({
        "config": cfg,
        "id": id,
        "status": status,
    })
}

/// GET /api/relay
pub async fn get_relay(State(state): State<AppState>) -> Json<Value> {
    Json(view(&state))
}

fn validate(cfg: &RelayConfig) -> Result<(), String> {
    if !cfg.enabled {
        return Ok(());
    }
    let (host, port) = cfg
        .server
        .rsplit_once(':')
        .ok_or("the relay's address is host:port")?;
    if host.trim_matches(['[', ']']).is_empty() || port.parse::<u16>().is_err() {
        return Err(format!("{} isn't host:port", cfg.server));
    }
    if ferrite_edge::identity::parse_pin(&cfg.pin).is_none() {
        return Err(
            "the pin is sha256: and 64 hex characters — `ferrite-relay pin` prints it".into(),
        );
    }
    Ok(())
}

/// PUT /api/relay — saved and applied at once.
pub async fn put_relay(
    State(state): State<AppState>,
    Json(mut cfg): Json<RelayConfig>,
) -> Result<Json<Value>, ApiError> {
    cfg.server = cfg.server.trim().to_string();
    cfg.pin = cfg.pin.trim().to_ascii_lowercase();
    validate(&cfg).map_err(|e| ApiError(FeriteError::Config(e)))?;
    state.live_config.write().relay = cfg;
    state.persist_config().await;
    state
        .apply_relay()
        .map_err(|e| ApiError(FeriteError::Config(e)))?;
    // Encrypted DNS named through the relay follows it, gone or changed.
    if state.live_config.read().secure_dns.certificate == CertSource::Relay {
        state.apply_secure_dns().await;
    }
    Ok(Json(view(&state)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    use ferrite_core::config::{CertSource, CustomRecordConfig, SecureDnsConfig};
    use ferrite_edge::identity::Identity;
    use ferrite_edge::proto::{self, Control, Opening};

    #[test]
    fn a_relay_needs_an_address_and_a_pin() {
        let pin = Identity::ephemeral("r").unwrap().pin();
        let on = |server: &str, pin: &str| RelayConfig {
            enabled: true,
            server: server.into(),
            pin: pin.into(),
        };
        assert_eq!(validate(&on("relay.example:4433", &pin)), Ok(()));
        assert_eq!(validate(&on("[2001:db8::1]:4433", &pin)), Ok(()));
        assert!(validate(&on("relay.example", &pin)).is_err());
        assert!(validate(&on("relay.example:4433", "nope")).is_err());
        assert_eq!(validate(&RelayConfig::default()), Ok(()));
    }

    /// The box connects out to a relay, and a device's DNS over HTTPS query
    /// the relay passes on is answered here — knowing the device by the
    /// address the relay saw, away from home.
    #[tokio::test]
    async fn queries_a_relay_passes_on_are_answered_as_the_device() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("relay").await;
        state
            .inner
            .custom_records
            .add(&CustomRecordConfig {
                domain: "home.test".into(),
                record_type: "A".into(),
                value: "10.0.0.7".into(),
                ttl: 60,
            })
            .unwrap();
        let mut log = state.query_rx.lock().take().unwrap();
        // Encrypted DNS on, on ports of its own: the relay doesn't need them.
        let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../secure/testdata");
        let free = || {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        };
        state.live_config.write().secure_dns = SecureDnsConfig {
            enabled: true,
            hostname: "dns.test".into(),
            certificate: CertSource::Files,
            cert_file: Some(testdata.join("cert.pem")),
            key_file: Some(testdata.join("key.pem")),
            dot_port: free(),
            doh_port: free(),
            http3: false,
            devices: vec!["phone".into()],
            ..SecureDnsConfig::default()
        };
        state.apply_secure_dns().await;

        // A relay, as small as it gets.
        let relay_id = Identity::ephemeral("relay").unwrap();
        let pin = relay_id.pin();
        let endpoint = quinn::Endpoint::server(
            ferrite_edge::tls::relay_config(&relay_id).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let relay_addr = endpoint.local_addr().unwrap();

        let Json(v) = put_relay(
            State(state.clone()),
            Json(RelayConfig {
                enabled: true,
                server: relay_addr.to_string(),
                pin,
            }),
        )
        .await
        .unwrap();
        let id = v["id"].as_str().unwrap().to_string();

        let conn = endpoint.accept().await.unwrap().await.unwrap();
        assert_eq!(
            ferrite_edge::tls::box_id(&conn).as_deref(),
            Some(id.as_str())
        );
        let (mut control, recv) = conn.accept_bi().await.unwrap();
        let mut recv = BufReader::new(recv);
        assert!(matches!(
            proto::recv(&mut recv).await.unwrap(),
            Some(Control::Hello { .. })
        ));
        proto::send(
            &mut control,
            &Control::Welcome {
                id: id.clone(),
                name: format!("{id}.r.test"),
                names: vec![],
                dns: false,
            },
        )
        .await
        .unwrap();
        for _ in 0..50 {
            if state
                .inner
                .relay
                .lock()
                .as_ref()
                .is_some_and(|r| r.client.status().connected)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let Json(v) = get_relay(State(state.clone())).await;
        assert_eq!(v["status"]["connected"], true, "{v}");

        // A device away from home, by way of the relay: TLS and a DoH query
        // over the stream the relay opens.
        let device: SocketAddr = "198.51.100.9:40000".parse().unwrap();
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(
            &Opening {
                port: 443,
                from: device,
            }
            .encode(),
        )
        .await
        .unwrap();
        let stream = tokio::io::join(recv, send);
        let mut cfg = tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::companions::AnyAnswer))
        .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(
                tokio_rustls::rustls::pki_types::ServerName::try_from("dns.test").unwrap(),
                stream,
            )
            .await
            .unwrap();
        // home.test A, as phone.
        let q: [u8; 27] = [
            0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'h', b'o', b'm', b'e', 4, b't', b'e', b's',
            b't', 0, 0, 1, 0, 1,
        ];
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(q);
        tls.write_all(
            format!("GET /dns-query/phone?dns={b64} HTTP/1.1\r\nHost: dns.test\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        assert_eq!(&response[response.len() - 4..], &[10, 0, 0, 7]);
        let entry = log.recv().await.unwrap();
        assert_eq!(
            (entry.client_ip.as_str(), entry.device.as_str()),
            ("198.51.100.9", "id:phone")
        );

        // Off: the connection goes.
        let Json(v) = put_relay(State(state.clone()), Json(RelayConfig::default()))
            .await
            .unwrap();
        assert!(v["status"].is_null(), "{v}");

        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }
}
