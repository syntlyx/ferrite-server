//! The TLS between a box and its relay, inside QUIC. Both sides show a
//! self-signed certificate and are known by its key alone: the relay by the
//! pin a box was given, a box by the ID its key hashes to. Each proves it
//! holds its key by signing the handshake — checked here, so a certificate
//! copied off someone else gets nobody anywhere.

use std::sync::Arc;
use std::time::Duration;

use tokio_rustls::rustls::{
    self, CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};

use crate::identity::{Identity, id_of, key_hash, public_key_of};

pub const ALPN: &[u8] = b"ferrite-relay/1";

/// A box opens nothing but its control stream; the relay opens one stream
/// per device connection, so the box lets it have many.
const STREAMS_FROM_RELAY: u32 = 4096;
/// Quiet this long and the connection is gone; the box pings well within.
const IDLE: Duration = Duration::from_secs(60);
const KEEP_ALIVE: Duration = Duration::from_secs(15);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn signature_checks(p: &CryptoProvider) -> &rustls::crypto::WebPkiSupportedAlgorithms {
    &p.signature_verification_algorithms
}

/// The relay's side: any box may come; who it is follows from its key.
#[derive(Debug)]
struct AnyBox(Arc<CryptoProvider>);

impl ClientCertVerifier for AnyBox {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, signature_checks(&self.0))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, signature_checks(&self.0))
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        signature_checks(&self.0).supported_schemes()
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// The box's side: the relay is the key it was pinned to, and nothing else.
#[derive(Debug)]
struct Pinned {
    key: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match public_key_of(end_entity) {
            Some(public) if key_hash(&public) == self.key => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, signature_checks(&self.provider))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, signature_checks(&self.provider))
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        signature_checks(&self.provider).supported_schemes()
    }
}

/// What the relay listens for boxes with.
pub fn relay_config(identity: &Identity) -> Result<quinn::ServerConfig, String> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(Arc::new(AnyBox(provider())))
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .map_err(|e| e.to_string())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(IDLE.try_into().ok());
    transport.max_concurrent_bidi_streams(8u32.into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// What a box connects to its relay with, pinned to the relay's key.
pub fn box_config(identity: &Identity, relay_key: [u8; 32]) -> Result<quinn::ClientConfig, String> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            key: relay_key,
            provider: provider(),
        }))
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .map_err(|e| e.to_string())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(IDLE.try_into().ok());
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    transport.max_concurrent_bidi_streams(STREAMS_FROM_RELAY.into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// Which box a connection is: the ID of the key it proved it holds.
pub fn box_id(conn: &quinn::Connection) -> Option<String> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    Some(id_of(&public_key_of(certs.first()?)?))
}
