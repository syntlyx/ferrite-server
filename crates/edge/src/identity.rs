//! Who a box is to the relay — and who the relay is to a box: a key made once
//! and kept, and what its public half hashes to. A box's ID is its name under
//! the relay's zone (`<id>.r.ferrite.me`), and only the box holding the key
//! can be it: the relay derives the ID from the key the box proves it holds
//! in the handshake, nothing the box merely says. The relay's own key is
//! pinned by boxes the same way.

use std::io;
use std::path::Path;

use data_encoding::BASE32_NOPAD;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use ring::digest;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A key and the self-signed certificate that carries it in a handshake.
pub struct Identity {
    /// 16 letters and digits from the key's hash: 80 bits, far too many to
    /// find another key with the same ID.
    pub id: String,
    /// The public key's SHA-256, what a pin names.
    pub key_hash: [u8; 32],
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

/// The public key (SubjectPublicKeyInfo) a DER certificate carries.
pub fn public_key_of(cert: &[u8]) -> Option<Vec<u8>> {
    x509_parser::parse_x509_certificate(cert)
        .ok()
        .map(|(_, c)| c.public_key().raw.to_vec())
}

pub fn key_hash(public_key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, public_key).as_ref());
    out
}

pub fn id_of(public_key: &[u8]) -> String {
    BASE32_NOPAD
        .encode(&key_hash(public_key)[..10])
        .to_ascii_lowercase()
}

/// Could `s` be a box's ID: 16 of base32's letters and digits, lowercase.
pub fn is_id(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// How a key is pinned: `sha256:` and its hash in hex.
pub fn pin_of(key_hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(key_hash))
}

/// A pin read back: `sha256:<64 hex>`.
pub fn parse_pin(pin: &str) -> Option<[u8; 32]> {
    let hex_part = pin.trim().strip_prefix("sha256:")?;
    let bytes = hex::decode(hex_part).ok()?;
    bytes.try_into().ok()
}

fn bad(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

impl Identity {
    /// The key in `dir/key.pem`, made there — readable by the owner only —
    /// the first time.
    pub fn load_or_create(dir: &Path, name: &str) -> io::Result<Self> {
        let path = dir.join("key.pem");
        let key = match std::fs::read_to_string(&path) {
            Ok(pem) => KeyPair::from_pem(&pem).map_err(bad)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(bad)?;
                std::fs::create_dir_all(dir)?;
                write_private(&path, key.serialize_pem().as_bytes())?;
                key
            }
            Err(e) => return Err(e),
        };
        Self::from_key(key, name)
    }

    /// A key that lives only as long as the process: tests.
    pub fn ephemeral(name: &str) -> io::Result<Self> {
        Self::from_key(
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(bad)?,
            name,
        )
    }

    fn from_key(key: KeyPair, name: &str) -> io::Result<Self> {
        let cert = CertificateParams::new(vec![name.to_string()])
            .map_err(bad)?
            .self_signed(&key)
            .map_err(bad)?;
        let cert = cert.der().clone();
        let public = public_key_of(&cert).ok_or_else(|| bad("the certificate made has no key"))?;
        Ok(Identity {
            id: id_of(&public),
            key_hash: key_hash(&public),
            cert,
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        })
    }

    pub fn pin(&self) -> String {
        pin_of(&self.key_hash)
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_its_id_wherever_it_is_read() {
        let dir = std::env::temp_dir().join(format!("ferrite-relay-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = Identity::load_or_create(&dir, "box").unwrap();
        let again = Identity::load_or_create(&dir, "box").unwrap();
        assert_eq!(first.id, again.id, "the same key, the same box");
        assert_eq!(first.id.len(), 16);
        assert!(
            first
                .id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        // What the relay works out from the certificate alone.
        assert_eq!(id_of(&public_key_of(&first.cert).unwrap()), first.id);
        assert_eq!(parse_pin(&first.pin()), Some(first.key_hash));
        assert_ne!(Identity::ephemeral("box").unwrap().id, first.id);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
