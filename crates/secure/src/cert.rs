//! The certificate the encrypted listeners present: read from PEM files,
//! swapped in place when the files change, described for the panel.

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use serde::Serialize;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

/// What the panel shows of the certificate in use.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CertInfo {
    /// The names it is valid for (subject alternative names, else the CN).
    pub names: Vec<String>,
    pub issuer: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
}

impl CertInfo {
    /// Does the certificate cover `name`, directly or by a wildcard one label up?
    pub fn covers(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.names.iter().any(|n| {
            let n = n.to_ascii_lowercase();
            n == name
                || n.strip_prefix("*.").is_some_and(|parent| {
                    name.split_once('.').is_some_and(|(_, rest)| rest == parent)
                })
        })
    }

    /// Time to get a new one: a third of its life left, as Let's Encrypt
    /// advises — 30 days of a 90-day certificate.
    pub fn due(&self, now: i64) -> bool {
        let life = (self.not_after - self.not_before).max(0);
        self.not_after - now < life / 3
    }
}

/// The certificate every handshake gets; replaced in place on reload, so the
/// listeners never stop for a renewal.
#[derive(Debug, Default)]
pub struct CertStore(ArcSwapOption<CertifiedKey>);

impl CertStore {
    pub fn set(&self, key: Arc<CertifiedKey>) {
        self.0.store(Some(key));
    }

    pub fn clear(&self) {
        self.0.store(None);
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.load_full()
    }
}

/// Read a PEM chain and its key. Errors are sentences for the panel.
pub fn load(cert: &Path, key: &Path) -> Result<(Arc<CertifiedKey>, CertInfo), String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("couldn't read {}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{} isn't a PEM certificate: {e}", cert.display()))?;
    let Some(leaf) = chain.first() else {
        return Err(format!("{} holds no certificate", cert.display()));
    };
    let info = describe(leaf)?;
    let private = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| format!("couldn't read the key in {}: {e}", key.display()))?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&private)
        .map_err(|e| format!("the key in {} can't be used: {e}", key.display()))?;
    let certified = CertifiedKey::new(chain, signer);
    if let Err(e) = certified.keys_match() {
        return Err(format!("the key doesn't belong to the certificate ({e})"));
    }
    Ok((Arc::new(certified), info))
}

fn describe(der: &CertificateDer<'_>) -> Result<CertInfo, String> {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
    let (_, x) = X509Certificate::from_der(der.as_ref())
        .map_err(|e| format!("the certificate doesn't parse: {e}"))?;
    let mut names: Vec<String> = x
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if names.is_empty()
        && let Some(cn) = x.subject().iter_common_name().next()
        && let Ok(cn) = cn.as_str()
    {
        names.push(cn.to_string());
    }
    Ok(CertInfo {
        names,
        issuer: x
            .issuer()
            .iter_organization()
            .next()
            .and_then(|o| o.as_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| x.issuer().to_string()),
        not_before: x.validity().not_before.timestamp(),
        not_after: x.validity().not_after.timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(names: &[&str]) -> CertInfo {
        CertInfo {
            names: names.iter().map(|s| s.to_string()).collect(),
            issuer: String::new(),
            not_before: 0,
            not_after: 0,
        }
    }

    #[test]
    fn wildcards_cover_one_label() {
        let c = info(&["dns.example.com", "*.dns.example.com"]);
        assert!(c.covers("dns.example.com"));
        assert!(c.covers("Pixel.dns.example.com"));
        assert!(!c.covers("a.b.dns.example.com"));
        assert!(!c.covers("example.com"));
        assert!(!info(&["*.example.com"]).covers("example.com"));
    }

    #[test]
    fn renewal_is_due_with_a_third_of_the_life_left() {
        let day = 86_400;
        let mut c = info(&["a.test"]);
        c.not_before = 0;
        c.not_after = 90 * day;
        assert!(!c.due(59 * day));
        assert!(c.due(61 * day));
        c.not_after = 45 * day;
        assert!(!c.due(29 * day));
        assert!(c.due(31 * day));
    }

    #[test]
    fn the_test_certificate_loads_and_describes_itself() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
        let (_, info) = load(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap();
        assert!(info.covers("dns.test"));
        assert!(info.covers("kid.dns.test"));
        assert!(info.not_after > 2_000_000_000);

        // An ECDSA key in SEC1 form, as `openssl ecparam -genkey` writes it.
        let (_, ec) = load(&dir.join("ec-cert.pem"), &dir.join("ec-key.pem")).unwrap();
        assert!(ec.covers("kid.dns.test"));

        let wrong = load(&dir.join("cert.pem"), &dir.join("other-key.pem"));
        assert!(wrong.unwrap_err().contains("doesn't belong"));
    }
}
