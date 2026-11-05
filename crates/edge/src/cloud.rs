//! How a box speaks for itself to the ferrite cloud: with the key it already
//! has for relays (`identity`), so its ID there is the same as on a relay.
//!
//! Every request a box makes is one the cloud first hands a nonce for. The box
//! signs the nonce, what the request is for (its action) and the request
//! itself, exactly as sent, so a signature is good once, for that one thing.
//! The cloud works the box's ID out of the key the signature checks with,
//! never from anything the box merely says.

use std::io;

use data_encoding::BASE64URL_NOPAD;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::identity::{Identity, id_of};

/// What a signature is made over starts with this, so one made here can't be
/// passed off as anything else the key signs.
const CONTEXT: &str = "ferrite-cloud-v1";

/// The cloud's answer to "a nonce, please".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub nonce: String,
}

/// A box's request, signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed {
    /// The box's public key (SubjectPublicKeyInfo, DER), base64url.
    pub key: String,
    pub nonce: String,
    /// The request itself, JSON, signed as this very text: nothing has to be
    /// put back into the same form to check it.
    pub body: String,
    /// ECDSA P-256 SHA-256 over `message(action, nonce, body)`, base64url.
    pub sig: String,
}

/// A signature that checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The box's ID, worked out from its key.
    pub id: String,
    /// Its public key, DER.
    pub key: Vec<u8>,
}

fn message(action: &str, nonce: &str, body: &str) -> Vec<u8> {
    format!("{CONTEXT}\n{action}\n{nonce}\n{body}").into_bytes()
}

fn bad(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// `body` signed by the box for `action`, with the cloud's `nonce`.
pub fn sign(
    identity: &Identity,
    action: &str,
    nonce: &str,
    body: &impl Serialize,
) -> io::Result<Signed> {
    let body = serde_json::to_string(body).map_err(bad)?;
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        identity.key.secret_der(),
        &rng,
    )
    .map_err(bad)?;
    let sig = key
        .sign(&rng, &message(action, nonce, &body))
        .map_err(bad)?;
    let public = crate::identity::public_key_of(&identity.cert)
        .ok_or_else(|| bad("the box's certificate has no key"))?;
    Ok(Signed {
        key: BASE64URL_NOPAD.encode(&public),
        nonce: nonce.to_string(),
        body,
        sig: BASE64URL_NOPAD.encode(sig.as_ref()),
    })
}

/// Whose `signed` is, if its signature is good for `action`. Whether its nonce
/// is one the cloud handed out, and unused, is for the cloud to know.
pub fn verify(signed: &Signed, action: &str) -> Result<Verified, &'static str> {
    let key = BASE64URL_NOPAD
        .decode(signed.key.as_bytes())
        .map_err(|_| "the key isn't base64url")?;
    let sig = BASE64URL_NOPAD
        .decode(signed.sig.as_bytes())
        .map_err(|_| "the signature isn't base64url")?;
    let point = p256_point(&key).ok_or("not a P-256 public key")?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&message(action, &signed.nonce, &signed.body), &sig)
        .map_err(|_| "the signature doesn't match")?;
    Ok(Verified {
        id: id_of(&key),
        key,
    })
}

/// The curve point in a P-256 SubjectPublicKeyInfo, and nothing else: a key
/// of another kind, or bytes trailing it, isn't one.
fn p256_point(spki: &[u8]) -> Option<&[u8]> {
    let (rest, info) = SubjectPublicKeyInfo::from_der(spki).ok()?;
    if !rest.is_empty() || info.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return None;
    }
    let curve = info.algorithm.parameters.as_ref()?.as_oid().ok()?;
    if curve != OID_EC_P256 {
        return None;
    }
    // Borrowed from `spki`, which outlives `info`.
    let point = info.subject_public_key.data;
    let at = spki.len().checked_sub(point.len())?;
    (spki[at..] == *point).then_some(&spki[at..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Body {
        version: &'static str,
    }

    #[test]
    fn a_signature_names_its_box_and_is_good_for_one_thing() {
        let me = Identity::ephemeral("box").unwrap();
        let signed = sign(&me, "status", "n0nce", &Body { version: "0.2.1" }).unwrap();
        let ok = verify(&signed, "status").unwrap();
        assert_eq!(ok.id, me.id, "the same ID the relay knows the box by");

        assert!(verify(&signed, "link-code").is_err(), "another action");
        let mut other = signed.clone();
        other.nonce = "another".into();
        assert!(verify(&other, "status").is_err(), "another nonce");
        let mut other = signed.clone();
        other.body = r#"{"version":"9.9.9"}"#.into();
        assert!(verify(&other, "status").is_err(), "another body");

        // Someone else's key with this box's signature.
        let them = Identity::ephemeral("box").unwrap();
        let mut other = signed.clone();
        other.key = sign(&them, "status", "n0nce", &Body { version: "0.2.1" })
            .unwrap()
            .key;
        assert!(verify(&other, "status").is_err(), "another key");
    }

    #[test]
    fn only_a_p256_key_will_do() {
        assert!(p256_point(b"").is_none());
        let me = Identity::ephemeral("box").unwrap();
        let spki = crate::identity::public_key_of(&me.cert).unwrap();
        assert_eq!(p256_point(&spki).map(<[u8]>::len), Some(65));
        let mut longer = spki.clone();
        longer.push(0);
        assert!(p256_point(&longer).is_none(), "trailing bytes");
    }
}
