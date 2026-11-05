//! Certificates from Let's Encrypt, proven over DNS (DNS-01): the challenge
//! goes into a TXT record — through the DNS provider's API, waiting until
//! the zone's own name servers answer with it, or handed to the relay whose
//! zone the name is in, which answers it at once — and then ferrite asks
//! for the certificate for the name and `*.name`. No port has to be open
//! for this, and a wildcard — client IDs over TLS — can only be had this way.
//!
//! What it keeps, in its own directory (one for production, another for
//! staging): the Let's Encrypt account, and per name the certificate chain
//! and its key.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, Order, OrderStatus, Problem, RetryPolicy,
};

use ferrite_core::config::AcmeConfig;

use crate::cloudflare::{Cloudflare, Zone};

/// How the name is proven: who puts the challenge in DNS.
pub(crate) enum Proof {
    /// Through Cloudflare's API, with this token.
    Cloudflare(String),
    /// The relay the box is connected to, which answers its zone's DNS.
    Relay(Arc<ferrite_edge::client::Client>),
}

/// How long the TXT record may take to reach the zone's name servers.
const PROPAGATION: Duration = Duration::from_secs(180);

/// Where the certificate for `hostname` is kept.
pub(crate) fn files(dir: &Path, hostname: &str) -> (PathBuf, PathBuf) {
    let d = dir.join(hostname);
    (d.join("cert.pem"), d.join("key.pem"))
}

fn problem(p: &Problem) -> String {
    let mut s = p
        .detail
        .clone()
        .unwrap_or_else(|| p.r#type.clone().unwrap_or_else(|| "no reason given".into()));
    for sub in &p.subproblems {
        if let Some(d) = &sub.detail {
            s.push_str("; ");
            s.push_str(d);
        }
    }
    s
}

fn acme_err(e: instant_acme::Error) -> String {
    match e {
        instant_acme::Error::Api(p) => format!("Let's Encrypt: {}", problem(&p)),
        instant_acme::Error::Timeout(_) => "Let's Encrypt took too long to answer".into(),
        other => format!("Let's Encrypt: {other}"),
    }
}

/// Write a file other users can't read, whole or not at all.
fn write_private(path: &Path, contents: &str) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("couldn't create {}: {e}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| format!("couldn't write {}: {e}", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("couldn't write {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("couldn't write {}: {e}", path.display()))
}

/// The account, made on first use and kept.
async fn account(dir: &Path, cfg: &AcmeConfig) -> Result<Account, String> {
    let url = if cfg.staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };
    let file = dir.join("account.json");
    if let Ok(saved) = std::fs::read_to_string(&file)
        && let Ok(credentials) = serde_json::from_str::<AccountCredentials>(&saved)
    {
        match Account::builder()
            .map_err(acme_err)?
            .from_credentials(credentials)
            .await
        {
            Ok(account) => return Ok(account),
            Err(e) => tracing::warn!("acme: the saved account didn't load ({e}), making a new one"),
        }
    }
    let contact = (!cfg.email.trim().is_empty()).then(|| format!("mailto:{}", cfg.email.trim()));
    let contacts: Vec<&str> = contact.as_deref().into_iter().collect();
    let (account, credentials) = Account::builder()
        .map_err(acme_err)?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url.to_owned(),
            None,
        )
        .await
        .map_err(acme_err)?;
    let json = serde_json::to_string_pretty(&credentials).map_err(|e| e.to_string())?;
    write_private(&file, &json)?;
    Ok(account)
}

/// Get a certificate for `hostname` and `*.hostname` and keep it in `dir`.
/// `step` hears what it is doing, for the panel.
pub(crate) async fn issue(
    dir: &Path,
    hostname: &str,
    cfg: &AcmeConfig,
    proof: &Proof,
    step: &(dyn Fn(&'static str) + Send + Sync),
) -> Result<(), String> {
    // What proving the name takes is checked before Let's Encrypt is asked
    // anything: its failed attempts count against a limit.
    let cloudflare = match proof {
        Proof::Cloudflare(token) => {
            let token = token.trim();
            if token.is_empty() {
                return Err("set a Cloudflare API token".into());
            }
            let cf = Cloudflare::new(token);
            step("finding the zone");
            let zone = cf.zone_for(hostname).await?;
            Some((cf, zone))
        }
        Proof::Relay(client) => {
            let st = client.status();
            if !st.connected {
                return Err("not connected to the relay".into());
            }
            if !st.dns {
                return Err("the relay doesn't answer its zone's DNS".into());
            }
            None
        }
    };
    step("opening the request");
    let account = account(dir, cfg).await?;
    let names = [
        Identifier::Dns(hostname.to_string()),
        Identifier::Dns(format!("*.{hostname}")),
    ];
    let mut order = account
        .new_order(&NewOrder::new(&names))
        .await
        .map_err(acme_err)?;

    // Both names are proven on the same record: one TXT value each.
    let record = format!("_acme-challenge.{hostname}");
    let mut values = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.map_err(acme_err)?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => return Err(format!("Let's Encrypt says the name is {other:?}")),
            }
            let challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or("Let's Encrypt offered no DNS challenge")?;
            values.push(challenge.key_authorization().dns_value());
        }
    }

    let mut added = Vec::new();
    let mut published = false;
    let outcome = async {
        if !values.is_empty() {
            match (&cloudflare, proof) {
                (Some((cf, zone)), _) => {
                    step("adding the TXT record");
                    for id in cf.leftovers(zone, &record).await.unwrap_or_default() {
                        let _ = cf.delete(zone, &id).await;
                    }
                    for value in &values {
                        added.push(cf.add_txt(zone, &record, value).await?);
                    }
                    step("waiting for the record to show up");
                    visible(zone, &record, &values).await?;
                }
                (None, Proof::Relay(client)) => {
                    // The relay is the zone's name server: answered as
                    // soon as it says so.
                    step("handing the challenge to the relay");
                    client.publish(values.clone()).await?;
                    published = true;
                }
                (None, Proof::Cloudflare(_)) => unreachable!("checked above"),
            }
            let mut authorizations = order.authorizations();
            while let Some(authz) = authorizations.next().await {
                let mut authz = authz.map_err(acme_err)?;
                if authz.status != AuthorizationStatus::Pending {
                    continue;
                }
                if let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) {
                    challenge.set_ready().await.map_err(acme_err)?;
                }
            }
        }
        step("waiting for Let's Encrypt to check");
        let status = order
            .poll_ready(&RetryPolicy::new().timeout(Duration::from_secs(120)))
            .await
            .map_err(acme_err)?;
        if status != OrderStatus::Ready {
            return Err(why_not(&mut order).await);
        }
        step("getting the certificate");
        let key = order.finalize().await.map_err(acme_err)?;
        let chain = order
            .poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(90)))
            .await
            .map_err(acme_err)?;
        Ok::<_, String>((chain, key))
    }
    .await;

    if let Some((cf, zone)) = &cloudflare {
        for id in added {
            if let Err(e) = cf.delete(zone, &id).await {
                tracing::warn!("acme: couldn't remove the challenge record from {record}: {e}");
            }
        }
    }
    if published
        && let Proof::Relay(client) = proof
        && let Err(e) = client.publish(Vec::new()).await
    {
        tracing::warn!("acme: the relay still answers the challenge: {e}");
    }
    let (chain, key) = outcome?;
    let (cert_file, key_file) = files(dir, hostname);
    write_private(&key_file, &key)?;
    write_private(&cert_file, &chain)?;
    Ok(())
}

/// Why Let's Encrypt turned the order down, from the challenge that failed.
async fn why_not(order: &mut Order) -> String {
    if let Some(p) = &order.state().error {
        return format!("Let's Encrypt: {}", problem(p));
    }
    let mut authorizations = order.authorizations();
    while let Some(Ok(mut authz)) = authorizations.next().await {
        if let Ok(state) = authz.refresh().await
            && let Some(p) = state.challenges.iter().find_map(|c| c.error.as_ref())
        {
            return format!("Let's Encrypt couldn't verify the name: {}", problem(p));
        }
    }
    "Let's Encrypt turned the request down".into()
}

/// Wait until every name server of the zone answers `name` with all of
/// `want`: Let's Encrypt asks them, not a cache.
async fn visible(zone: &Zone, name: &str, want: &[String]) -> Result<(), String> {
    let mut servers = Vec::new();
    for ns in &zone.name_servers {
        if let Ok(mut addrs) = tokio::net::lookup_host((ns.as_str(), 53)).await
            && let Some(addr) = addrs.find(SocketAddr::is_ipv4)
        {
            servers.push(addr);
        }
    }
    if servers.is_empty() {
        // Can't ask them directly: give the record time to spread instead.
        tokio::time::sleep(Duration::from_secs(30)).await;
        return Ok(());
    }
    let deadline = Instant::now() + PROPAGATION;
    loop {
        let mut everywhere = true;
        for server in &servers {
            let got = txt(*server, name).await.unwrap_or_default();
            if !want.iter().all(|w| got.contains(w)) {
                everywhere = false;
                break;
            }
        }
        if everywhere {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "the TXT record didn't reach {}'s name servers in {} minutes",
                zone.name,
                PROPAGATION.as_secs() / 60
            ));
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// The TXT strings `server` has for `name`.
async fn txt(server: SocketAddr, name: &str) -> Result<Vec<String>, String> {
    let qname = Name::from_str(&format!("{name}.")).map_err(|e| e.to_string())?;
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(1);
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(qname, RecordType::TXT));
    let raw = msg.to_bytes().map_err(|e| e.to_string())?;
    let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| e.to_string())?;
    sock.send_to(&raw, server)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .map_err(|_| "no answer".to_string())?
        .map_err(|e| e.to_string())?;
    let rsp = Message::from_bytes(&buf[..n]).map_err(|e| e.to_string())?;
    if rsp.metadata.id != id {
        return Err("an answer to something else".into());
    }
    Ok(rsp
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::TXT(t) => Some(
                t.txt_data
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_kept_per_name_and_private() {
        let dir = std::env::temp_dir().join(format!("ferrite-acme-{}", std::process::id()));
        let (cert, key) = files(&dir, "dns.example.com");
        assert_eq!(cert, dir.join("dns.example.com/cert.pem"));
        write_private(&key, "secret").unwrap();
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Talks to Let's Encrypt's staging service: an account is made and an
    /// order for a name that can't exist is turned down by name — which
    /// takes working TLS, signing and nonces to get to.
    /// `cargo test -p ferrite-secure -- --ignored`
    #[tokio::test]
    #[ignore = "network: Let's Encrypt staging"]
    async fn lets_encrypt_staging_answers() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("ferrite-acme-le-{}", std::process::id()));
        let cfg = AcmeConfig {
            staging: true,
            ..AcmeConfig::default()
        };
        let made = account(&dir, &cfg).await.unwrap();
        assert!(dir.join("account.json").exists());
        let names = [Identifier::Dns("nothing.invalid".into())];
        let Err(err) = made
            .new_order(&NewOrder::new(&names))
            .await
            .map_err(acme_err)
        else {
            panic!("an order for a name that can't exist");
        };
        assert!(err.contains("Let's Encrypt"), "{err}");
        eprintln!("{err}");
        // The saved account loads again.
        account(&dir, &cfg).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
