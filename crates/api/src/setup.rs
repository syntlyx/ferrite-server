//! `/api/setup` — a device at home sets itself up for encrypted DNS, without
//! the panel's password. Who may is `[secure_dns] self_setup`: nobody
//! (`off`), devices named in Clients (`named`, the default) or any device at
//! home (`anyone`). One that does is added to the devices answered away from
//! home under its own name, and the webhook is told — it can be removed in
//! the panel like any other.
//!
//! Only from home: from outside these answer nothing but that. A POST takes
//! a JSON body, so another site the device has open can't make it from the
//! device's browser (a cross-site JSON request needs CORS, which isn't given).

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{Value, json};

use ferrite_app::AppState;
use ferrite_core::config::{SecureDnsConfig, SelfSetup};
use ferrite_core::net::{format_mac, is_local, parse_ip, parse_mac, unmap_v4};

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

/// The device asking, as far as the box knows it.
struct Asker {
    ip: IpAddr,
    mac: Option<String>,
    /// Its name in Clients, given by you.
    alias: Option<String>,
    /// What it calls itself (DHCP, mDNS, PTR), when it isn't named.
    seen_as: Option<String>,
}

async fn who(state: &AppState, ip: IpAddr) -> Asker {
    let registry = &state.inner.client_registry;
    let mut mac = registry.get_mac(ip);
    if mac.is_none() {
        // Not asked anything yet, or not lately: the neighbour table knows.
        mac = ferrite_clients::scan_neighbors()
            .await
            .into_iter()
            .find(|(i, _)| unmap_v4(*i) == ip)
            .map(|(_, m)| format_mac(&m));
    }
    let alias = {
        let cfg = state.live_config.read();
        cfg.client_aliases
            .iter()
            .find(|a| {
                a.ip.as_deref().and_then(parse_ip) == Some(ip)
                    || (mac.is_some()
                        && a.mac.as_deref().and_then(parse_mac).map(|m| format_mac(&m)) == mac)
            })
            .map(|a| a.name.clone())
    };
    let seen_as = registry.get_name(ip).filter(|n| Some(n) != alias.as_ref());
    Asker {
        ip,
        mac,
        alias,
        seen_as,
    }
}

/// A device name — one DNS label — made from a person's name for it:
/// "Телефон мами" → `telefon-mamy`, "iPhone Alex" → `iphone-alex`.
pub(crate) fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.to_lowercase().chars() {
        let latin: &str = match c {
            'a'..='z' | '0'..='9' => {
                out.push(c);
                continue;
            }
            'а' => "a",
            'б' => "b",
            'в' => "v",
            'г' => "h",
            'ґ' => "g",
            'д' => "d",
            'е' | 'э' => "e",
            'є' => "ye",
            'ё' => "yo",
            'ж' => "zh",
            'з' => "z",
            'и' | 'ы' => "y",
            'і' => "i",
            'ї' => "yi",
            'й' => "y",
            'к' => "k",
            'л' | 'ł' => "l",
            'м' => "m",
            'н' | 'ñ' | 'ń' => "n",
            'о' | 'ó' | 'ö' | 'ô' => "o",
            'п' => "p",
            'р' => "r",
            'с' | 'ś' | 'š' => "s",
            'т' => "t",
            'у' | 'ü' | 'ú' | 'ù' => "u",
            'ф' => "f",
            'х' => "kh",
            'ц' => "ts",
            'ч' | 'č' => "ch",
            'ш' => "sh",
            'щ' => "shch",
            'ю' => "yu",
            'я' => "ya",
            'ä' | 'á' | 'à' | 'â' | 'ą' => "a",
            'é' | 'è' | 'ê' | 'ę' | 'ë' => "e",
            'ç' | 'ć' => "c",
            'ź' | 'ż' | 'ž' => "z",
            'ß' => "ss",
            'ь' | 'ъ' | '\'' | '’' | 'ʼ' => continue,
            _ => "-",
        };
        out.push_str(latin);
    }
    let mut label = String::new();
    for part in out.split('-').filter(|p| !p.is_empty()) {
        if !label.is_empty() {
            label.push('-');
        }
        label.push_str(part);
    }
    label.truncate(40);
    let label = label.trim_end_matches('-').to_string();
    ferrite_core::net::normalize_client_id(&label).unwrap_or_else(|| "device".into())
}

/// The device this name already has: `slug` itself, or `slug-` and four
/// letters or digits.
fn existing(devices: &[String], slug: &str) -> Option<String> {
    devices
        .iter()
        .find(|d| {
            d.as_str() == slug
                || d.strip_prefix(slug)
                    .and_then(|rest| rest.strip_prefix('-'))
                    .is_some_and(|tail| {
                        tail.len() == 4
                            && tail
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    })
        })
        .cloned()
}

/// Four letters or digits, so the name can't be guessed from the outside:
/// the box's own name is public, the devices' names are the key.
fn suffix() -> String {
    use ring::rand::SecureRandom;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 4];
    let _ = ring::rand::SystemRandom::new().fill(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

/// The name `name` (a client's, from Clients) goes by in encrypted DNS: the
/// one it was given before, or — with `make` — a new one, saved and applied
/// at once. `(id, made now)`.
pub(crate) async fn device_for(state: &AppState, name: &str, make: bool) -> Option<(String, bool)> {
    let base = slug(name);
    // Looked up and added under one lock: two taps make one device.
    let found = {
        let mut live = state.live_config.write();
        let devices = &mut live.secure_dns.devices;
        match existing(devices, &base) {
            Some(id) => Some((id, false)),
            None if make => {
                let id = format!("{base}-{}", suffix());
                devices.push(id.clone());
                Some((id, true))
            }
            None => None,
        }
    };
    if let Some((_, true)) = &found {
        state.persist_config().await;
        state.apply_secure_dns().await;
    }
    found
}

/// What a device is told to type in, for `id`.
pub(crate) fn how(cfg: &SecureDnsConfig, id: &str) -> Value {
    let host = &cfg.hostname;
    json!({
        // Android's Private DNS takes a name only, so it needs 853.
        "android": (cfg.dot_port == 853).then(|| format!("{id}.{host}")),
        "doh_url": (cfg.doh_port != 0).then(|| if cfg.doh_port == 443 {
            format!("https://{host}/dns-query/{id}")
        } else {
            format!("https://{host}:{}/dns-query/{id}", cfg.doh_port)
        }),
    })
}

/// The device asking and the mode, or why it can't: `away`, `off` (no
/// encrypted DNS yet) or `closed` (self-setup is off).
async fn judge(state: &AppState, peer: &Peer) -> Result<(Asker, SelfSetup), &'static str> {
    let ip = peer
        .as_ref()
        .map(|Extension(ConnectInfo(a))| unmap_v4(a.ip()));
    let Some(ip) = ip.filter(|ip| is_local(*ip)) else {
        return Err("away");
    };
    let (mode, ready) = {
        let cfg = &state.live_config.read().secure_dns;
        (
            cfg.self_setup,
            cfg.enabled && !cfg.hostname.is_empty() && (cfg.dot_port != 0 || cfg.doh_port != 0),
        )
    };
    if !ready {
        return Err("off");
    }
    if mode == SelfSetup::Off {
        return Err("closed");
    }
    Ok((who(state, ip).await, mode))
}

/// GET /api/setup — what this device may do here.
pub async fn view(State(state): State<AppState>, peer: Peer) -> Response {
    let (asker, mode) = match judge(&state, &peer).await {
        Ok(found) => found,
        Err("away") => {
            return (StatusCode::FORBIDDEN, Json(json!({ "state": "away" }))).into_response();
        }
        Err(why) => return Json(json!({ "state": why })).into_response(),
    };
    let ip = asker.ip.to_string();
    if mode == SelfSetup::Named && asker.alias.is_none() {
        return Json(json!({ "state": "unnamed", "ip": ip, "mac": asker.mac })).into_response();
    }
    let cfg = state.live_config.read().secure_dns.clone();
    let name = asker.alias.clone().or(asker.seen_as.clone());
    let id = name
        .as_deref()
        .and_then(|n| existing(&cfg.devices, &slug(n)));
    Json(json!({
        "state": "ready",
        "mode": mode,
        "named": asker.alias.is_some(),
        "name": name,
        "ip": ip,
        "mac": asker.mac,
        "id": id,
        "hostname": cfg.hostname,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
pub struct Claim {
    /// What to call it, when it has no name in Clients (`anyone` only).
    #[serde(default)]
    name: Option<String>,
}

/// POST /api/setup — set this device up: its device name (made now, or the
/// one it was given before), what to type in, and a link to the profile for
/// an iPhone, iPad or Mac.
pub async fn claim(State(state): State<AppState>, peer: Peer, Json(req): Json<Claim>) -> Response {
    let refuse = |status: StatusCode, why: &str| {
        (status, Json(json!({ "error": why, "state": why }))).into_response()
    };
    let (asker, mode) = match judge(&state, &peer).await {
        Ok(found) => found,
        Err("away") => return refuse(StatusCode::FORBIDDEN, "away"),
        Err(why) => return refuse(StatusCode::CONFLICT, why),
    };
    let name = match (&asker.alias, mode) {
        (Some(alias), _) => alias.clone(),
        (None, SelfSetup::Anyone) => req
            .name
            .map(|n| n.trim().chars().take(64).collect::<String>())
            .filter(|n| !n.is_empty())
            .or(asker.seen_as.clone())
            .unwrap_or_else(|| "device".into()),
        (None, _) => return refuse(StatusCode::FORBIDDEN, "unnamed"),
    };
    let Some((id, made)) = device_for(&state, &name, true).await else {
        return refuse(StatusCode::CONFLICT, "off");
    };
    if made {
        tracing::info!("secure dns: {name} ({}) set itself up as {id}", asker.ip);
        announce(&state, &id, &name, &asker);
    }
    let cfg = state.live_config.read().secure_dns.clone();
    let profile = ferrite_secure::SecureDns::profile(&cfg, &id)
        .is_some()
        .then(|| {
            format!(
                "/api/secure-dns/profile/{}",
                state.inner.secure_dns.profile_link(&id)
            )
        });
    let mut out = how(&cfg, &id);
    out["id"] = json!(id);
    out["name"] = json!(name);
    out["new"] = json!(made);
    out["profile_url"] = json!(profile);
    Json(out).into_response()
}

/// Tell the webhook, when there is one: a device now answered from the
/// internet is worth knowing about.
fn announce(state: &AppState, id: &str, name: &str, asker: &Asker) {
    use ferrite_core::notify;
    let Some(target) = notify::Target::from_config(&state.live_config.read().notifications) else {
        return;
    };
    let at = match &asker.mac {
        Some(mac) => format!("{}, {mac}", asker.ip),
        None => asker.ip.to_string(),
    };
    let message = format!(
        "{name} ({at}) set itself up for encrypted DNS as {id} and is answered away from home now. \
         Remove it under Settings → Encrypted DNS if it shouldn't be."
    );
    let notice = notify::Notice {
        title: format!("Encrypted DNS: {name}"),
        message: message.clone(),
        level: notify::Level::Info,
        tags: &["lock"],
        event: json!({
            "event": "secure_dns_device",
            "device": id,
            "name": name,
            "ip": asker.ip.to_string(),
            "mac": asker.mac,
            "message": message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }),
    };
    tokio::spawn(async move {
        if let Err(e) = notify::send(&notify::client(), &target, &notice).await {
            tracing::warn!("encrypted DNS self-setup webhook: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrite_core::config::{CertSource, ClientAliasConfig};

    fn from(ip: &str) -> Peer {
        Some(Extension(ConnectInfo(SocketAddr::new(
            ip.parse().unwrap(),
            50_000,
        ))))
    }

    async fn body(r: Response) -> (StatusCode, Value) {
        let status = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn devices_at_home_set_themselves_up() {
        let (state, db, config_path) =
            ferrite_app::test_support::app_state_with_config_path("self-setup").await;
        let at = |ip: &str| from(ip);

        // Nothing to set up yet.
        let (_, v) = body(view(State(state.clone()), at("192.168.1.50")).await).await;
        assert_eq!(v["state"], "off");

        let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../secure/testdata");
        {
            let mut live = state.live_config.write();
            live.secure_dns = SecureDnsConfig {
                enabled: true,
                hostname: "dns.test".into(),
                certificate: CertSource::Files,
                cert_file: Some(testdata.join("cert.pem")),
                key_file: Some(testdata.join("key.pem")),
                dot_port: free_port(),
                doh_port: free_port(),
                ..SecureDnsConfig::default()
            };
            live.client_aliases.push(ClientAliasConfig {
                ip: Some("192.168.1.50".into()),
                mac: None,
                name: "Телефон мами".into(),
            });
        }
        state.apply_secure_dns().await;

        // From outside: nothing but that.
        let (status, v) = body(view(State(state.clone()), at("198.51.100.7")).await).await;
        assert_eq!(
            (status, v),
            (StatusCode::FORBIDDEN, json!({ "state": "away" }))
        );
        let r = claim(
            State(state.clone()),
            at("198.51.100.7"),
            Json(Claim::default()),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        // A named device at home: set up under its own name, once.
        let (_, v) = body(view(State(state.clone()), at("192.168.1.50")).await).await;
        assert_eq!(v["state"], "ready", "{v}");
        assert_eq!(v["name"], "Телефон мами");
        assert!(v["id"].is_null());
        let (status, first) = body(
            claim(
                State(state.clone()),
                at("192.168.1.50"),
                Json(Claim::default()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let id = first["id"].as_str().unwrap().to_string();
        assert!(id.starts_with("telefon-mamy-"), "{id}");
        assert_eq!(first["new"], true);
        assert_eq!(
            first["doh_url"],
            format!("https://dns.test:{}/dns-query/{id}", {
                state.live_config.read().secure_dns.doh_port
            })
        );
        assert!(
            first["profile_url"]
                .as_str()
                .unwrap()
                .starts_with("/api/secure-dns/profile/")
        );
        assert!(state.live_config.read().secure_dns.devices.contains(&id));
        let (_, again) = body(
            claim(
                State(state.clone()),
                at("192.168.1.50"),
                Json(Claim::default()),
            )
            .await,
        )
        .await;
        assert_eq!(
            (again["id"].as_str(), again["new"].as_bool()),
            (Some(id.as_str()), Some(false))
        );
        let (_, v) = body(view(State(state.clone()), at("192.168.1.50")).await).await;
        assert_eq!(v["id"], id.as_str());

        // A device you haven't named: told to ask, and can't.
        let (_, v) = body(view(State(state.clone()), at("192.168.1.51")).await).await;
        assert_eq!(v["state"], "unnamed");
        assert_eq!(v["ip"], "192.168.1.51");
        let r = claim(
            State(state.clone()),
            at("192.168.1.51"),
            Json(Claim {
                name: Some("guest".into()),
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        // Anyone at home: it says what to call it.
        state.live_config.write().secure_dns.self_setup = SelfSetup::Anyone;
        let (_, v) = body(
            claim(
                State(state.clone()),
                at("192.168.1.51"),
                Json(Claim {
                    name: Some("Гість".into()),
                }),
            )
            .await,
        )
        .await;
        assert!(v["id"].as_str().unwrap().starts_with("hist-"), "{v}");

        // The panel finds the same device by the client's name, and makes
        // one for a client that hasn't any.
        let Json(v) = crate::secure_dns::device(
            State(state.clone()),
            axum::extract::Query(
                serde_json::from_value(json!({ "name": "Телефон мами" })).unwrap(),
            ),
        )
        .await;
        assert_eq!(v["id"], id.as_str());
        let Json(v) = crate::secure_dns::make_device(
            State(state.clone()),
            Json(serde_json::from_value(json!({ "name": "Pixel 8" })).unwrap()),
        )
        .await
        .unwrap();
        assert!(v["id"].as_str().unwrap().starts_with("pixel-8-"), "{v}");
        assert_eq!(v["new"], true);

        // Off: nobody.
        state.live_config.write().secure_dns.self_setup = SelfSetup::Off;
        let (_, v) = body(view(State(state.clone()), at("192.168.1.50")).await).await;
        assert_eq!(v["state"], "closed");

        ferrite_app::test_support::cleanup_sqlite(&db);
        let _ = std::fs::remove_file(&config_path);
    }

    #[test]
    fn names_become_device_names() {
        assert_eq!(slug("iPhone Alex"), "iphone-alex");
        assert_eq!(slug("Телефон мами"), "telefon-mamy");
        assert_eq!(slug("Їжачок  Юрко"), "yizhachok-yurko");
        assert_eq!(slug("Jürgen's iPad"), "jurgens-ipad");
        assert_eq!(slug("---"), "device");
        assert_eq!(slug("❤️"), "device");
        assert!(slug(&"a".repeat(100)).len() <= 40);
    }

    #[test]
    fn a_device_keeps_the_name_it_was_given() {
        let devices = vec!["pixel".to_string(), "iphone-alex-k7f3".to_string()];
        assert_eq!(
            existing(&devices, "iphone-alex").as_deref(),
            Some("iphone-alex-k7f3")
        );
        assert_eq!(existing(&devices, "pixel").as_deref(), Some("pixel"));
        assert_eq!(existing(&devices, "iphone"), None);
        assert_eq!(
            existing(&["iphone-alex-old-k7f3".into()], "iphone-alex"),
            None
        );
        let s = suffix();
        assert_eq!(s.len(), 4);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }
}
