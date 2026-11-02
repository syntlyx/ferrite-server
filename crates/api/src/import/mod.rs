//! `POST /api/import` — bring a Pi-hole or AdGuard Home setup over.
//!
//! The upload is a Pi-hole v6 Teleporter archive (`.zip`) or an
//! `AdGuardHome.yaml`; which one is told by its first bytes. Without `apply`
//! the answer is the plan: what would be imported, and what can't be, with
//! the reason. `?apply=lists,rules,…` then imports the chosen parts of the
//! same file. Nothing is replaced except where a part says so (`upstreams`):
//! lists, rules, records, names and profiles are added beside what is there,
//! and what already exists is left alone.
//!
//! Every part goes through the same checks as the panel — the same handlers
//! where one exists — so an import can't put anything in the config the panel
//! would refuse.

mod adguard;
mod pihole;
mod zip;

use std::collections::HashSet;
use std::net::IpAddr;

use axum::{
    Json,
    body::Bytes,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_blocklist::ListPolarity;
use ferrite_core::config::{
    BlockResponse, BlocklistProfileConfig, ClientAliasConfig, CustomRecordConfig, ListConfig,
    UpstreamConfig, YoutubeRestrict, ZoneConfig,
};
use ferrite_core::error::FeriteError;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Everything a source file says, in ferrite's terms.
#[derive(Debug, Default, Serialize)]
pub struct ImportPlan {
    /// `pihole` or `adguard`.
    pub source: &'static str,
    pub lists: Vec<ListConfig>,
    pub allowlists: Vec<ListConfig>,
    /// Manual entries: names, wildcards, `/regex/`.
    pub block: Vec<String>,
    pub allow: Vec<String>,
    pub records: Vec<CustomRecordConfig>,
    /// Device names.
    pub aliases: Vec<ClientAliasConfig>,
    pub profiles: Vec<BlocklistProfileConfig>,
    /// Devices that skip filtering.
    pub bypass: Vec<String>,
    /// Catalog services blocked network-wide.
    pub services: Vec<String>,
    pub safe_search: bool,
    pub youtube_restricted: YoutubeRestrict,
    pub block_response: Option<BlockResponse>,
    pub block_ipv4: Option<Ipv4Addr>,
    pub block_ipv6: Option<Ipv6Addr>,
    /// Queries per client per minute.
    pub rate_limit: Option<u32>,
    pub allowed_clients: Vec<String>,
    pub denied_clients: Vec<String>,
    pub serve_stale: Option<bool>,
    pub upstreams: Vec<UpstreamConfig>,
    pub zones: Vec<ZoneConfig>,
    /// What couldn't be carried over, and why — one line each.
    pub notes: Vec<String>,
}

impl ImportPlan {
    fn note(&mut self, line: impl Into<String>) {
        self.notes.push(line.into());
    }
}

/// The separately importable parts of a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Part {
    /// Block and allow list subscriptions.
    Lists,
    /// Manual block and allow entries.
    Rules,
    /// Local DNS records.
    Records,
    /// Device names, profiles and filtering bypass.
    Devices,
    /// Network-wide blocked services and SafeSearch.
    Services,
    /// Block answer, rate limit, client access, optimistic cache.
    Dns,
    /// Upstream resolvers and zone forwarding — replaces them; restarts.
    Upstreams,
}

impl Part {
    fn parse(s: &str) -> Option<Part> {
        Some(match s.trim() {
            "lists" => Part::Lists,
            "rules" => Part::Rules,
            "records" => Part::Records,
            "devices" => Part::Devices,
            "services" => Part::Services,
            "dns" => Part::Dns,
            "upstreams" => Part::Upstreams,
            _ => return None,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct ImportQuery {
    /// Comma-separated parts to import; absent = only show the plan.
    pub apply: Option<String>,
}

/// POST /api/import — the plan for the uploaded file, or (with `apply`) the
/// import of the chosen parts of it.
pub async fn post_import(
    State(state): State<AppState>,
    Query(query): Query<ImportQuery>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let mut plan = parse(&body).map_err(|e| ApiError(FeriteError::Config(e)))?;
    resolve_hosts(&mut plan).await;
    let Some(apply) = query.apply else {
        return Ok(Json(json!({ "plan": plan })));
    };
    let mut parts = HashSet::new();
    for p in apply.split(',').filter(|p| !p.trim().is_empty()) {
        parts.insert(Part::parse(p).ok_or_else(|| {
            ApiError(FeriteError::Config(format!(
                "unknown import part '{}'",
                p.trim()
            )))
        })?);
    }
    let report = apply_plan(&state, plan, &parts).await?;
    Ok(Json(report))
}

/// Read a Teleporter archive or an AdGuard Home config into a plan.
pub(crate) fn parse(data: &[u8]) -> Result<ImportPlan, String> {
    if data.starts_with(b"PK\x03\x04") {
        return pihole::parse(data);
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| "this is neither a Pi-hole Teleporter archive nor an AdGuardHome.yaml")?;
    if text.trim_start().starts_with('{') {
        return Err("this looks like JSON — upload AdGuardHome.yaml or a Teleporter .zip".into());
    }
    adguard::parse(text)
}

// ── Upstreams ────────────────────────────────────────────────────────────────

/// Well-known DoT/DoQ addresses and the names on their certificates, for an
/// upstream given by address alone.
const KNOWN_TLS_NAMES: [(&str, &str); 8] = [
    ("1.1.1.1", "cloudflare-dns.com"),
    ("1.0.0.1", "cloudflare-dns.com"),
    ("8.8.8.8", "dns.google"),
    ("8.8.4.4", "dns.google"),
    ("9.9.9.9", "dns.quad9.net"),
    ("149.112.112.112", "dns.quad9.net"),
    ("94.140.14.14", "dns.adguard-dns.com"),
    ("94.140.15.15", "dns.adguard-dns.com"),
];

/// Split `host[:port]` / `[v6]:port` / bare v6.
fn host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    let s = s.trim().trim_end_matches('/');
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    if s.parse::<Ipv6Addr>().is_ok() {
        return Some((s.to_string(), default_port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((s.to_string(), default_port)),
    }
}

/// One upstream as AdGuard Home writes it (`tls://…`, `https://…`,
/// `quic://…`, `8.8.8.8`, `udp://…`) or Pi-hole does (`1.1.1.1#53`). A host
/// name in a DoT/DoQ address is kept for [`resolve_hosts`] to turn into an IP.
pub(crate) fn parse_upstream(raw: &str) -> Result<UpstreamConfig, String> {
    let s = raw.trim();
    if s.starts_with("sdns://") {
        return Err(format!("{s}: DNSCrypt isn't supported"));
    }
    if s.starts_with("h3://") {
        return Err(format!("{s}: DNS-over-HTTP/3 isn't supported"));
    }
    if let Some(rest) = s.strip_prefix("https://") {
        let host = rest.split(['/', '?']).next().unwrap_or("");
        let (host, _) = host_port(host, 443).ok_or_else(|| format!("{s}: unreadable"))?;
        return Ok(UpstreamConfig::Https {
            url: s.to_string(),
            bootstrap_ip: host.parse::<IpAddr>().ok().map(|ip| ip.to_string()),
        });
    }
    let tls_like = |rest: &str, port: u16| -> Result<(String, u16, String), String> {
        let (host, port) = host_port(rest, port).ok_or_else(|| format!("{s}: unreadable"))?;
        let name = if host.parse::<IpAddr>().is_ok() {
            KNOWN_TLS_NAMES
                .iter()
                .find(|(ip, _)| *ip == host)
                .map(|(_, n)| (*n).to_string())
                .ok_or_else(|| {
                    format!("{s}: by address alone the certificate name is unknown — add it with its name")
                })?
        } else {
            host.clone()
        };
        Ok((host, port, name))
    };
    if let Some(rest) = s.strip_prefix("tls://") {
        let (address, port, tls_name) = tls_like(rest, 853)?;
        return Ok(UpstreamConfig::Tls {
            address,
            port,
            tls_name,
            egress: None,
        });
    }
    if let Some(rest) = s.strip_prefix("quic://") {
        let (address, port, tls_name) = tls_like(rest, 853)?;
        return Ok(UpstreamConfig::Quic {
            address,
            port,
            tls_name,
        });
    }
    let plain = s
        .strip_prefix("udp://")
        .or_else(|| s.strip_prefix("tcp://"))
        .unwrap_or(s);
    // Pi-hole writes the port after a `#`.
    let (host, port) = match plain.split_once('#') {
        Some((h, p)) => (
            h.to_string(),
            p.parse().map_err(|_| format!("{s}: bad port"))?,
        ),
        None => host_port(plain, 53).ok_or_else(|| format!("{s}: unreadable"))?,
    };
    if host.parse::<IpAddr>().is_err() {
        return Err(format!("{s}: a plain upstream needs an IP address"));
    }
    Ok(UpstreamConfig::Plain {
        address: host,
        port,
        egress: None,
    })
}

/// Turn the host names a DoT/DoQ upstream was given as into addresses, and
/// give a DoH upstream its bootstrap address, with the box's own resolver.
/// One that won't resolve is dropped with a note.
async fn resolve_hosts(plan: &mut ImportPlan) {
    let mut kept = Vec::with_capacity(plan.upstreams.len());
    for up in std::mem::take(&mut plan.upstreams) {
        let host = match &up {
            UpstreamConfig::Tls { address, .. } | UpstreamConfig::Quic { address, .. }
                if address.parse::<IpAddr>().is_err() =>
            {
                Some(address.clone())
            }
            UpstreamConfig::Https {
                url,
                bootstrap_ip: None,
            } => url["https://".len()..]
                .split(['/', '?', ':'])
                .next()
                .map(str::to_string),
            _ => None,
        };
        let Some(host) = host else {
            kept.push(up);
            continue;
        };
        let ip = tokio::net::lookup_host((host.as_str(), 443))
            .await
            .ok()
            .and_then(|mut addrs| addrs.find(|a| a.is_ipv4()).map(|a| a.ip()));
        let Some(ip) = ip else {
            plan.note(format!(
                "upstream {host}: couldn't resolve it from this box — skipped"
            ));
            continue;
        };
        kept.push(match up {
            UpstreamConfig::Tls {
                port,
                tls_name,
                egress,
                ..
            } => UpstreamConfig::Tls {
                address: ip.to_string(),
                port,
                tls_name,
                egress,
            },
            UpstreamConfig::Quic { port, tls_name, .. } => UpstreamConfig::Quic {
                address: ip.to_string(),
                port,
                tls_name,
            },
            UpstreamConfig::Https { url, .. } => UpstreamConfig::Https {
                url,
                bootstrap_ip: Some(ip.to_string()),
            },
            other => other,
        });
    }
    plan.upstreams = kept;
}

// ── Shared helpers for the two readers ───────────────────────────────────────

/// A list name for a subscription: its description, or one made from the URL —
/// `owner file` for a GitHub-hosted list, `host file` otherwise. Unique among
/// `taken` (case-insensitively), which it joins.
pub(crate) fn list_name(comment: Option<&str>, url: &str, taken: &mut HashSet<String>) -> String {
    let base = comment
        .map(str::trim)
        // Pi-hole's own note on lists carried over from v5 says nothing.
        .filter(|c| !c.is_empty() && !c.starts_with("Migrated from "))
        .map(|c| c.chars().take(60).collect::<String>())
        .unwrap_or_else(|| name_from_url(url));
    let mut name = base.clone();
    let mut n = 2;
    while !taken.insert(name.to_lowercase()) {
        name = format!("{base} ({n})");
        n += 1;
    }
    name
}

fn name_from_url(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let mut segs = rest.split('/').filter(|s| !s.is_empty());
    let host = segs.next().unwrap_or(rest);
    let path: Vec<&str> = segs.collect();
    let file = path.last().copied().unwrap_or("");
    let stem = file
        .rsplit_once('.')
        .filter(|(stem, ext)| !stem.is_empty() && ext.len() <= 4)
        .map(|(stem, _)| stem)
        .unwrap_or(file);
    let who = match host {
        "raw.githubusercontent.com" | "github.com" | "gitlab.com" | "codeberg.org" => {
            path.first().copied().unwrap_or(host)
        }
        _ => host.trim_start_matches("www."),
    };
    if stem.is_empty() || stem == who {
        who.to_string()
    } else {
        format!("{who} {stem}")
    }
}

/// A device id ferrite can scope by — an IP or a MAC — normalised; `None`
/// for a CIDR, a host name, an interface or a ClientID.
pub(crate) fn device_key(id: &str) -> Option<String> {
    ferrite_core::net::normalize_client_key(id)
}

/// A custom record for `domain` answering `value`: A / AAAA for an address,
/// CNAME for a name.
pub(crate) fn record(domain: &str, value: &str) -> Option<CustomRecordConfig> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let value = value.trim().trim_end_matches('.');
    if domain.is_empty() || value.is_empty() {
        return None;
    }
    let record_type = match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => "A",
        Ok(IpAddr::V6(_)) => "AAAA",
        Err(_) => "CNAME",
    };
    Some(CustomRecordConfig {
        domain,
        record_type: record_type.into(),
        value: value.to_string(),
        ttl: 300,
    })
}

// ── Applying ─────────────────────────────────────────────────────────────────

async fn apply_plan(
    state: &AppState,
    plan: ImportPlan,
    parts: &HashSet<Part>,
) -> Result<Value, ApiError> {
    let mut report = serde_json::Map::new();
    let mut restart = false;

    if parts.contains(&Part::Lists) {
        let block = add_lists(state, ListPolarity::Block, &plan.lists).await;
        let allow = add_lists(state, ListPolarity::Allow, &plan.allowlists).await;
        report.insert("lists".into(), json!({ "block": block, "allow": allow }));
        crate::lists::sync_and_refresh(state, "importing lists").await;
    }

    if parts.contains(&Part::Rules) {
        let block = crate::blocklist::import_entries(state, false, &plan.block);
        let allow = crate::blocklist::import_entries(state, true, &plan.allow);
        state.inner.dns_cache.clear();
        state.persist_config().await;
        report.insert("rules".into(), json!({ "block": block, "allow": allow }));
    }

    if parts.contains(&Part::Records) {
        let existing: HashSet<(String, String)> = state
            .live_config
            .read()
            .custom_records
            .iter()
            .map(|r| (r.domain.clone(), r.record_type.clone()))
            .collect();
        let (mut added, mut skipped) = (0, Vec::new());
        for r in plan.records.clone() {
            if existing.contains(&(r.domain.clone(), r.record_type.clone())) {
                skipped.push(format!("{} {}: already there", r.domain, r.record_type));
                continue;
            }
            let what = format!("{} {}", r.domain, r.record_type);
            match crate::custom_records::add_record(State(state.clone()), Json(r)).await {
                Ok(_) => added += 1,
                Err(e) => skipped.push(format!("{what}: {}", e.0)),
            }
        }
        report.insert(
            "records".into(),
            json!({ "added": added, "skipped": skipped }),
        );
    }

    if parts.contains(&Part::Devices) {
        let devices = apply_devices(state, &plan).await?;
        report.insert("devices".into(), devices);
    }

    if parts.contains(&Part::Services) {
        let mut services = state.live_config.read().blocklist.services.clone();
        for s in &plan.services {
            if !services.contains(s) {
                services.push(s.clone());
            }
        }
        let Json(_) = crate::services::put_blocked(
            State(state.clone()),
            Json(crate::services::ServicesPayload {
                services: services.clone(),
            }),
        )
        .await?;
        let (search, youtube) = {
            let cfg = state.live_config.read();
            (
                cfg.blocklist.safe_search || plan.safe_search,
                cfg.blocklist
                    .youtube_restricted
                    .max(plan.youtube_restricted),
            )
        };
        let Json(_) = crate::safesearch::put_safe_search(
            State(state.clone()),
            Json(crate::safesearch::SafeSearchBody {
                safe_search: search,
                youtube_restricted: youtube,
            }),
        )
        .await?;
        report.insert(
            "services".into(),
            json!({ "services": services, "safe_search": search }),
        );
    }

    if parts.contains(&Part::Dns) {
        let patch = crate::settings::SettingsPatch {
            blocklist_block_response: plan.block_response,
            blocklist_block_ipv4: plan.block_ipv4.map(Some),
            blocklist_block_ipv6: plan.block_ipv6.map(Some),
            dns_rate_limit: plan.rate_limit,
            dns_allowed_clients: (!plan.allowed_clients.is_empty())
                .then(|| plan.allowed_clients.clone()),
            dns_denied_clients: (!plan.denied_clients.is_empty())
                .then(|| plan.denied_clients.clone()),
            dns_serve_stale: plan.serve_stale,
            ..Default::default()
        };
        let Json(v) = crate::settings::update_settings(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(patch),
        )
        .await?;
        report.insert("dns".into(), v["changed"].clone());
    }

    if parts.contains(&Part::Upstreams) {
        if plan.upstreams.is_empty() {
            report.insert("upstreams".into(), json!("nothing to import"));
        } else {
            let patch = crate::settings::SettingsPatch {
                upstream: Some(plan.upstreams.clone()),
                zones: (!plan.zones.is_empty()).then(|| plan.zones.clone()),
                ..Default::default()
            };
            let Json(v) = crate::settings::update_settings(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                Json(patch),
            )
            .await?;
            restart = v["restart_required"].as_bool().unwrap_or(false);
            report.insert("upstreams".into(), json!(plan.upstreams.len()));
        }
    }

    tracing::info!(
        "imported from {}: {:?}",
        plan.source,
        report.keys().collect::<Vec<_>>()
    );
    Ok(json!({
        "status": "ok",
        "source": plan.source,
        "applied": report,
        "restart_required": restart,
    }))
}

/// Add subscriptions not already there (by URL or name); the reasons the rest
/// were skipped come back with the count.
async fn add_lists(state: &AppState, polarity: ListPolarity, lists: &[ListConfig]) -> Value {
    let subs = state.inner.blocklist.subscriptions(polarity);
    let mut added = 0;
    let mut skipped = Vec::new();
    for l in lists {
        let have = subs.lists();
        if have
            .iter()
            .any(|h| h.url == l.url || h.name.eq_ignore_ascii_case(&l.name))
        {
            skipped.push(format!("{}: already subscribed", l.name));
            continue;
        }
        if let Err(e) = ferrite_blocklist::loader::validate_remote_list_url(&l.url).await {
            skipped.push(format!("{}: {e}", l.name));
            continue;
        }
        match subs.add(l.clone()) {
            Ok(()) => added += 1,
            Err(e) => skipped.push(format!("{}: {e}", l.name)),
        }
    }
    json!({ "added": added, "skipped": skipped })
}

/// Names, profiles and bypass. Profiles join the existing set through the
/// profiles handler, so they get its checks; an id already taken is skipped.
async fn apply_devices(state: &AppState, plan: &ImportPlan) -> Result<Value, ApiError> {
    let mut names = 0;
    let mut skipped = Vec::new();
    for a in &plan.aliases {
        let payload = crate::clients::AliasPayload {
            ip: a.ip.clone(),
            mac: a.mac.clone(),
            name: a.name.clone(),
        };
        match crate::clients::add_alias(State(state.clone()), Json(payload)).await {
            Ok(_) => names += 1,
            Err(e) => skipped.push(format!("{}: {}", a.name, e.0)),
        }
    }

    let mut profiles = state.live_config.read().blocklist.profiles.clone();
    let known_lists: HashSet<String> = state
        .inner
        .blocklist
        .subscriptions(ListPolarity::Block)
        .lists()
        .into_iter()
        .map(|l| l.name)
        .collect();
    let mut added_profiles = 0;
    for p in &plan.profiles {
        if profiles.iter().any(|q| q.id == p.id) {
            skipped.push(format!("profile {}: one with that id exists", p.name));
            continue;
        }
        let mut p = p.clone();
        // A list the import didn't bring (or that was skipped) would fail
        // the whole set; keep the ones that exist.
        let before = p.lists.len();
        p.lists.retain(|l| known_lists.contains(l));
        if p.lists.len() < before {
            skipped.push(format!(
                "profile {}: {} of its lists aren't subscribed here",
                p.name,
                before - p.lists.len()
            ));
        }
        profiles.push(p);
        added_profiles += 1;
    }
    if added_profiles > 0 {
        let Json(_) = crate::profiles::put_profiles(State(state.clone()), Json(profiles)).await?;
    }

    if !plan.bypass.is_empty() {
        let mut bypass = state.live_config.read().blocklist.client_bypass.clone();
        for b in &plan.bypass {
            if !bypass.contains(b) {
                bypass.push(b.clone());
            }
        }
        let Json(_) = crate::settings::update_settings(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(crate::settings::SettingsPatch {
                blocklist_client_bypass: Some(bypass),
                ..Default::default()
            }),
        )
        .await?;
    }

    Ok(json!({
        "names": names,
        "profiles": added_profiles,
        "bypass": plan.bypass.len(),
        "skipped": skipped,
    }))
}

#[cfg(test)]
mod tests;
