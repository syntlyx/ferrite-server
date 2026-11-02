//! `AdGuardHome.yaml`: filter subscriptions, user rules, DNS rewrites, blocked
//! services, SafeSearch, persistent clients and the DNS settings that have a
//! ferrite counterpart. Both layouts are read — settings under `dns` (before
//! v0.107.37) and under `filtering` (since).

use std::collections::HashSet;

use yaml_rust2::{Yaml, YamlLoader};

use super::pihole::slug;
use super::{ImportPlan, device_key, list_name, parse_upstream, record};
use ferrite_core::config::{
    BlockResponse, BlocklistProfileConfig, ClientAliasConfig, ListConfig, YoutubeRestrict,
    ZoneConfig,
};
use ferrite_core::net::IpNetwork;

pub fn parse(text: &str) -> Result<ImportPlan, String> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| format!("YAML doesn't parse: {e}"))?;
    let doc = docs.first().ok_or("the file is empty")?;
    if doc["dns"].is_badvalue() && doc["schema_version"].is_badvalue() {
        return Err("this isn't an AdGuardHome.yaml (no dns section)".into());
    }
    let mut plan = ImportPlan {
        source: "adguard",
        ..Default::default()
    };
    let dns = &doc["dns"];
    let filtering = &doc["filtering"];
    // A setting lives under `filtering` in newer versions, `dns` in older.
    let setting = |key: &str| -> &Yaml {
        if !filtering[key].is_badvalue() {
            &filtering[key]
        } else {
            &dns[key]
        }
    };

    // ── Subscriptions ────────────────────────────────────────────────────
    let mut taken = HashSet::new();
    for (key, allow) in [("filters", false), ("whitelist_filters", true)] {
        for f in doc[key].as_vec().map(Vec::as_slice).unwrap_or_default() {
            let Some(url) = f["url"].as_str() else {
                continue;
            };
            if !url.starts_with("http://") && !url.starts_with("https://") {
                plan.note(format!(
                    "list {}: a local file on the AdGuard box — only http(s) lists can be subscribed",
                    f["name"].as_str().unwrap_or(url)
                ));
                continue;
            }
            let cfg = ListConfig {
                url: url.to_string(),
                name: list_name(f["name"].as_str(), url, &mut taken),
                enabled: f["enabled"].as_bool().unwrap_or(true),
            };
            if allow {
                plan.allowlists.push(cfg);
            } else {
                plan.lists.push(cfg);
            }
        }
    }
    let network_lists: Vec<String> = plan
        .lists
        .iter()
        .filter(|l| l.enabled)
        .map(|l| l.name.clone())
        .collect();

    // ── User rules ───────────────────────────────────────────────────────
    let mut modifiers = 0;
    for rule in strings(&doc["user_rules"]) {
        match user_rule(&rule) {
            Rule::Block(e) => plan.block.push(e),
            Rule::Allow(e) => plan.allow.push(e),
            Rule::Comment => {}
            Rule::Modifier => modifiers += 1,
            Rule::Unsupported => plan.note(format!("rule {rule}: no counterpart")),
        }
    }
    if modifiers > 0 {
        plan.note(format!(
            "{modifiers} rule(s) with $client, $dnstype, $dnsrewrite or other modifiers left out"
        ));
    }
    for e in plan.block.iter().chain(&plan.allow) {
        if let Err(err) = ferrite_blocklist::validate_entry(e) {
            plan.notes.push(format!("rule {e}: {err}"));
        }
    }
    plan.block
        .retain(|e| ferrite_blocklist::validate_entry(e).is_ok());
    plan.allow
        .retain(|e| ferrite_blocklist::validate_entry(e).is_ok());

    // ── Rewrites ─────────────────────────────────────────────────────────
    for r in setting("rewrites")
        .as_vec()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if r["enabled"].as_bool() == Some(false) {
            continue;
        }
        let (Some(domain), Some(answer)) = (r["domain"].as_str(), r["answer"].as_str()) else {
            continue;
        };
        // "A" / "AAAA" as the answer means "keep the upstream's" — an exception.
        if answer.eq_ignore_ascii_case("a") || answer.eq_ignore_ascii_case("aaaa") {
            plan.note(format!(
                "rewrite {domain} → {answer}: an exception, nothing to add"
            ));
            continue;
        }
        if let Some(rec) = record(domain, answer) {
            plan.records.push(rec);
        }
    }

    // ── Services, SafeSearch ─────────────────────────────────────────────
    let blocked = setting("blocked_services");
    let (ids, schedule) = if blocked.as_vec().is_some() {
        (strings(blocked), false)
    } else {
        (
            strings(&blocked["ids"]),
            blocked["schedule"].as_hash().is_some_and(|h| h.len() > 1),
        )
    };
    plan.services = map_services(&ids, &mut plan.notes, "network");
    if schedule {
        plan.note("the pause schedule for blocked services isn't imported — services stay blocked");
    }
    let safe = setting("safe_search");
    plan.safe_search = safe["enabled"].as_bool().unwrap_or(false)
        || dns["safesearch_enabled"].as_bool().unwrap_or(false);
    if plan.safe_search && safe["youtube"].as_bool().unwrap_or(true) {
        plan.youtube_restricted = YoutubeRestrict::Moderate;
    }
    if setting("parental_enabled").as_bool() == Some(true)
        || setting("safebrowsing_enabled").as_bool() == Some(true)
    {
        plan.note(
            "AdGuard's cloud parental control and safe browsing have no counterpart — \
             subscribe to an adult-content or malware list from the catalog instead",
        );
    }

    // ── DNS settings ─────────────────────────────────────────────────────
    match setting("blocking_mode").as_str() {
        Some("nxdomain") => plan.block_response = Some(BlockResponse::Nxdomain),
        Some("null_ip") => plan.block_response = Some(BlockResponse::NullIp),
        Some("refused") => plan.block_response = Some(BlockResponse::Refused),
        Some("custom_ip") => {
            plan.block_ipv4 = setting("blocking_ipv4")
                .as_str()
                .and_then(|s| s.parse().ok());
            plan.block_ipv6 = setting("blocking_ipv6")
                .as_str()
                .and_then(|s| s.parse().ok());
            if plan.block_ipv4.is_some() || plan.block_ipv6.is_some() {
                plan.block_response = Some(BlockResponse::CustomIp);
            }
        }
        _ => {} // "default" or unset: keep ferrite's
    }
    if let Some(qps) = dns["ratelimit"].as_i64() {
        plan.rate_limit = Some(qps.clamp(0, i64::from(u32::MAX) / 60) as u32 * 60);
    }
    for (key, out) in [("allowed_clients", 0), ("disallowed_clients", 1)] {
        for c in strings(&dns[key]) {
            if IpNetwork::parse(&c).is_some() {
                if out == 0 {
                    plan.allowed_clients.push(c);
                } else {
                    plan.denied_clients.push(c);
                }
            } else {
                plan.note(format!(
                    "{key} {c}: a ClientID — only IPs and ranges carry over"
                ));
            }
        }
    }
    if dns["cache_optimistic"].as_bool() == Some(true) {
        plan.serve_stale = Some(true);
    }

    // ── Upstreams ────────────────────────────────────────────────────────
    for line in strings(&dns["upstream_dns"]) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // "[/a.lan/b.lan/]10.0.0.1" — forward those domains there.
        if let Some(rest) = line.strip_prefix("[/") {
            let Some((domains, server)) = rest.split_once("/]") else {
                continue;
            };
            match parse_upstream(server) {
                Ok(ferrite_core::config::UpstreamConfig::Plain { address, port, .. }) => {
                    let upstream = match address.parse::<std::net::IpAddr>() {
                        Ok(std::net::IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
                        _ => format!("{address}:{port}"),
                    };
                    for d in domains.split('/').filter(|d| !d.is_empty()) {
                        plan.zones.push(ZoneConfig {
                            name: d.trim_start_matches("*.").to_string(),
                            upstream: upstream.clone(),
                        });
                    }
                }
                Ok(_) => plan.note(format!(
                    "{line}: per-domain upstreams forward over plain DNS only here"
                )),
                Err(e) => plan.note(format!("upstream {e}")),
            }
            continue;
        }
        match parse_upstream(line) {
            Ok(u) => plan.upstreams.push(u),
            Err(e) => plan.note(format!("upstream {e}")),
        }
    }

    // ── Persistent clients ───────────────────────────────────────────────
    let mut profile_ids = HashSet::new();
    for c in doc["clients"]["persistent"]
        .as_vec()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(name) = c["name"].as_str().map(str::trim).filter(|n| !n.is_empty()) else {
            continue;
        };
        let mut keys = Vec::new();
        for id in strings(&c["ids"]) {
            match device_key(&id) {
                Some(k) => keys.push(k),
                None => plan.note(format!(
                    "client {name}: {id} isn't an IP or a MAC — ferrite can't scope by it"
                )),
            }
        }
        if keys.is_empty() {
            continue;
        }
        for k in &keys {
            let is_ip = k.parse::<std::net::IpAddr>().is_ok();
            plan.aliases.push(ClientAliasConfig {
                ip: is_ip.then(|| k.clone()),
                mac: (!is_ip).then(|| k.clone()),
                name: name.to_string(),
            });
        }
        if !strings(&c["upstreams"]).is_empty() {
            plan.note(format!(
                "client {name}: per-device upstreams have no counterpart"
            ));
        }
        let own_settings = c["use_global_settings"].as_bool() == Some(false);
        if own_settings && c["filtering_enabled"].as_bool() == Some(false) {
            plan.bypass.extend(keys.iter().cloned());
            continue;
        }
        let services = if c["use_global_blocked_services"].as_bool() == Some(false) {
            let b = &c["blocked_services"];
            let ids = if b.as_vec().is_some() {
                strings(b)
            } else {
                strings(&b["ids"])
            };
            map_services(&ids, &mut plan.notes, name)
        } else {
            vec![]
        };
        let safe = own_settings
            && (c["safe_search"]["enabled"].as_bool() == Some(true)
                || c["safesearch_enabled"].as_bool() == Some(true));
        if services.is_empty() && !safe {
            continue;
        }
        let mut id = slug(name);
        while !profile_ids.insert(id.clone()) {
            id.push('-');
            id.push('2');
        }
        plan.profiles.push(BlocklistProfileConfig {
            id,
            name: name.to_string(),
            // A profile's lists are its whole subscription set: the network's.
            lists: network_lists.clone(),
            clients: keys,
            block: vec![],
            allow: vec![],
            services,
            schedule: vec![],
            safe_search: safe,
            youtube_restricted: if safe {
                YoutubeRestrict::Moderate
            } else {
                YoutubeRestrict::Off
            },
            allowlists: vec![],
            default_deny: false,
        });
    }
    Ok(plan)
}

fn strings(v: &Yaml) -> Vec<String> {
    v.as_vec()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

enum Rule {
    Block(String),
    Allow(String),
    Comment,
    Modifier,
    Unsupported,
}

/// One AdGuard user rule in ferrite's terms: `||x^` and plain names are
/// names, `/re/` a regex, `@@` allows, `0.0.0.0 x` is a hosts-file block.
fn user_rule(raw: &str) -> Rule {
    let r = raw.trim();
    if r.is_empty() || r.starts_with('!') || r.starts_with('#') {
        return Rule::Comment;
    }
    let (allow, r) = match r.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, r),
    };
    let wrap = |e: String| {
        if allow {
            Rule::Allow(e)
        } else {
            Rule::Block(e)
        }
    };
    // A regex may itself contain `$`; only a trailing $modifier counts.
    if r.starts_with('/') {
        return match r.rfind('/') {
            Some(end) if end > 0 => {
                let tail = &r[end + 1..];
                if tail.is_empty() || tail == "$important" {
                    wrap(r[..=end].to_string())
                } else {
                    Rule::Modifier
                }
            }
            _ => Rule::Unsupported,
        };
    }
    let (body, mods) = match r.split_once('$') {
        Some((b, m)) => (b, Some(m)),
        None => (r, None),
    };
    if let Some(m) = mods
        && m != "important"
    {
        return Rule::Modifier;
    }
    // Hosts-file line: "0.0.0.0 example.com".
    let mut words = body.split_whitespace();
    if let (Some(first), Some(second)) = (words.next(), words.next())
        && first.parse::<std::net::IpAddr>().is_ok()
    {
        return if allow {
            Rule::Unsupported
        } else {
            Rule::Block(second.to_ascii_lowercase())
        };
    }
    let name = body
        .trim_start_matches("||")
        .trim_start_matches('|')
        .trim_end_matches('^')
        .trim_end_matches('|')
        .to_ascii_lowercase();
    let bare = name.trim_start_matches("*.");
    if name.is_empty() || bare.contains(['*', '/', '^', '|', ' ']) || !bare.contains('.') {
        return Rule::Unsupported;
    }
    wrap(name)
}

/// AdGuard's service ids in ferrite's catalog: the same id, or a known rename.
fn map_services(ids: &[String], notes: &mut Vec<String>, whose: &str) -> Vec<String> {
    const RENAMED: [(&str, &str); 9] = [
        ("twitter", "x"),
        ("amazon_streaming", "primevideo"),
        ("xboxlive", "xbox"),
        ("blizzard_entertainment", "battlenet"),
        ("riot_games", "riot"),
        ("epic_games", "fortnite"),
        ("openai", "chatgpt"),
        ("disney_plus", "disneyplus"),
        ("max", "hbomax"),
    ];
    let mut out = Vec::new();
    let mut unknown = Vec::new();
    for id in ids {
        let id = id.trim().to_ascii_lowercase();
        let mapped = RENAMED
            .iter()
            .find(|(from, _)| *from == id)
            .map(|(_, to)| (*to).to_string())
            .unwrap_or(id.clone());
        if ferrite_core::services::find(&mapped).is_some() {
            if !out.contains(&mapped) {
                out.push(mapped);
            }
        } else {
            unknown.push(id);
        }
    }
    if !unknown.is_empty() {
        notes.push(format!(
            "blocked services ({whose}) not in ferrite's catalog: {}",
            unknown.join(", ")
        ));
    }
    out
}
