//! Pi-hole v6 Teleporter archives: `etc/pihole/gravity.db` (lists, domain
//! rules, groups, clients) and `etc/pihole/pihole.toml` (upstreams, local
//! records, conditional forwarding, blocking mode, rate limit).
//!
//! Groups map onto profiles. Pi-hole's Default group (id 0) is the network:
//! what is assigned to it becomes network-wide; every other group with
//! clients becomes a profile of the same name, its lists the group's own plus
//! — when its clients are in Default too — the network's.

use std::collections::{BTreeSet, HashMap, HashSet};

use rusqlite::{Connection, OpenFlags};

use super::{ImportPlan, device_key, list_name, parse_upstream, record, zip};
use ferrite_core::config::{
    BlockResponse, BlocklistProfileConfig, ClientAliasConfig, ListConfig, ZoneConfig,
};

pub fn parse(data: &[u8]) -> Result<ImportPlan, String> {
    let entries = zip::entries(data)?;
    let find = |path: &str| {
        entries
            .iter()
            .find(|e| e.name.trim_start_matches('/') == path)
    };
    let gravity = find("etc/pihole/gravity.db");
    let toml = find("etc/pihole/pihole.toml");
    if gravity.is_none() && toml.is_none() {
        return Err(
            "this archive holds no gravity.db or pihole.toml — is it a Pi-hole v6 \
                    Teleporter export? (a v5 one is a .tar.gz: restore it into v6 and export again)"
                .into(),
        );
    }
    let mut plan = ImportPlan {
        source: "pihole",
        ..Default::default()
    };
    if let Some(entry) = gravity {
        let bytes = zip::read(data, entry)?;
        read_gravity(&bytes, &mut plan)?;
    }
    if let Some(entry) = toml {
        let bytes = zip::read(data, entry)?;
        let text = String::from_utf8_lossy(&bytes);
        read_toml(&text, &mut plan)?;
    }
    Ok(plan)
}

struct Adlist {
    url: String,
    enabled: bool,
    comment: Option<String>,
    allow: bool,
}

struct Rule {
    kind: i64,
    domain: String,
    enabled: bool,
}

/// The gravity database, through a temporary file (SQLite reads files).
fn read_gravity(bytes: &[u8], plan: &mut ImportPlan) -> Result<(), String> {
    if !bytes.starts_with(b"SQLite format 3\0") {
        return Err("gravity.db in the archive isn't an SQLite database".into());
    }
    let path = std::env::temp_dir().join(format!(
        "ferrite-import-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::write(&path, bytes).map_err(|e| format!("couldn't stage gravity.db: {e}"))?;
    let result = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("couldn't open gravity.db: {e}"))
        .and_then(|db| read_tables(&db, plan).map_err(|e| format!("gravity.db: {e}")));
    let _ = std::fs::remove_file(&path);
    result
}

fn has_column(db: &Connection, table: &str, column: &str) -> bool {
    db.prepare(&format!("SELECT {column} FROM \"{table}\" LIMIT 0"))
        .is_ok()
}

fn read_tables(db: &Connection, plan: &mut ImportPlan) -> rusqlite::Result<()> {
    // ── Raw tables ───────────────────────────────────────────────────────
    let mut groups: HashMap<i64, (String, bool)> = HashMap::new();
    for row in db
        .prepare("SELECT id, name, enabled FROM \"group\"")?
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })?
    {
        let (id, name, enabled) = row?;
        groups.insert(id, (name, enabled));
    }

    let adlist_type = if has_column(db, "adlist", "type") {
        "type"
    } else {
        "0"
    };
    let mut adlists: HashMap<i64, Adlist> = HashMap::new();
    for row in db
        .prepare(&format!(
            "SELECT id, address, enabled, comment, {adlist_type} FROM adlist ORDER BY id"
        ))?
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                Adlist {
                    url: r.get(1)?,
                    enabled: r.get(2)?,
                    comment: r.get(3)?,
                    allow: r.get::<_, i64>(4)? == 1,
                },
            ))
        })?
    {
        let (id, a) = row?;
        adlists.insert(id, a);
    }

    let mut rules: HashMap<i64, Rule> = HashMap::new();
    for row in db
        .prepare("SELECT id, type, domain, enabled FROM domainlist ORDER BY id")?
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                Rule {
                    kind: r.get(1)?,
                    domain: r.get(2)?,
                    enabled: r.get(3)?,
                },
            ))
        })?
    {
        let (id, rule) = row?;
        rules.insert(id, rule);
    }

    let mut clients: HashMap<i64, (String, Option<String>)> = HashMap::new();
    for row in db
        .prepare("SELECT id, ip, comment FROM client")?
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?
    {
        let (id, ip, comment) = row?;
        clients.insert(id, (ip, comment));
    }

    let by_group = |table: &str, column: &str| -> rusqlite::Result<HashMap<i64, BTreeSet<i64>>> {
        let mut out: HashMap<i64, BTreeSet<i64>> = HashMap::new();
        for row in db
            .prepare(&format!("SELECT {column}, group_id FROM {table}"))?
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?
        {
            let (item, group) = row?;
            out.entry(item).or_default().insert(group);
        }
        Ok(out)
    };
    let adlist_groups = by_group("adlist_by_group", "adlist_id")?;
    let rule_groups = by_group("domainlist_by_group", "domainlist_id")?;
    let client_groups = by_group("client_by_group", "client_id")?;
    let in_group = |map: &HashMap<i64, BTreeSet<i64>>, id: i64, g: i64| {
        map.get(&id).is_some_and(|gs| gs.contains(&g))
    };
    let group_on = |g: i64| groups.get(&g).is_none_or(|(_, on)| *on);

    // ── Lists ────────────────────────────────────────────────────────────
    let mut taken = HashSet::new();
    let mut list_names: HashMap<i64, String> = HashMap::new();
    let mut global_block: Vec<String> = Vec::new();
    let mut ids: Vec<&i64> = adlists.keys().collect();
    ids.sort();
    for &id in ids {
        let a = &adlists[&id];
        if !a.url.starts_with("http://") && !a.url.starts_with("https://") {
            plan.note(format!(
                "list {}: only http(s) lists can be subscribed",
                a.url
            ));
            continue;
        }
        let name = list_name(a.comment.as_deref(), &a.url, &mut taken);
        let network = in_group(&adlist_groups, id, 0);
        let on_a_group = adlist_groups
            .get(&id)
            .is_some_and(|gs| gs.iter().any(|&g| g != 0));
        if !network && on_a_group {
            plan.note(format!(
                "list {name}: Pi-hole applies it to some groups only — ferrite's lists are \
                 network-wide, narrowed per profile, so it comes in switched off"
            ));
        }
        let cfg = ListConfig {
            url: a.url.clone(),
            name: name.clone(),
            enabled: a.enabled && network,
        };
        if a.allow {
            plan.allowlists.push(cfg);
        } else {
            if cfg.enabled {
                global_block.push(name.clone());
            }
            plan.lists.push(cfg);
        }
        list_names.insert(id, name);
    }

    // ── Domain rules ─────────────────────────────────────────────────────
    let mut disabled = 0;
    let mut entry_of = |rule: &Rule, plan: &mut ImportPlan| -> Option<(bool, String)> {
        if !rule.enabled {
            disabled += 1;
            return None;
        }
        let allow = rule.kind == 0 || rule.kind == 2;
        let regex = rule.kind == 2 || rule.kind == 3;
        let entry = if regex {
            if rule.domain.contains(";querytype=")
                || rule.domain.contains(";invert")
                || rule.domain.contains(";reply=")
            {
                plan.note(format!(
                    "regex {}: Pi-hole's ;querytype / ;invert / ;reply extensions have no equivalent",
                    rule.domain
                ));
                return None;
            }
            format!("/{}/", rule.domain)
        } else {
            rule.domain.trim().to_ascii_lowercase()
        };
        if let Err(e) = ferrite_blocklist::validate_entry(&entry) {
            plan.note(format!("rule {}: {e}", rule.domain));
            return None;
        }
        Some((allow, entry))
    };
    let mut rule_ids: Vec<&i64> = rules.keys().collect();
    rule_ids.sort();
    let mut exact_seen = false;
    for &id in &rule_ids {
        if !in_group(&rule_groups, *id, 0) {
            continue;
        }
        if let Some((allow, entry)) = entry_of(&rules[id], plan) {
            exact_seen |= !entry.starts_with('/');
            if allow {
                plan.allow.push(entry);
            } else {
                plan.block.push(entry);
            }
        }
    }
    if exact_seen {
        plan.note(
            "an exact Pi-hole entry matches that name only; in ferrite a name covers its \
             subdomains too",
        );
    }

    // ── Names, profiles ──────────────────────────────────────────────────
    for (ip, comment) in clients.values() {
        let Some(name) = comment.as_deref().map(str::trim).filter(|c| !c.is_empty()) else {
            continue;
        };
        if let Some(key) = device_key(ip) {
            plan.aliases.push(alias(&key, name));
        }
    }

    let mut group_ids: Vec<&i64> = groups.keys().filter(|&&g| g != 0).collect();
    group_ids.sort();
    for &g in group_ids {
        let (name, _) = &groups[&g];
        if !group_on(g) {
            plan.note(format!("group {name}: disabled in Pi-hole — skipped"));
            continue;
        }
        let members: Vec<i64> = clients
            .keys()
            .filter(|&&c| in_group(&client_groups, c, g))
            .copied()
            .collect();
        if members.is_empty() {
            continue;
        }
        let mut keys = Vec::new();
        for c in &members {
            let ip = &clients[c].0;
            match device_key(ip) {
                Some(k) => keys.push(k),
                None => plan.note(format!(
                    "group {name}: client {ip} isn't an IP or a MAC — ferrite can't scope by it"
                )),
            }
        }
        if keys.is_empty() {
            continue;
        }
        let also_network = members.iter().any(|c| in_group(&client_groups, *c, 0));
        let mut lists: Vec<String> = adlists
            .iter()
            .filter(|(id, a)| !a.allow && a.enabled && in_group(&adlist_groups, **id, g))
            .filter_map(|(id, _)| list_names.get(id))
            .filter(|n| global_block.contains(n))
            .cloned()
            .collect();
        if also_network {
            for n in &global_block {
                if !lists.contains(n) {
                    lists.push(n.clone());
                }
            }
        }
        lists.sort();
        let (mut block, mut allow) = (Vec::new(), Vec::new());
        for &id in &rule_ids {
            if in_group(&rule_groups, *id, g)
                && !in_group(&rule_groups, *id, 0)
                && let Some((is_allow, entry)) = entry_of(&rules[id], plan)
            {
                if is_allow {
                    allow.push(entry);
                } else {
                    block.push(entry);
                }
            }
        }
        plan.profiles.push(BlocklistProfileConfig {
            id: slug(name),
            name: name.clone(),
            lists,
            clients: keys,
            block,
            allow,
            services: vec![],
            schedule: vec![],
            safe_search: false,
            youtube_restricted: Default::default(),
            allowlists: vec![],
            default_deny: false,
        });
    }
    if disabled > 0 {
        plan.note(format!("{disabled} disabled domain rule(s) left out"));
    }
    Ok(())
}

fn alias(key: &str, name: &str) -> ClientAliasConfig {
    let is_ip = key.parse::<std::net::IpAddr>().is_ok();
    ClientAliasConfig {
        ip: is_ip.then(|| key.to_string()),
        mac: (!is_ip).then(|| key.to_string()),
        name: name.to_string(),
    }
}

/// Lowercase slug, like the panel makes from a profile name.
pub(crate) fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() { "group".into() } else { out }
}

/// `pihole.toml`: the DNS settings that have a ferrite counterpart.
fn read_toml(text: &str, plan: &mut ImportPlan) -> Result<(), String> {
    let doc: toml::Value =
        toml::from_str(text).map_err(|e| format!("pihole.toml doesn't parse: {e}"))?;
    let dns = &doc["dns"];
    let strings = |v: Option<&toml::Value>| -> Vec<String> {
        v.and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };

    for up in strings(dns.get("upstreams")) {
        match parse_upstream(&up) {
            Ok(u) => plan.upstreams.push(u),
            Err(e) => plan.note(format!("upstream {e}")),
        }
    }

    // Local DNS records: "IP name [alias…]".
    for line in strings(dns.get("hosts")) {
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        for name in parts {
            if let Some(r) = record(name, ip) {
                plan.records.push(r);
            }
        }
    }
    // CNAMEs: "alias,target[,ttl]".
    for line in strings(dns.get("cnameRecords")) {
        let mut parts = line.split(',');
        if let (Some(name), Some(target)) = (parts.next(), parts.next())
            && let Some(mut r) = record(name, target)
        {
            r.record_type = "CNAME".into();
            if let Some(ttl) = parts.next().and_then(|t| t.trim().parse().ok()) {
                r.ttl = ttl;
            }
            plan.records.push(r);
        }
    }

    // Conditional forwarding: "active,CIDR,server[#port],domain".
    for line in strings(dns.get("revServers")) {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 3 || parts[0] != "true" {
            continue;
        }
        let (host, port) = match parts[2].split_once('#') {
            Some((h, p)) => (h, p),
            None => (parts[2], "53"),
        };
        let server = match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
            Ok(ip) => format!("{ip}:{port}"),
            Err(_) => {
                plan.note(format!(
                    "conditional forwarding to {host}: needs an IP address"
                ));
                continue;
            }
        };
        if let Some(domain) = parts.get(3).filter(|d| !d.is_empty()) {
            plan.zones.push(ZoneConfig {
                name: domain.to_string(),
                upstream: server.clone(),
            });
        }
        match reverse_zone(parts[1]) {
            Some(zone) => plan.zones.push(ZoneConfig {
                name: zone,
                upstream: server,
            }),
            None => plan.note(format!(
                "conditional forwarding for {}: only /8, /16 and /24 IPv4 ranges map to a reverse zone",
                parts[1]
            )),
        }
    }

    // Blocking mode.
    if let Some(mode) = dns
        .get("blocking")
        .and_then(|b| b.get("mode"))
        .and_then(|m| m.as_str())
    {
        let reply = dns.get("reply").and_then(|r| r.get("blocking"));
        let addr = |key: &str| {
            reply
                .and_then(|r| r.get(key))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        match mode {
            "NULL" => plan.block_response = Some(BlockResponse::NullIp),
            "NX" => plan.block_response = Some(BlockResponse::Nxdomain),
            "NODATA" => plan.block_response = Some(BlockResponse::Nodata),
            "IP" | "IP-NODATA-AAAA" => {
                plan.block_ipv4 = addr("IPv4").and_then(|s| s.parse().ok());
                plan.block_ipv6 = if mode == "IP" {
                    addr("IPv6").and_then(|s| s.parse().ok())
                } else {
                    None
                };
                if plan.block_ipv4.is_some() || plan.block_ipv6.is_some() {
                    plan.block_response = Some(BlockResponse::CustomIp);
                } else {
                    plan.note("blocking mode IP without an address — left as it is");
                }
            }
            other => plan.note(format!("blocking mode {other}: no counterpart")),
        }
    }

    // Rate limit: count per interval seconds → per minute.
    if let Some(rl) = dns.get("rateLimit") {
        let count = rl.get("count").and_then(|v| v.as_integer()).unwrap_or(0);
        let interval = rl
            .get("interval")
            .and_then(|v| v.as_integer())
            .unwrap_or(60);
        if count > 0 && interval > 0 {
            plan.rate_limit = Some(((count * 60) / interval).clamp(1, u32::MAX as i64) as u32);
        } else {
            plan.rate_limit = Some(0);
        }
    }
    Ok(())
}

/// The reverse zone of an IPv4 /8, /16 or /24.
fn reverse_zone(cidr: &str) -> Option<String> {
    let (ip, len) = cidr.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip.parse().ok()?;
    let o = ip.octets();
    Some(match len {
        "24" => format!("{}.{}.{}.in-addr.arpa", o[2], o[1], o[0]),
        "16" => format!("{}.{}.in-addr.arpa", o[1], o[0]),
        "8" => format!("{}.in-addr.arpa", o[0]),
        _ => return None,
    })
}
