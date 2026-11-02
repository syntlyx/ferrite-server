use super::*;
use ferrite_app::test_support;
use ferrite_core::config::BlockResponse;

const ADGUARD: &str = r#"
http:
  address: 0.0.0.0:3000
dns:
  bind_hosts:
    - 0.0.0.0
  upstream_dns:
    - '# a comment'
    - tls://1.1.1.1
    - https://9.9.9.9/dns-query
    - 8.8.8.8
    - '[/lan/home.arpa/]192.168.1.1'
    - sdns://AgcAAAAAAAAABzEuMC4wLjE
  ratelimit: 20
  allowed_clients:
    - 192.168.1.0/24
    - my-phone-client-id
  disallowed_clients: []
  cache_optimistic: true
filtering:
  blocking_mode: custom_ip
  blocking_ipv4: 192.168.1.5
  blocking_ipv6: ""
  parental_enabled: true
  safe_search:
    enabled: true
    youtube: true
  rewrites:
    - domain: nas.lan
      answer: 192.168.1.20
    - domain: '*.home.lan'
      answer: nas.lan
    - domain: keep.example
      answer: A
  blocked_services:
    ids:
      - tiktok
      - twitter
      - some_unknown_service
    schedule:
      time_zone: Local
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: false
    url: https://example.org/off.txt
    name: Off list
    id: 2
  - enabled: true
    url: /opt/AdGuardHome/data/userfilters/local.txt
    name: Local file
    id: 3
whitelist_filters:
  - enabled: true
    url: https://example.org/allow.txt
    name: Allow feed
    id: 4
user_rules:
  - '! a comment'
  - '||ads.example.com^'
  - '@@||good.example.com^'
  - '/^tracker[0-9]+\./'
  - '0.0.0.0 hosts-style.example'
  - '||per-client.example^$client=192.168.1.9'
  - plain.example
  - '||*.wild.example^'
clients:
  persistent:
    - name: Kid tablet
      ids:
        - 192.168.1.40
        - aa:bb:cc:dd:ee:01
      use_global_settings: false
      filtering_enabled: true
      safe_search:
        enabled: true
      use_global_blocked_services: false
      blocked_services:
        ids:
          - tiktok
          - roblox
    - name: Living room TV
      ids:
        - 192.168.1.50
      use_global_settings: false
      filtering_enabled: false
    - name: Phone by ClientID
      ids:
        - my-phone
schema_version: 29
"#;

#[test]
fn adguard_config_maps_onto_ferrite() {
    let plan = parse(ADGUARD.as_bytes()).unwrap();
    assert_eq!(plan.source, "adguard");

    // Lists: http(s) only, enabled flag kept.
    assert_eq!(plan.lists.len(), 2);
    assert!(plan.lists[0].enabled && !plan.lists[1].enabled);
    assert_eq!(plan.allowlists.len(), 1);

    // Rules.
    assert!(plan.block.contains(&"ads.example.com".to_string()));
    assert!(plan.block.contains(&r"/^tracker[0-9]+\./".to_string()));
    assert!(plan.block.contains(&"hosts-style.example".to_string()));
    assert!(plan.block.contains(&"plain.example".to_string()));
    assert!(plan.block.contains(&"*.wild.example".to_string()));
    assert_eq!(plan.allow, vec!["good.example.com".to_string()]);
    assert!(!plan.block.iter().any(|b| b.contains("per-client")));

    // Rewrites: an address, a CNAME; the "A" exception is not a record.
    assert_eq!(plan.records.len(), 2);
    assert_eq!(plan.records[0].record_type, "A");
    assert_eq!(plan.records[1].domain, "*.home.lan");
    assert_eq!(plan.records[1].record_type, "CNAME");

    // Services: twitter → x; unknown ones are named in a note.
    assert_eq!(plan.services, vec!["tiktok".to_string(), "x".to_string()]);
    assert!(
        plan.notes
            .iter()
            .any(|n| n.contains("some_unknown_service"))
    );
    assert!(plan.safe_search);

    // DNS settings.
    assert_eq!(plan.block_response, Some(BlockResponse::CustomIp));
    assert_eq!(plan.block_ipv4, Some("192.168.1.5".parse().unwrap()));
    assert_eq!(plan.rate_limit, Some(1200));
    assert_eq!(plan.allowed_clients, vec!["192.168.1.0/24".to_string()]);
    assert_eq!(plan.serve_stale, Some(true));

    // Upstreams: DoT by a known address gets its name; DNSCrypt is a note;
    // per-domain forwarding becomes zones.
    assert_eq!(plan.upstreams.len(), 3);
    assert!(matches!(
        &plan.upstreams[0],
        UpstreamConfig::Tls { address, tls_name, .. } if address == "1.1.1.1" && tls_name == "cloudflare-dns.com"
    ));
    assert!(matches!(
        &plan.upstreams[1],
        UpstreamConfig::Https { bootstrap_ip: Some(ip), .. } if ip == "9.9.9.9"
    ));
    assert_eq!(plan.zones.len(), 2);
    assert_eq!(plan.zones[0].upstream, "192.168.1.1:53");
    assert!(plan.notes.iter().any(|n| n.contains("DNSCrypt")));

    // Clients: names for every IP/MAC, a profile for the tablet, the TV
    // bypasses filtering, the ClientID-only one is a note.
    assert_eq!(plan.aliases.len(), 3);
    assert_eq!(plan.profiles.len(), 1);
    let kid = &plan.profiles[0];
    assert_eq!(kid.id, "kid-tablet");
    assert_eq!(
        kid.services,
        vec!["tiktok".to_string(), "roblox".to_string()]
    );
    assert!(kid.safe_search);
    assert_eq!(kid.lists, vec!["AdGuard DNS filter".to_string()]);
    assert_eq!(plan.bypass, vec!["192.168.1.50".to_string()]);
    assert!(plan.notes.iter().any(|n| n.contains("my-phone")));
    assert!(plan.notes.iter().any(|n| n.contains("parental")));
}

fn gravity_db() -> Vec<u8> {
    let path = std::env::temp_dir().join(format!(
        "ferrite-test-gravity-{}-{}.db",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(
            r#"
            CREATE TABLE "group" (id INTEGER PRIMARY KEY, enabled BOOLEAN, name TEXT, description TEXT);
            CREATE TABLE adlist (id INTEGER PRIMARY KEY, address TEXT, enabled BOOLEAN, comment TEXT, type INTEGER DEFAULT 0);
            CREATE TABLE adlist_by_group (adlist_id INTEGER, group_id INTEGER);
            CREATE TABLE domainlist (id INTEGER PRIMARY KEY, type INTEGER, domain TEXT, enabled BOOLEAN, comment TEXT);
            CREATE TABLE domainlist_by_group (domainlist_id INTEGER, group_id INTEGER);
            CREATE TABLE client (id INTEGER PRIMARY KEY, ip TEXT, comment TEXT);
            CREATE TABLE client_by_group (client_id INTEGER, group_id INTEGER);

            INSERT INTO "group" VALUES (0, 1, 'Default', ''), (1, 1, 'Kids', ''), (2, 0, 'Off', '');
            INSERT INTO adlist VALUES
              (1, 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 1, 'StevenBlack', 0),
              (2, 'https://example.org/kids-only.txt', 1, 'Kids extra', 0),
              (3, 'https://example.org/allow.txt', 1, '', 1);
            INSERT INTO adlist_by_group VALUES (1, 0), (1, 1), (2, 1), (3, 0);
            INSERT INTO domainlist VALUES
              (1, 1, 'ads.example.com', 1, ''),
              (2, 0, 'good.example.com', 1, ''),
              (3, 3, '^track[0-9]+\.', 1, ''),
              (4, 3, 'bad;querytype=AAAA', 1, ''),
              (5, 1, 'off.example.com', 0, ''),
              (6, 1, 'games.example.com', 1, '');
            INSERT INTO domainlist_by_group VALUES (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 1);
            INSERT INTO client VALUES
              (1, '192.168.1.40', 'Kid tablet'),
              (2, 'AA:BB:CC:DD:EE:02', 'Kid phone'),
              (3, '192.168.1.0/24', 'whole LAN');
            INSERT INTO client_by_group VALUES (1, 1), (1, 0), (2, 1), (3, 1);
            "#,
        )
        .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

const PIHOLE_TOML: &str = r#"
[dns]
upstreams = ["9.9.9.9", "149.112.112.112#53"]
hosts = ["192.168.1.20 nas.lan nas"]
cnameRecords = ["media.lan,nas.lan"]
revServers = ["true,192.168.1.0/24,192.168.1.1,lan"]

[dns.blocking]
mode = "NULL"

[dns.rateLimit]
count = 1000
interval = 60
"#;

#[test]
fn pihole_teleporter_maps_onto_ferrite() {
    let gravity = gravity_db();
    let archive = zip::build(&[
        ("etc/pihole/gravity.db", &gravity),
        ("etc/pihole/pihole.toml", PIHOLE_TOML.as_bytes()),
        ("etc/hosts", b"127.0.0.1 localhost"),
    ]);
    let plan = parse(&archive).unwrap();
    assert_eq!(plan.source, "pihole");

    // The Default group's list is on; the Kids-only one comes in off, noted.
    assert_eq!(plan.lists.len(), 2);
    assert!(plan.lists[0].enabled && !plan.lists[1].enabled);
    assert!(plan.notes.iter().any(|n| n.contains("Kids extra")));
    assert_eq!(plan.allowlists.len(), 1);

    // Default-group rules; the extension regex and the disabled one aren't.
    assert_eq!(
        plan.block,
        vec![
            "ads.example.com".to_string(),
            r"/^track[0-9]+\./".to_string()
        ]
    );
    assert_eq!(plan.allow, vec!["good.example.com".to_string()]);
    assert!(plan.notes.iter().any(|n| n.contains("querytype")));
    assert!(
        plan.notes
            .iter()
            .any(|n| n.contains("disabled domain rule"))
    );

    // Kids → a profile: its clients that ferrite can scope, the network's
    // lists (a member is in Default too), its own rule.
    assert_eq!(plan.profiles.len(), 1);
    let kids = &plan.profiles[0];
    assert_eq!(kids.id, "kids");
    assert_eq!(kids.clients.len(), 2);
    assert!(kids.clients.contains(&"aa:bb:cc:dd:ee:02".to_string()));
    assert_eq!(kids.lists, vec!["StevenBlack".to_string()]);
    assert_eq!(kids.block, vec!["games.example.com".to_string()]);
    assert!(plan.notes.iter().any(|n| n.contains("192.168.1.0/24")));

    // Names from client comments (not the CIDR one).
    assert_eq!(plan.aliases.len(), 2);

    // pihole.toml.
    assert_eq!(plan.upstreams.len(), 2);
    assert!(matches!(
        &plan.upstreams[1],
        UpstreamConfig::Plain { port: 53, .. }
    ));
    assert_eq!(plan.records.len(), 3); // nas.lan, nas, media.lan CNAME
    assert!(
        plan.records
            .iter()
            .any(|r| r.domain == "media.lan" && r.record_type == "CNAME")
    );
    assert_eq!(plan.zones.len(), 2);
    assert!(
        plan.zones
            .iter()
            .any(|z| z.name == "1.168.192.in-addr.arpa")
    );
    assert_eq!(plan.block_response, Some(BlockResponse::NullIp));
    assert_eq!(plan.rate_limit, Some(1000));
}

#[test]
fn what_isnt_an_export_is_refused_with_a_reason() {
    assert!(parse(b"{\"json\": true}").unwrap_err().contains("JSON"));
    assert!(
        parse(b"just: text\n")
            .unwrap_err()
            .contains("AdGuardHome.yaml")
    );
    let other_zip = zip::build(&[("readme.txt", b"hi")]);
    assert!(parse(&other_zip).unwrap_err().contains("Teleporter"));
}

#[test]
fn upstream_strings_from_both_tools() {
    assert!(matches!(
        parse_upstream("1.1.1.1#5353").unwrap(),
        UpstreamConfig::Plain { port: 5353, .. }
    ));
    assert!(matches!(
        parse_upstream("udp://[2606:4700::1111]:53").unwrap(),
        UpstreamConfig::Plain { address, .. } if address == "2606:4700::1111"
    ));
    assert!(matches!(
        parse_upstream("quic://dns.adguard-dns.com").unwrap(),
        UpstreamConfig::Quic { address, tls_name, .. } if address == "dns.adguard-dns.com" && tls_name == "dns.adguard-dns.com"
    ));
    assert!(parse_upstream("tls://203.0.113.9").is_err());
    assert!(parse_upstream("dns.example").is_err());
}

#[tokio::test]
async fn applying_adds_beside_what_is_there() {
    let (state, db) = test_support::app_state("import-apply").await;
    state
        .inner
        .blocklist
        .add_blacklist("ads.example.com")
        .unwrap();

    let plan = parse(ADGUARD.as_bytes()).unwrap();
    let parts: HashSet<Part> = [
        Part::Rules,
        Part::Records,
        Part::Devices,
        Part::Services,
        Part::Dns,
    ]
    .into_iter()
    .collect();
    let report = apply_plan(&state, plan, &parts).await.unwrap();

    // The entry already there is not added twice.
    assert_eq!(report["applied"]["rules"]["block"]["already"], 1);
    assert!(
        state
            .inner
            .blocklist
            .list_blacklist()
            .contains(&r"/^tracker[0-9]+\./".to_string())
    );
    assert!(
        state
            .inner
            .blocklist
            .should_block_for("tracker42.cdn.test", None)
    );
    assert_eq!(state.inner.custom_records.list().len(), 2);

    let cfg = state.live_config.read().clone();
    assert!(cfg.blocklist.services.contains(&"x".to_string()));
    assert!(cfg.blocklist.safe_search);
    assert_eq!(cfg.blocklist.block_response, BlockResponse::CustomIp);
    assert_eq!(cfg.dns.rate_limit, 1200);
    assert!(cfg.dns.serve_stale);
    assert_eq!(
        cfg.blocklist.client_bypass,
        vec!["192.168.1.50".to_string()]
    );
    assert_eq!(cfg.client_aliases.len(), 3);
    // The tablet's profile lists the AdGuard list, which isn't subscribed
    // here (lists weren't imported) — dropped with a word, profile kept.
    let kid = cfg
        .blocklist
        .profiles
        .iter()
        .find(|p| p.id == "kid-tablet")
        .unwrap();
    assert!(kid.lists.is_empty());
    assert!(
        report["applied"]["devices"]["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("aren't subscribed"))
    );

    // Upstreams weren't asked for: untouched.
    assert_eq!(cfg.upstream.len(), state.inner.config.upstream.len());

    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[test]
fn list_names_read_like_names() {
    let mut taken = HashSet::new();
    assert_eq!(
        list_name(
            Some("Migrated from /etc/pihole/adlists.list"),
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            &mut taken
        ),
        "StevenBlack hosts"
    );
    assert_eq!(
        list_name(
            None,
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
            &mut taken
        ),
        "cdn.jsdelivr.net pro"
    );
    assert_eq!(
        list_name(Some("My list"), "https://x.example/a.txt", &mut taken),
        "My list"
    );
    assert_eq!(
        list_name(Some("my list"), "https://y.example/b.txt", &mut taken),
        "my list (2)"
    );
}
