use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use crate::clients::normalize_client_key;
use crate::error::{FeriteError, Result};

/// XDG-style config dir: always `~/.config/ferrite` on every platform.
pub fn config_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/etc"))
        .join(".config/ferrite")
}

/// XDG-style data dir: always `~/.local/share/ferrite` on every platform.
pub fn data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib"))
        .join(".local/share/ferrite")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default = "default_upstreams")]
    pub upstream: Vec<UpstreamConfig>,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub panel: PanelConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
    #[serde(default)]
    pub custom_records: Vec<CustomRecordConfig>,
    /// Selective per-domain routing through tunnels/proxies (egresses).
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Verbose debug-level logging for the `ferrite` target. On by default so a
    /// problem leaves a useful trail to attach to a bug report; turn it off from
    /// Settings if the volume is too high. Applied live (no restart); the
    /// `RUST_LOG` environment variable overrides it.
    #[serde(default = "default_true")]
    pub debug_logging: bool,
    /// Override path for static web UI files. If unset, defaults to `data_dir()/web`.
    /// Useful during frontend development to point at a local `dist/` folder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_dir: Option<PathBuf>,
}

fn default_upstreams() -> Vec<UpstreamConfig> {
    vec![
        UpstreamConfig::Plain {
            address: "8.8.8.8".to_string(),
            port: 53,
            egress: None,
        },
        UpstreamConfig::Plain {
            address: "8.8.4.4".to_string(),
            port: 53,
            egress: None,
        },
    ]
}

/// A custom DNS record (defined in config or added at runtime via API).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomRecordConfig {
    /// Domain or wildcard, e.g. `"router.lan"` or `"*.home.lan"`.
    pub domain: String,
    /// `"A"`, `"AAAA"`, or `"CNAME"`.
    #[serde(rename = "type")]
    pub record_type: String,
    /// IPv4/IPv6 address or CNAME target hostname.
    pub value: String,
    #[serde(default = "default_custom_ttl")]
    pub ttl: u32,
}

fn default_custom_ttl() -> u32 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DnsConfig {
    pub bind_addr: SocketAddr,
    pub cache_size: usize,
    /// Byte budget for the DNS response cache, in MiB. `cache_size` bounds the
    /// entry *count*, which alone can't bound memory — a DNSSEC answer with
    /// RRSIGs is 10–20× the size of a plain one. `0` disables the byte bound.
    pub cache_max_mb: usize,
    pub min_ttl: u64,
    pub max_ttl: u64,
    /// Domains to suppress from the query log entirely.
    /// Supports exact names (`fe.te`) and wildcard suffixes (`*.local`).
    pub log_ignore: Vec<String>,
    /// Strip EDNS Client Subnet (RFC 7871) from upstream queries so a resolver
    /// never learns the client's subnet. On by default.
    #[serde(default = "default_true")]
    pub strip_ecs: bool,
    /// Set the DNSSEC-OK (DO) bit on upstream queries and forward signatures
    /// untouched. Enforcement relies on a validating upstream over a secure
    /// channel (DoT/DoH/tunnel) — ferrite does not validate locally yet. On by default.
    #[serde(default = "default_true")]
    pub dnssec: bool,
}

/// Route a DNS zone to a specific upstream server instead of the default pool.
///
/// Example (routes all local reverse-DNS to the router):
/// ```toml
/// [[zones]]
/// name = "1.168.192.in-addr.arpa"
/// upstream = "192.168.1.1:53"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZoneConfig {
    /// Zone suffix to match, e.g. `"1.168.192.in-addr.arpa"` or `"localdomain"`.
    pub name: String,
    /// Upstream address for this zone, e.g. `"192.168.1.1:53"`.
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UpstreamConfig {
    Plain {
        address: String,
        port: u16,
        /// Route this resolver's DNS-over-TCP through a named egress (tunnel).
        /// Empty/absent = direct. The address must be a literal IP (no bootstrap
        /// loop). Falls back to direct when the egress is down.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        egress: Option<String>,
    },
    Tls {
        address: String,
        port: u16,
        tls_name: String,
        /// Route this DoT resolver's TLS through a named egress (tunnel). Same
        /// semantics as `Plain::egress` — direct fallback when the egress is down.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        egress: Option<String>,
    },
    Https {
        url: String,
        /// IP address to use when connecting, bypassing DNS resolution.
        /// Required when ferrite is the system DNS resolver (bootstrap problem).
        /// Example: "1.1.1.1" for cloudflare-dns.com
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bootstrap_ip: Option<String>,
    },
    Quic {
        address: String,
        port: u16,
        tls_name: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct StorageConfig {
    /// SQLite database path.
    pub path: PathBuf,
    /// Automatically delete query log entries older than this many days.
    /// 0 = disabled (default). Applied once at startup and then every 24 hours.
    #[serde(skip_serializing_if = "is_retention_disabled")]
    pub log_retention_days: u32,
}

fn is_retention_disabled(d: &u32) -> bool {
    *d == 0
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ApiConfig {
    pub bind_addr: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Argon2 hash of the web UI password. `None` means no auth required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PanelConfig {
    pub enabled: bool,
    pub domain: String,
    /// Optional IPv4 address for the built-in panel shortcut A record.
    /// Useful in Docker bridge mode, where interface auto-detection sees the
    /// container IP instead of the host/LAN IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    /// Optional display URL used in startup logs. DNS A records cannot carry a
    /// port, so set this when the web UI is published on a non-80 host port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BlocklistConfig {
    pub enabled: bool,
    #[serde(default = "default_blocklist_decision_cache_size")]
    pub decision_cache_size: usize,
    pub lists: Vec<ListConfig>,
    pub wildcard_block: Vec<String>,
    pub whitelist: Vec<String>,
    pub client_bypass: Vec<String>,
}

fn default_blocklist_decision_cache_size() -> usize {
    // ~120 B/entry when full. A home network sees well under 20k unique
    // domains a day, so this keeps the hit rate while capping RAM at ~2.5 MB.
    20_000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListConfig {
    pub url: String,
    pub name: String,
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_http_port() -> u16 {
    80
}

fn default_https_port() -> u16 {
    443
}

fn default_max_connections() -> usize {
    128
}

/// Selective per-domain routing.
///
/// For a domain that matches a rule, DNS answers with ferrite's own LAN IP so
/// the client connects to us; the proxy listeners on `http_port`/`https_port`
/// then read the SNI/Host and forward the connection through the named egress.
/// The config file is written by the server (web UI is the primary editor);
/// hand-editing is supported but not required.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub enabled: bool,
    /// Plain-HTTP listener port (privileged 80 by default; override for non-root dev).
    pub http_port: u16,
    /// TLS (SNI) listener port (privileged 443 by default; override for non-root dev).
    pub https_port: u16,
    /// IPv4 address advertised in DNS answers for routed domains. Auto-detected
    /// at startup when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_ipv4: Option<Ipv4Addr>,
    /// IPv6 address advertised for routed domains. When unset, AAAA queries for
    /// routed domains return NODATA so clients fall back to IPv4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_ipv6: Option<Ipv6Addr>,
    /// Hard cap on simultaneous proxied connections (bounds memory).
    pub max_connections: usize,
    /// Optional URL POSTed a JSON event when an egress stays down past the
    /// alert grace period (and again on recovery). Plain webhook — works with
    /// ntfy, a Slack/Telegram shim, or anything that accepts a JSON POST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_webhook: Option<String>,
    pub egresses: Vec<EgressConfig>,
    pub rules: Vec<RuleConfig>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            http_port: default_http_port(),
            https_port: default_https_port(),
            advertise_ipv4: None,
            advertise_ipv6: None,
            max_connections: default_max_connections(),
            alert_webhook: None,
            egresses: Vec::new(),
            rules: Vec::new(),
        }
    }
}

/// A named egress backend. Flat (not a flattened tagged enum) so it round-trips
/// cleanly through TOML serialization, which `persist_config` relies on. The
/// `kind` discriminator selects which of the optional fields apply; the egress
/// builder validates that the required ones are present.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EgressConfig {
    /// Stable identifier referenced by rules (lowercased).
    pub id: String,
    /// Human-friendly display name (defaults to `id`).
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `"direct"` | `"socks5"` | `"wireguard"`.
    pub kind: String,
    // ── socks5 fields ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    // ── wireguard field ──
    /// Raw WireGuard `.conf` text (`[Interface]`/`[Peer]`) pasted in the web UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    // ── evasion (DPI bypass) field ──
    /// Byte offset at which to split the TLS ClientHello. `None` = auto-split
    /// inside the SNI host name. Only used by the `evasion` egress kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seg_position: Option<u16>,
    // ── wireguard tuning ──
    /// Per-connection *receive* socket buffer in KiB for a WireGuard egress.
    /// Larger = higher single-connection download throughput (the TCP window
    /// scales with it) at more RAM. `None` uses the default. Only used by the
    /// `wireguard` egress kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer_kb: Option<u32>,
    /// Per-connection *send* socket buffer in KiB. Bounds one connection's
    /// upload window; tunnel traffic is download-dominant, so `None` defaults
    /// to half of `buffer_kb` (both rings are allocated up-front per
    /// connection). Raise it if a client uploads heavily through the tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_buffer_kb: Option<u32>,
}

/// Maps a domain pattern to an egress. `pattern` is an exact domain (matches the
/// name and its subdomains) or a wildcard (`*.example.com`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleConfig {
    pub pattern: String,
    pub egress: String,
    /// When the chosen egress is unhealthy: refuse the connection (true) rather
    /// than leak it directly (false). Enforced at connect time, not DNS time.
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    /// Restrict the rule to these clients (MAC or IP strings). Empty = all
    /// clients. Lets a domain be routed only for specific devices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<String>,
}

impl ProxyConfig {
    pub fn normalize(&mut self) {
        // An all-whitespace webhook means "no webhook".
        self.alert_webhook = self
            .alert_webhook
            .take()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty());

        // Normalize egress ids/names; drop empties and duplicate ids (last wins).
        let mut seen: HashSet<String> = HashSet::new();
        let mut kept: Vec<EgressConfig> = Vec::with_capacity(self.egresses.len());
        for mut e in std::mem::take(&mut self.egresses).into_iter().rev() {
            e.id = e.id.trim().to_ascii_lowercase();
            e.kind = e.kind.trim().to_ascii_lowercase();
            if e.id.is_empty() {
                tracing::warn!("proxy: dropping egress with empty id");
                continue;
            }
            if !seen.insert(e.id.clone()) {
                tracing::warn!(
                    "proxy: duplicate egress id '{}', keeping last definition",
                    e.id
                );
                continue;
            }
            e.name = if e.name.trim().is_empty() {
                e.id.clone()
            } else {
                e.name.trim().to_string()
            };
            kept.push(e);
        }
        kept.reverse();
        self.egresses = kept;

        // Normalize rule patterns; drop rules referencing an unknown egress.
        let ids: HashSet<&str> = self.egresses.iter().map(|e| e.id.as_str()).collect();
        let mut rules = std::mem::take(&mut self.rules);
        rules.retain_mut(|r| {
            r.pattern = r.pattern.trim().trim_end_matches('.').to_ascii_lowercase();
            r.egress = r.egress.trim().to_ascii_lowercase();
            if r.pattern.is_empty() {
                tracing::warn!("proxy: dropping rule with empty pattern");
                return false;
            }
            if !ids.contains(r.egress.as_str()) {
                tracing::warn!(
                    "proxy: rule '{}' references unknown egress '{}', dropping",
                    r.pattern,
                    r.egress
                );
                return false;
            }
            true
        });
        self.rules = rules;
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:53".parse().unwrap(),
            cache_size: 10_000,
            cache_max_mb: 8,
            min_ttl: 60,
            max_ttl: 3600,
            log_ignore: vec![
                "fe.te".to_string(),
                "*.arpa".to_string(),
                "*.local".to_string(),
                "*.localdomain".to_string(),
            ],
            strip_ecs: true,
            dnssec: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: data_dir().join("ferrite.db"),
            log_retention_days: 0,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".parse().unwrap(),
            api_key: None,
            password_hash: None,
        }
    }
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            domain: "fe.te".to_string(),
            ipv4: None,
            url: None,
        }
    }
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            decision_cache_size: default_blocklist_decision_cache_size(),
            lists: vec![ListConfig {
                url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                name: "StevenBlack".to_string(),
                enabled: true,
            }],
            wildcard_block: vec![],
            whitelist: vec![],
            client_bypass: vec![],
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns: DnsConfig::default(),
            upstream: vec![
                UpstreamConfig::Plain {
                    address: "8.8.8.8".to_string(),
                    port: 53,
                    egress: None,
                },
                UpstreamConfig::Plain {
                    address: "8.8.4.4".to_string(),
                    port: 53,
                    egress: None,
                },
            ],
            storage: StorageConfig::default(),
            api: ApiConfig::default(),
            panel: PanelConfig::default(),
            blocklist: BlocklistConfig::default(),
            zones: vec![],
            custom_records: vec![],
            proxy: ProxyConfig::default(),
            debug_logging: true,
            web_dir: None,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let candidates = Self::config_candidates();

        for path in &candidates {
            if path.exists() {
                tracing::info!("loading config from {}", path.display());
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| FeriteError::Config(format!("read {}: {}", path.display(), e)))?;
                let config: Config = toml::from_str(&raw)?;
                return Ok(config.normalized());
            }
        }

        tracing::warn!(
            "no config file found, using defaults (searched: {})",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok(Config::default())
    }

    pub fn normalized(mut self) -> Self {
        self.normalize();
        self
    }

    pub fn normalize(&mut self) {
        self.api.normalize();
        self.panel.normalize();
        self.blocklist.normalize();
        self.proxy.normalize();
    }

    pub fn config_candidates() -> Vec<PathBuf> {
        vec![
            config_dir().join("config.toml"),
            PathBuf::from("/etc/ferrite/config.toml"),
        ]
    }

    #[allow(dead_code)]
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(&self.clone().normalized())?;
        // Write to a temp file then atomically rename to avoid corrupting config on crash.
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &raw)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

impl ApiConfig {
    pub fn normalize(&mut self) {
        self.api_key = normalize_secret(self.api_key.take());
        self.password_hash = normalize_secret(self.password_hash.take());
    }

    pub fn api_key(&self) -> Option<&str> {
        configured_secret(self.api_key.as_deref())
    }

    pub fn password_hash(&self) -> Option<&str> {
        configured_secret(self.password_hash.as_deref())
    }

    pub fn has_api_key(&self) -> bool {
        self.api_key().is_some()
    }

    pub fn has_password(&self) -> bool {
        self.password_hash().is_some()
    }
}

impl PanelConfig {
    pub fn normalize(&mut self) {
        let domain = self.domain.trim().trim_end_matches('.');
        if domain.is_empty() {
            self.domain = "fe.te".to_string();
        } else {
            self.domain = domain.to_ascii_lowercase();
        }

        self.url = normalize_secret(self.url.take());
    }
}

impl BlocklistConfig {
    pub fn normalize(&mut self) {
        let normalized: BTreeSet<String> = self
            .client_bypass
            .iter()
            .filter_map(|key| normalize_client_key(key))
            .collect();
        self.client_bypass = normalized.into_iter().collect();
    }
}

fn normalize_secret(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn configured_secret(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_serializes_without_option_none_errors() {
        let raw = toml::to_string_pretty(&Config::default()).unwrap();

        assert!(!raw.contains("api_key"));
        assert!(!raw.contains("password_hash"));
        assert!(!raw.contains("bootstrap_ip"));
    }

    #[test]
    fn minimal_config_toml_loads_with_defaults() {
        let cfg: Config = toml::from_str::<Config>(
            r#"
            [dns]
            min_ttl = 120

            [api]
            bind_addr = "127.0.0.1:18080"
            "#,
        )
        .unwrap()
        .normalized();

        assert_eq!(cfg.dns.min_ttl, 120);
        assert_eq!(cfg.dns.max_ttl, 3600);
        assert_eq!(cfg.dns.cache_size, 10_000);
        assert_eq!(cfg.api.bind_addr.to_string(), "127.0.0.1:18080");
        assert!(cfg.storage.path.ends_with("ferrite.db"));
        assert!(!cfg.upstream.is_empty());
        assert!(cfg.panel.enabled);
        assert_eq!(cfg.panel.domain, "fe.te");
    }

    #[test]
    fn unset_optional_fields_are_omitted_but_set_values_are_saved() {
        let mut cfg = Config::default();
        cfg.api.api_key = Some("secret".to_string());
        cfg.api.password_hash = Some("hash".to_string());
        cfg.upstream = vec![UpstreamConfig::Https {
            url: "https://dns.example.test/dns-query".to_string(),
            bootstrap_ip: Some("192.0.2.53".to_string()),
        }];

        let raw = toml::to_string_pretty(&cfg).unwrap();

        assert!(raw.contains("api_key = \"secret\""));
        assert!(raw.contains("password_hash = \"hash\""));
        assert!(raw.contains("bootstrap_ip = \"192.0.2.53\""));
    }

    #[test]
    fn blank_api_secrets_are_treated_as_unset_and_not_saved() {
        let cfg = toml::from_str::<Config>(
            r#"
            [api]
            api_key = "   "
            password_hash = ""
            "#,
        )
        .unwrap()
        .normalized();

        assert!(!cfg.api.has_api_key());
        assert!(!cfg.api.has_password());
        assert!(cfg.api.api_key.is_none());
        assert!(cfg.api.password_hash.is_none());

        let mut cfg = Config::default();
        cfg.api.api_key = Some("   ".to_string());
        cfg.api.password_hash = Some("\t".to_string());
        let raw = toml::to_string_pretty(&cfg.normalized()).unwrap();

        assert!(!raw.contains("api_key"));
        assert!(!raw.contains("password_hash"));
    }

    #[test]
    fn proxy_config_defaults_to_disabled_on_standard_ports() {
        let cfg = Config::default();
        assert!(!cfg.proxy.enabled);
        assert_eq!(cfg.proxy.http_port, 80);
        assert_eq!(cfg.proxy.https_port, 443);
        assert_eq!(cfg.proxy.max_connections, 128);
        assert!(cfg.proxy.egresses.is_empty());
        assert!(cfg.proxy.rules.is_empty());
    }

    #[test]
    fn proxy_config_parses_egresses_and_rules_and_round_trips_toml() {
        let cfg = toml::from_str::<Config>(
            r#"
            [proxy]
            enabled = true
            http_port = 8080
            https_port = 8443
            advertise_ipv4 = "192.168.1.10"

            [[proxy.egresses]]
            id = "Work"
            name = "Work SOCKS"
            kind = "socks5"
            address = "10.0.0.1"
            port = 1080

            [[proxy.rules]]
            pattern = "*.Google.com"
            egress = "work"
            "#,
        )
        .unwrap()
        .normalized();

        assert!(cfg.proxy.enabled);
        assert_eq!(cfg.proxy.http_port, 8080);
        assert_eq!(
            cfg.proxy.advertise_ipv4.unwrap().to_string(),
            "192.168.1.10"
        );
        assert_eq!(cfg.proxy.egresses.len(), 1);
        // id lowercased, name preserved.
        assert_eq!(cfg.proxy.egresses[0].id, "work");
        assert_eq!(cfg.proxy.egresses[0].name, "Work SOCKS");
        assert_eq!(cfg.proxy.egresses[0].kind, "socks5");
        assert_eq!(cfg.proxy.egresses[0].port, Some(1080));
        // rule pattern lowercased + trailing dot stripped; fail_closed defaults true.
        assert_eq!(cfg.proxy.rules.len(), 1);
        assert_eq!(cfg.proxy.rules[0].pattern, "*.google.com");
        assert_eq!(cfg.proxy.rules[0].egress, "work");
        assert!(cfg.proxy.rules[0].fail_closed);

        // Must round-trip through TOML serialization (persist_config relies on it).
        let raw = toml::to_string_pretty(&cfg).unwrap();
        let reparsed = toml::from_str::<Config>(&raw).unwrap().normalized();
        assert_eq!(reparsed.proxy.egresses.len(), 1);
        assert_eq!(reparsed.proxy.rules.len(), 1);
    }

    #[test]
    fn proxy_normalize_drops_dup_egress_ids_and_dangling_rules() {
        let cfg = toml::from_str::<Config>(
            r#"
            [proxy]
            enabled = true

            [[proxy.egresses]]
            id = "a"
            kind = "direct"

            [[proxy.egresses]]
            id = "A"
            kind = "direct"

            [[proxy.rules]]
            pattern = "example.com"
            egress = "a"

            [[proxy.rules]]
            pattern = "leak.com"
            egress = "ghost"
            "#,
        )
        .unwrap()
        .normalized();

        // Duplicate id (case-insensitive) collapses to one.
        assert_eq!(cfg.proxy.egresses.len(), 1);
        assert_eq!(cfg.proxy.egresses[0].id, "a");
        // name defaulted to id.
        assert_eq!(cfg.proxy.egresses[0].name, "a");
        // The rule pointing at a non-existent egress is dropped; the valid one stays.
        assert_eq!(cfg.proxy.rules.len(), 1);
        assert_eq!(cfg.proxy.rules[0].pattern, "example.com");
    }

    #[test]
    fn panel_config_normalizes_blank_domain_and_url() {
        let cfg = toml::from_str::<Config>(
            r#"
            [panel]
            domain = "  "
            url = "   "
            "#,
        )
        .unwrap()
        .normalized();

        assert_eq!(cfg.panel.domain, "fe.te");
        assert!(cfg.panel.url.is_none());
    }
}
