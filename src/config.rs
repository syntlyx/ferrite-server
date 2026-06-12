use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
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
        },
        UpstreamConfig::Plain {
            address: "8.8.4.4".to_string(),
            port: 53,
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
    pub min_ttl: u64,
    pub max_ttl: u64,
    /// Domains to suppress from the query log entirely.
    /// Supports exact names (`fe.te`) and wildcard suffixes (`*.local`).
    pub log_ignore: Vec<String>,
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
    },
    Tls {
        address: String,
        port: u16,
        tls_name: String,
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
    50_000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListConfig {
    pub url: String,
    pub name: String,
    pub enabled: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:53".parse().unwrap(),
            cache_size: 10_000,
            min_ttl: 60,
            max_ttl: 3600,
            log_ignore: vec![
                "fe.te".to_string(),
                "*.arpa".to_string(),
                "*.local".to_string(),
                "*.localdomain".to_string(),
            ],
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
                },
                UpstreamConfig::Plain {
                    address: "8.8.4.4".to_string(),
                    port: 53,
                },
            ],
            storage: StorageConfig::default(),
            api: ApiConfig::default(),
            panel: PanelConfig::default(),
            blocklist: BlocklistConfig::default(),
            zones: vec![],
            custom_records: vec![],
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
