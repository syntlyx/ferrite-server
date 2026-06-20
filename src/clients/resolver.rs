use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

use super::{
    ClientRegistry, MISS_TTL, PtrEntry, RESOLVE_TTL, ip_to_ptr_domain, is_link_local_v6, mac, mdns,
};

impl ClientRegistry {
    pub(super) async fn run_pipeline(&self, ip: IpAddr) {
        // Learn (and persist) the IP→MAC binding first, then reuse the MAC for the
        // name lookup so we never query the neighbour table twice in one pipeline.
        let mac = self.learn_ip_mac(ip).await;
        let name = self.resolve(ip, mac).await;
        let ttl = if name.is_some() {
            RESOLVE_TTL
        } else {
            MISS_TTL
        };
        self.ptr_cache.insert(
            ip,
            PtrEntry {
                name,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    async fn resolve(&self, ip: IpAddr, mac: Option<[u8; 6]>) -> Option<String> {
        if let IpAddr::V6(v6) = ip
            && is_link_local_v6(v6)
        {
            return self.resolve_link_local(v6).await;
        }
        self.resolve_normal(ip, mac).await
    }

    /// Link-local IPv6 pipeline:
    /// 1. mDNS directly on the link-local address (also handles Avahi).
    /// 2. NDP/EUI-64 MAC → ARP → IPv4 → upstream PTR / mDNS on IPv4.
    async fn resolve_link_local(&self, v6: Ipv6Addr) -> Option<String> {
        let ip = IpAddr::V6(v6);
        let device_mac = self
            .mac_for_ip(ip)
            .or_else(|| super::mac::extract_eui64_mac(v6));

        // Fast path: fresh MAC cache hit.
        if let Some(m) = device_mac
            && let Some(entry) = self.mac_to_name.get(&m)
            && Instant::now() < entry.1
        {
            return Some(entry.0.clone());
        }

        // mDNS directly on the link-local address.
        if let Some(raw) = mdns::mdns_ptr_lookup(IpAddr::V6(v6)).await {
            let name = normalize_hostname(&raw);
            tracing::debug!("fe80::{} → '{}' via mDNS", v6, name);
            if let Some(m) = device_mac {
                self.cache_mac(m, &name).await;
            }
            return Some(name);
        }

        // MAC fallback: ARP table → IPv4 address → full pipeline.
        let m = device_mac?;
        let ipv4 = match mac::lookup_ipv4_for_mac(m).await {
            Some(ip) => ip,
            None => {
                tracing::debug!("fe80::{}: MAC {:02x?} not in ARP table", v6, m);
                return None;
            }
        };
        tracing::debug!("fe80::{} → ARP {:02x?} → IPv4 {}", v6, m, ipv4);

        // Resolve the IPv4 PTR directly; cache the result under the link-local
        // device's MAC (passing None avoids a redundant ARP lookup for the v4).
        let name = self.resolve_normal(IpAddr::V4(ipv4), None).await;
        if let Some(ref n) = name {
            tracing::debug!("fe80::{} → '{}' via MAC→IPv4→resolve", v6, n);
            self.cache_mac(m, n).await;
        }
        name
    }

    /// Normal (non-link-local) pipeline: upstream PTR → mDNS.
    /// When `mac` is known, the resolved name is cached and persisted against it.
    async fn resolve_normal(&self, ip: IpAddr, mac: Option<[u8; 6]>) -> Option<String> {
        if let Some(raw) = self.upstream_ptr(ip).await {
            let name = normalize_hostname(&raw);
            if let Some(m) = mac {
                self.cache_mac(m, &name).await;
            }
            return Some(name);
        }
        if let Some(raw) = mdns::mdns_ptr_lookup(ip).await {
            let name = normalize_hostname(&raw);
            tracing::debug!("mDNS {} → '{}'", ip, name);
            if let Some(m) = mac {
                self.cache_mac(m, &name).await;
            }
            return Some(name);
        }
        None
    }

    async fn upstream_ptr(&self, ip: IpAddr) -> Option<String> {
        let ptr_domain = ip_to_ptr_domain(ip);
        tracing::debug!("PTR lookup: {}", ptr_domain);
        let raw = build_ptr_query(&ptr_domain)?;
        match self.upstream.resolve_raw(raw).await {
            Ok((response, _)) => {
                let name = parse_ptr_response(&response);
                if let Some(ref n) = name {
                    tracing::debug!("PTR {} → {}", ip, n);
                }
                name
            }
            Err(e) => {
                tracing::debug!("PTR {} failed: {}", ip, e);
                None
            }
        }
    }

    /// Resolve the current MAC for `ip` and keep the persisted binding in sync.
    ///
    /// EUI-64 IPv6 carries its MAC inline, so no neighbour lookup is needed. For
    /// everything else we consult the live neighbour table and persist the binding
    /// whenever it is new or changed ("last binding wins"). If the device is
    /// currently offline we fall back to the last known binding so a learned
    /// mapping is never lost.
    async fn learn_ip_mac(&self, ip: IpAddr) -> Option<[u8; 6]> {
        if let IpAddr::V6(v6) = ip
            && let Some(m) = super::mac::extract_eui64_mac(v6)
        {
            return Some(m);
        }
        match mac::lookup_mac_for_ip(ip).await {
            Some(m) => {
                if self.ip_to_mac.get(&ip).map(|e| *e) != Some(m) {
                    tracing::debug!("learned MAC {:02x?} for {}", m, ip);
                    self.ip_to_mac.insert(ip, m);
                    self.persist_binding(ip, m).await;
                }
                Some(m)
            }
            None => self.ip_to_mac.get(&ip).map(|e| *e),
        }
    }

    /// Cache `name` for `mac` (in-memory, with TTL) and persist it as the device's
    /// last-known hostname. The DB write is skipped when the name is unchanged.
    pub(super) async fn cache_mac(&self, mac: [u8; 6], name: &str) {
        let changed = self
            .mac_to_name
            .get(&mac)
            .map(|e| e.0 != name)
            .unwrap_or(true);
        self.mac_to_name
            .insert(mac, (name.to_owned(), Instant::now() + RESOLVE_TTL));
        if changed {
            self.persist_device(mac, name).await;
        }
    }

    /// Best-effort persistence of a device's last-known hostname. Never blocks
    /// resolution: a failed write is logged and dropped.
    async fn persist_device(&self, mac: [u8; 6], name: &str) {
        if let Err(e) = self
            .storage
            .upsert_device(&super::format_mac(&mac), Some(name))
            .await
        {
            tracing::debug!("failed to persist device {:02x?}: {}", mac, e);
        }
    }

    /// Best-effort persistence of an IP→MAC binding.
    pub(super) async fn persist_binding(&self, ip: IpAddr, mac: [u8; 6]) {
        if let Err(e) = self
            .storage
            .upsert_ip_binding(&ip.to_string(), &super::format_mac(&mac))
            .await
        {
            tracing::debug!("failed to persist binding {} → {:02x?}: {}", ip, mac, e);
        }
    }
}

// ── DNS helpers ───────────────────────────────────────────────────────────────

fn build_ptr_query(ptr_domain: &str) -> Option<Vec<u8>> {
    let name = Name::from_ascii(ptr_domain).ok()?;

    let mut question = Query::new();
    question.set_name(name);
    question.set_query_type(RecordType::PTR);
    question.set_query_class(DNSClass::IN);

    let mut msg = Message::new(super::random_query_id()?, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(question);

    msg.to_bytes().ok()
}

fn parse_ptr_response(bytes: &[u8]) -> Option<String> {
    let msg = Message::from_bytes(bytes).ok()?;
    for answer in &msg.answers {
        if let RData::PTR(ptr) = &answer.data {
            let s = ptr.to_string();
            let s = s.trim_end_matches('.');
            if !s.is_empty() {
                return Some(s.to_ascii_lowercase());
            }
        }
    }
    None
}

fn normalize_hostname(name: &str) -> String {
    for suffix in super::LOCAL_SUFFIXES {
        if let Some(host) = name.strip_suffix(suffix)
            && !host.is_empty()
        {
            return host.to_owned();
        }
    }
    name.to_owned()
}
