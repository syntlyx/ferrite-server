use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

use super::{
    ip_to_ptr_domain, is_link_local_v6, mac, mdns, ClientRegistry, PtrEntry, MISS_TTL, RESOLVE_TTL,
};

impl ClientRegistry {
    pub(super) async fn run_pipeline(&self, ip: IpAddr) {
        self.learn_ip_mac(ip).await;
        let name = self.resolve(ip).await;
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

    async fn resolve(&self, ip: IpAddr) -> Option<String> {
        if let IpAddr::V6(v6) = ip {
            if is_link_local_v6(v6) {
                return self.resolve_link_local(v6).await;
            }
        }
        self.resolve_normal(ip).await
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
        if let Some(m) = device_mac {
            if let Some(entry) = self.mac_to_name.get(&m) {
                if Instant::now() < entry.1 {
                    return Some(entry.0.clone());
                }
            }
        }

        // mDNS directly on the link-local address.
        if let Some(raw) = mdns::mdns_ptr_lookup(IpAddr::V6(v6)).await {
            let name = normalize_hostname(&raw);
            tracing::debug!("fe80::{} → '{}' via mDNS", v6, name);
            if let Some(m) = device_mac {
                self.cache_mac(m, &name);
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

        let name = self.resolve_normal(IpAddr::V4(ipv4)).await;
        if let Some(ref n) = name {
            tracing::debug!("fe80::{} → '{}' via MAC→IPv4→resolve", v6, n);
            self.cache_mac(m, n);
        }
        name
    }

    /// Normal (non-link-local) pipeline: upstream PTR → mDNS.
    async fn resolve_normal(&self, ip: IpAddr) -> Option<String> {
        if let Some(raw) = self.upstream_ptr(ip).await {
            let name = normalize_hostname(&raw);
            self.learn_mac(ip, &name).await;
            return Some(name);
        }
        if let Some(raw) = mdns::mdns_ptr_lookup(ip).await {
            let name = normalize_hostname(&raw);
            tracing::debug!("mDNS {} → '{}'", ip, name);
            self.learn_mac(ip, &name).await;
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

    /// Look up the neighbour-table MAC for `ip` and keep the IP→MAC map warm.
    async fn learn_ip_mac(&self, ip: IpAddr) -> Option<[u8; 6]> {
        if let Some(m) = self.mac_for_ip(ip) {
            return Some(m);
        }
        let m = mac::lookup_mac_for_ip(ip).await?;
        tracing::debug!("learned MAC {:02x?} from {}", m, ip);
        self.ip_to_mac.insert(ip, m);
        Some(m)
    }

    /// Look up the neighbour-table MAC for `ip` and store `name` in the MAC cache.
    async fn learn_mac(&self, ip: IpAddr, name: &str) {
        if let Some(m) = self.learn_ip_mac(ip).await {
            tracing::debug!("learned MAC {:02x?} → '{}' from {}", m, name, ip);
            self.cache_mac(m, name);
        }
    }

    pub(super) fn cache_mac(&self, mac: [u8; 6], name: &str) {
        self.mac_to_name
            .insert(mac, (name.to_owned(), Instant::now() + RESOLVE_TTL));
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
        if let Some(host) = name.strip_suffix(suffix) {
            if !host.is_empty() {
                return host.to_owned();
            }
        }
    }
    name.to_owned()
}
