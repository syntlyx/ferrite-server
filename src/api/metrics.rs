//! `GET /api/metrics` — Prometheus text exposition (version 0.0.4).
//!
//! Hand-rolled: the format is a dozen lines of writer code, not worth a crate.
//! Everything is read from counters that already exist (LiveStats atomics,
//! memstats gauges, the proxy's ProxyStats), so a scrape does no locking beyond
//! the per-egress domain-table mutexes it never touches — snapshots are cheap
//! and safe on the hot path.
//!
//! The route sits behind the same auth middleware as the rest of the API:
//! configure Prometheus with `bearer_token` (or an `X-Api-Key` header) when an
//! API key is set, and use `metrics_path: /api/metrics` in the scrape config.
//! Per-domain tables are deliberately NOT exported (unbounded label
//! cardinality); rule patterns and egress ids are config-bounded, so they are.

use std::fmt::Display;
use std::fmt::Write;
use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;

use crate::app::AppState;
use crate::memstats;

const CONTENT_TYPE_PROM: &str = "text/plain; version=0.0.4; charset=utf-8";

pub async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let mut out = String::with_capacity(4096);

    family(
        &mut out,
        "ferrite_build_info",
        "Constant 1, labeled with the ferrite version.",
        "gauge",
    );
    sample(
        &mut out,
        "ferrite_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );

    // ── DNS ──────────────────────────────────────────────────────────────
    let live = &state.inner.live_stats;
    family(
        &mut out,
        "ferrite_dns_queries_total",
        "DNS queries handled, by outcome. The statuses sum to the overall total.",
        "counter",
    );
    for (status, counter) in [
        ("blocked", &live.total_blocked),
        ("allowed", &live.total_allowed),
        ("cached", &live.total_cached),
        ("upstream", &live.total_upstream),
        ("routed", &live.total_routed),
    ] {
        sample(
            &mut out,
            "ferrite_dns_queries_total",
            &[("status", status)],
            counter.load(Ordering::Relaxed),
        );
    }

    family(
        &mut out,
        "ferrite_dns_queries_dropped_total",
        "Query log entries dropped because the stats writer lagged (back-pressure).",
        "counter",
    );
    sample(
        &mut out,
        "ferrite_dns_queries_dropped_total",
        &[],
        live.dropped(),
    );

    family(
        &mut out,
        "ferrite_dns_cache_entries",
        "Entries currently in the DNS response cache.",
        "gauge",
    );
    sample(
        &mut out,
        "ferrite_dns_cache_entries",
        &[],
        state.inner.dns_cache.len(),
    );
    family(
        &mut out,
        "ferrite_dns_cache_bytes",
        "Approximate bytes held by the DNS response cache.",
        "gauge",
    );
    sample(
        &mut out,
        "ferrite_dns_cache_bytes",
        &[],
        state.inner.dns_cache.bytes(),
    );

    family(
        &mut out,
        "ferrite_blocklist_domains",
        "Domains in the compiled blocklist.",
        "gauge",
    );
    sample(
        &mut out,
        "ferrite_blocklist_domains",
        &[],
        state.inner.blocklist.blocked_count(),
    );

    // ── Process ──────────────────────────────────────────────────────────
    family(
        &mut out,
        "ferrite_heap_live_bytes",
        "Live heap bytes (allocated minus freed).",
        "gauge",
    );
    sample(
        &mut out,
        "ferrite_heap_live_bytes",
        &[],
        memstats::heap_live_bytes(),
    );
    family(
        &mut out,
        "ferrite_heap_peak_bytes",
        "High-water mark of live heap bytes.",
        "gauge",
    );
    sample(
        &mut out,
        "ferrite_heap_peak_bytes",
        &[],
        memstats::heap_peak_bytes(),
    );
    if let Some(fds) = memstats::fd_count() {
        family(
            &mut out,
            "ferrite_open_fds",
            "Open file descriptors (Linux only).",
            "gauge",
        );
        sample(&mut out, "ferrite_open_fds", &[], fds);
    }
    if let Some(smaps) = memstats::smaps_rollup() {
        family(
            &mut out,
            "ferrite_rss_bytes",
            "Resident set size (Linux only).",
            "gauge",
        );
        sample(&mut out, "ferrite_rss_bytes", &[], smaps.rss_bytes);
        family(
            &mut out,
            "ferrite_rss_anonymous_bytes",
            "Anonymous (non file-backed) resident memory (Linux only).",
            "gauge",
        );
        sample(
            &mut out,
            "ferrite_rss_anonymous_bytes",
            &[],
            smaps.anonymous_bytes,
        );
    }
    family(
        &mut out,
        "ferrite_proxy_splices_active",
        "Intercepted proxy connections currently alive (client-egress splices).",
        "gauge",
    );
    sample(
        &mut out,
        "ferrite_proxy_splices_active",
        &[],
        memstats::PROXY_CONNS.get(),
    );
    family(
        &mut out,
        "ferrite_wg_virtual_connections_active",
        "Virtual TCP connections currently open inside WireGuard tunnels.",
        "gauge",
    );
    sample(
        &mut out,
        "ferrite_wg_virtual_connections_active",
        &[],
        memstats::WG_CONNS.get(),
    );

    // ── Per-egress (selective routing) ───────────────────────────────────
    let proxy_cfg = state.live_config.read().proxy.clone();
    let proxy = &state.inner.proxy;
    let stats = proxy.stats();

    family(
        &mut out,
        "ferrite_egress_up",
        "1 when the egress is healthy (breaker closed and, for WireGuard, handshake live).",
        "gauge",
    );
    for e in &proxy_cfg.egresses {
        sample(
            &mut out,
            "ferrite_egress_up",
            &[("egress", &e.id)],
            u8::from(proxy.is_egress_healthy(&e.id)),
        );
    }

    family(
        &mut out,
        "ferrite_egress_down_seconds",
        "Seconds the egress has been unhealthy (0 while healthy).",
        "gauge",
    );
    for e in &proxy_cfg.egresses {
        let secs = proxy.down_info(&e.id).map(|(s, _)| s).unwrap_or(0);
        sample(
            &mut out,
            "ferrite_egress_down_seconds",
            &[("egress", &e.id)],
            secs,
        );
    }

    family(
        &mut out,
        "ferrite_egress_wg_handshake_age_seconds",
        "Seconds since the WireGuard handshake (absent for other egress kinds).",
        "gauge",
    );
    for e in &proxy_cfg.egresses {
        if let Some(age) = proxy.egress(&e.id).and_then(|eg| eg.handshake_age_secs()) {
            sample(
                &mut out,
                "ferrite_egress_wg_handshake_age_seconds",
                &[("egress", &e.id)],
                age,
            );
        }
    }

    // Active-probe latency + reachability. Emitted only for egresses probed at
    // least once (each family stays contiguous — see the note below).
    let probes: Vec<_> = proxy_cfg
        .egresses
        .iter()
        .filter_map(|e| stats.probe_snapshot(&e.id).map(|p| (e.id.as_str(), p)))
        .collect();
    family(
        &mut out,
        "ferrite_egress_probe_up",
        "1 if the last active probe through the egress succeeded, else 0.",
        "gauge",
    );
    for (id, p) in &probes {
        sample(
            &mut out,
            "ferrite_egress_probe_up",
            &[("egress", id)],
            u8::from(p.ok),
        );
    }
    family(
        &mut out,
        "ferrite_egress_probe_rtt_ms",
        "Round-trip of the last successful active probe through the egress (ms).",
        "gauge",
    );
    for (id, p) in &probes {
        if let Some(rtt) = p.rtt_ms {
            sample(
                &mut out,
                "ferrite_egress_probe_rtt_ms",
                &[("egress", id)],
                rtt,
            );
        }
    }

    // All samples of a family must form one contiguous block right after its
    // HELP/TYPE header (exposition-format rule), so snapshot every egress once
    // and emit family by family — never interleaved per egress.
    let snapshots: Vec<_> = proxy_cfg
        .egresses
        .iter()
        .map(|e| (e.id.as_str(), stats.egress_snapshot(&e.id)))
        .collect();

    family(
        &mut out,
        "ferrite_egress_connections_active",
        "Connections currently spliced through the egress.",
        "gauge",
    );
    for (id, s) in &snapshots {
        sample(
            &mut out,
            "ferrite_egress_connections_active",
            &[("egress", id)],
            s.active,
        );
    }
    family(
        &mut out,
        "ferrite_egress_connections_total",
        "Connections ever opened through the egress.",
        "counter",
    );
    for (id, s) in &snapshots {
        sample(
            &mut out,
            "ferrite_egress_connections_total",
            &[("egress", id)],
            s.total_conns,
        );
    }
    family(
        &mut out,
        "ferrite_egress_bytes_total",
        "Bytes moved through the egress, by direction (up = client to destination).",
        "counter",
    );
    for (id, s) in &snapshots {
        sample(
            &mut out,
            "ferrite_egress_bytes_total",
            &[("egress", id), ("direction", "up")],
            s.bytes_up,
        );
        sample(
            &mut out,
            "ferrite_egress_bytes_total",
            &[("egress", id), ("direction", "down")],
            s.bytes_down,
        );
    }
    family(
        &mut out,
        "ferrite_egress_connect_failures_total",
        "Failed connect attempts through the egress.",
        "counter",
    );
    for (id, s) in &snapshots {
        sample(
            &mut out,
            "ferrite_egress_connect_failures_total",
            &[("egress", id)],
            s.connect_fails,
        );
    }
    family(
        &mut out,
        "ferrite_egress_fail_closed_drops_total",
        "Client connections dropped by fail-closed rules.",
        "counter",
    );
    for (id, s) in &snapshots {
        sample(
            &mut out,
            "ferrite_egress_fail_closed_drops_total",
            &[("egress", id)],
            s.fail_closed_drops,
        );
    }

    family(
        &mut out,
        "ferrite_rule_hits_total",
        "Connections routed per rule (pattern + egress).",
        "counter",
    );
    for r in stats.rule_hits_snapshot() {
        sample(
            &mut out,
            "ferrite_rule_hits_total",
            &[("pattern", &r.pattern), ("egress", &r.egress)],
            r.hits,
        );
    }

    ([(CONTENT_TYPE, CONTENT_TYPE_PROM)], out)
}

/// Write the `# HELP` / `# TYPE` header for a metric family.
fn family(out: &mut String, name: &str, help: &str, typ: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {typ}");
}

/// Write one sample line, escaping label values per the exposition format.
fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: impl Display) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (i, (k, v)) in labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{k}=\"{}\"", escape_label(v));
        }
        out.push('}');
    }
    let _ = writeln!(out, " {value}");
}

/// Escape a label value: backslash, double-quote, and newline (the three
/// characters the exposition format requires escaping).
fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EgressConfig, ProxyConfig, RuleConfig};
    use crate::test_support;

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape_label(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape_label("x\ny"), "x\\ny");
    }

    #[tokio::test]
    async fn metrics_expose_dns_and_egress_counters() {
        let (state, db) = test_support::app_state("metrics").await;

        // Configure one egress + rule and record some traffic.
        let mut cfg = ProxyConfig {
            enabled: true,
            egresses: vec![EgressConfig {
                id: "vpn".to_string(),
                name: "vpn".to_string(),
                enabled: true,
                kind: "direct".to_string(),
                address: None,
                port: None,
                username: None,
                password: None,
                config: None,
                seg_position: None,
                buffer_kb: None,
                tx_buffer_kb: None,
            }],
            rules: vec![RuleConfig {
                pattern: "*.example.com".to_string(),
                egress: "vpn".to_string(),
                fail_closed: true,
                clients: Vec::new(),
            }],
            ..ProxyConfig::default()
        };
        cfg.normalize();
        state.inner.proxy.reload(&cfg);
        state.live_config.write().proxy = cfg;

        let stats = state.inner.proxy.stats();
        stats.record_rule_hit("*.example.com", "vpn");
        let es = stats.egress("vpn");
        drop(es.begin_conn("www.example.com"));
        es.add_domain_bytes("www.example.com", 10, 200);

        let resp = get_metrics(axum::extract::State(state.clone()))
            .await
            .into_response();
        let (parts, body) = resp.into_parts();
        assert!(
            parts
                .headers
                .get(CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/plain; version=0.0.4"),
        );
        let body = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        for expected in [
            "# TYPE ferrite_dns_queries_total counter",
            "ferrite_dns_queries_total{status=\"blocked\"} ",
            "ferrite_dns_queries_total{status=\"routed\"} ",
            "ferrite_egress_up{egress=\"vpn\"} 1",
            "ferrite_egress_connections_total{egress=\"vpn\"} 1",
            // Egress byte counters are fed by the Counted splice wrapper (unit
            // tested in proxy::stats); here only the exposition wiring matters.
            "ferrite_egress_bytes_total{egress=\"vpn\",direction=\"down\"} 0",
            "ferrite_rule_hits_total{pattern=\"*.example.com\",egress=\"vpn\"} 1",
            "ferrite_egress_down_seconds{egress=\"vpn\"} 0",
        ] {
            assert!(body.contains(expected), "missing `{expected}` in:\n{body}");
        }
        // Per-domain tables must never be exported (unbounded cardinality).
        assert!(!body.contains("www.example.com"), "domain label leaked");

        // Exposition rule: every sample must sit in the contiguous block of the
        // most recent `# TYPE` family — interleaving families breaks parsers.
        let mut current = "";
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                current = rest.split(' ').next().unwrap();
            } else if !line.starts_with('#') && !line.is_empty() {
                let name = line.split(['{', ' ']).next().unwrap();
                assert_eq!(name, current, "sample outside its family block: {line}");
            }
        }

        drop(state);
        test_support::cleanup_sqlite(&db);
    }
}
