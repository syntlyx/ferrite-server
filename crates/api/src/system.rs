use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use serde_json::Value;

use crate::ApiError;
use ferrite_app::AppState;
use ferrite_core::error::FeriteError;

/// Cache TTL for system stats — sysinfo is expensive (200ms sleep + hwmon reads).
const SYSTEM_STATS_TTL: Duration = Duration::from_secs(3);

/// Sampling window for network throughput (delta between two refreshes).
const NET_SAMPLE_WINDOW: Duration = Duration::from_millis(200);

/// GET /api/stats/system — CPU, memory, swap, network I/O, disk, temperature, uptime.
///
/// Result is cached for 3 seconds to prevent concurrent sysinfo spawns when the
/// dashboard polls frequently (multiple tabs, reconnects, etc.).
///
/// Both CPU values come from the shared `CpuSampler` (same tick, same window),
/// so global and process usage are directly comparable.
pub async fn get_system_stats(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    // Return cached value if still fresh.
    {
        let cache = state.system_stats_cache.lock();
        if let Some((ts, ref val)) = *cache
            && ts.elapsed() < SYSTEM_STATS_TTL
        {
            return Ok(Json(val.clone()));
        }
    }

    let global_cpu = state.cpu_sampler.global_cpu_percent();
    let process_cpu = state.cpu_sampler.process_cpu_percent();

    let mut stats = tokio::task::spawn_blocking(move || system_snapshot(global_cpu, process_cpu))
        .await
        .map_err(|e| ApiError(FeriteError::Internal(e.to_string())))?;

    stats["ferrite"] = ferrite_internals(&state);

    *state.system_stats_cache.lock() = Some((Instant::now(), stats.clone()));

    Ok(Json(stats))
}

/// ferrite's own memory accounting — every structure that could conceivably
/// grow, so an RSS increase can be attributed (or ruled out) from the panel.
/// The attribution chain, top down:
///   `rss - rss_anonymous`         = file-backed (mmap'd FSTs, binary text) —
///                                   kernel-reclaimable, not a leak;
///   `rss_anonymous - heap_live`   = allocator retention/fragmentation plus
///                                   the small non-Rust remainder (bundled
///                                   SQLite on libc malloc, thread stacks);
///   `heap_live_bytes` growing     = the code holds it — find the counter
///                                   below that grew with it.
/// `mimalloc_commit_bytes` is mimalloc's internal committed-slices counter,
/// NOT residency: on overcommit Linux it can sit far above `rss_anonymous`
/// (observed 98 MB vs 16 MB resident) and behaves as a high-water mark of
/// arena slice usage. Watch its trend, never subtract it from RSS.
///
/// And before reading a large `rss_anonymous` as a problem: on a machine with
/// free memory the allocator keeps pages it no longer needs, because nothing
/// is asking for them back. Measured on Linux/musl with a million-domain
/// blocklist — the heaviest thing ferrite does — `rss_anonymous` settles
/// anywhere between 4 MB and 140 MB from run to run while `heap_live` stays at
/// 1.6 MB; the same build under a 24 MB cgroup limit refreshes that same list
/// and serves it in ~15 MB RSS. What the process *needs* is the transient
/// demand of a refresh, not the number RSS shows when memory is free. Chase
/// `heap_live` and `heap_peak`; treat a large `rss_anonymous` with a flat
/// `heap_live` as retention, and confirm it with a memory limit before
/// believing it is a leak.
fn ferrite_internals(state: &AppState) -> Value {
    let (ptr_cache, ip_to_mac) = state.inner.client_registry.cache_sizes();
    let rss = ferrite_core::memstats::smaps_rollup();
    let alloc = ferrite_core::memstats::mimalloc_commit();
    serde_json::json!({
        "heap_live_bytes": ferrite_core::memstats::heap_live_bytes(),
        "heap_peak_bytes": ferrite_core::memstats::heap_peak_bytes(),
        "mimalloc_commit_bytes": alloc.commit_bytes,
        "mimalloc_commit_peak_bytes": alloc.commit_peak_bytes,
        "rss_bytes": rss.as_ref().map(|r| r.rss_bytes),
        "rss_anonymous_bytes": rss.as_ref().map(|r| r.anonymous_bytes),
        "fd_count": ferrite_core::memstats::fd_count(),
        "dns_cache": {
            "entries": state.inner.dns_cache.len(),
            "bytes":   state.inner.dns_cache.bytes(),
        },
        "blocklist_decision_cache_entries": state.inner.blocklist.decision_cache_entries(),
        "client_registry": { "ptr_cache": ptr_cache, "ip_to_mac": ip_to_mac },
        "proxy_active_connections": ferrite_core::memstats::PROXY_CONNS.get(),
        "wg_virtual_connections":   ferrite_core::memstats::WG_CONNS.get(),
        "sessions": state.sessions.len(),
    })
}

fn system_snapshot(global_cpu: f32, process_cpu: f32) -> Value {
    use sysinfo::{Components, Networks, ProcessesToUpdate, System};

    let mut sys = System::new();
    let mut networks = Networks::new_with_refreshed_list();
    let self_pid = sysinfo::get_current_pid().ok();

    sys.refresh_memory();
    if let Some(pid) = self_pid {
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
    }

    // Network throughput needs a delta between two refreshes.
    std::thread::sleep(NET_SAMPLE_WINDOW);
    networks.refresh(true);

    let interval_secs = NET_SAMPLE_WINDOW.as_secs_f64();

    let total_mem = sys.total_memory();
    let available_mem = sys.available_memory();
    let free_mem = sys.free_memory();
    let cache_mem = meminfo_cache_bytes();
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();
    let uptime = System::uptime();
    let load = System::load_average();

    let cpu_temp: Option<f32> = Components::new_with_refreshed_list()
        .iter()
        .find_map(|c| c.temperature().filter(|t| t.is_finite() && *t > 0.0));

    let (rx_bytes, tx_bytes, link_speed_mbps, active_ifaces) = collect_network(&networks);

    let rx_per_sec = (rx_bytes as f64 / interval_secs) as u64;
    let tx_per_sec = (tx_bytes as f64 / interval_secs) as u64;
    let (rx_util, tx_util) = match link_speed_mbps {
        Some(mbps) => {
            let cap = mbps as f64 * 1_000_000.0;
            let rx = (rx_per_sec as f64 * 8.0 / cap * 100.0).min(100.0);
            let tx = (tx_per_sec as f64 * 8.0 / cap * 100.0).min(100.0);
            (Some(rx), Some(tx))
        }
        None => (None, None),
    };

    let process_stats = self_pid.and_then(|pid| sys.process(pid)).map(|p| {
        let mem = p.memory();
        serde_json::json!({
            "memory_bytes":   mem,
            "memory_percent": percent(mem, total_mem),
            "cpu_percent":    process_cpu,
        })
    });

    let disk = collect_disk();

    serde_json::json!({
        "cpu_usage_percent": global_cpu,
        "cpu_temp_celsius":  cpu_temp,
        "memory": memory_snapshot(total_mem, available_mem, free_mem, cache_mem),
        "swap": {
            "total_bytes":  total_swap,
            "used_bytes":   used_swap,
            "used_percent": percent(used_swap, total_swap),
        },
        "network": {
            "interfaces":             active_ifaces,
            "rx_bytes_per_sec":       rx_per_sec,
            "tx_bytes_per_sec":       tx_per_sec,
            "link_speed_mbps":        link_speed_mbps,
            "rx_utilization_percent": rx_util,
            "tx_utilization_percent": tx_util,
        },
        "disk":    disk,
        "process": process_stats,
        "load_avg": { "one": load.one, "five": load.five, "fifteen": load.fifteen },
        "uptime_seconds": uptime,
    })
}

/// Buffers + page cache + reclaimable slab — `free`'s "buff/cache" column,
/// from `/proc/meminfo` (Linux only; `None` elsewhere). sysinfo reports
/// MemFree and MemAvailable but not the cache, and MemAvailable alone cannot
/// stand in for it: it is an estimate that withholds the kernel's watermark
/// reserve and counts only the part of the cache it expects to get back, so on
/// an idle box it sits *below* MemFree and `total - available` charges the
/// dashboard for cache nobody asked for.
fn meminfo_cache_bytes() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    parse_meminfo_cache(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

fn parse_meminfo_cache(text: &str) -> Option<u64> {
    let field = |name: &str| -> Option<u64> {
        let kb: u64 = text
            .lines()
            .find(|l| l.starts_with(name))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb * 1024)
    };
    // `Cached` already includes Shmem, exactly as `free` counts it;
    // `SReclaimable` is missing on kernels older than 2.6.19.
    Some(field("Buffers:")? + field("Cached:")? + field("SReclaimable:").unwrap_or(0))
}

/// The memory block the dashboard draws, in `free`'s accounting: `used` is
/// what is neither free nor cache. Page cache is the kernel making use of idle
/// RAM and it is handed back on demand, so counting it as used makes a router
/// doing nothing look half-loaded — the box below reported 408 MB used against
/// `free`'s 170 MB, the difference being 221 MB of cache plus the watermark
/// reserve. Without `/proc` (non-Linux) the MemAvailable estimate is the best
/// available stand-in, and the arithmetic below falls back to exactly it.
fn memory_snapshot(total: u64, available: u64, free: u64, cache: Option<u64>) -> Value {
    let reclaimable = cache.unwrap_or_else(|| available.saturating_sub(free));
    let used = total.saturating_sub(free).saturating_sub(reclaimable);
    let allocated = total.saturating_sub(free);

    serde_json::json!({
        "total_bytes":       total,
        "used_bytes":        used,
        "used_percent":      percent(used, total),
        "available_bytes":   available,
        "free_bytes":        free,
        "allocated_bytes":   allocated,
        "reclaimable_bytes": reclaimable,
    })
}

fn percent(value: u64, total: u64) -> f64 {
    if total > 0 {
        value as f64 / total as f64 * 100.0
    } else {
        0.0
    }
}

fn collect_network(networks: &sysinfo::Networks) -> (u64, u64, Option<u64>, Vec<String>) {
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut link_speed_mbps: Option<u64> = None;
    let mut active_ifaces: Vec<String> = Vec::new();

    for (name, data) in networks {
        if name == "lo" || name == "lo0" {
            continue;
        }
        // Skip interfaces that are explicitly reported as down.
        let operstate = std::fs::read_to_string(format!("/sys/class/net/{}/operstate", name))
            .unwrap_or_default();
        match operstate.trim() {
            "down" | "notpresent" | "lowerlayerdown" => continue,
            _ => {}
        }
        rx_bytes += data.received();
        tx_bytes += data.transmitted();
        active_ifaces.push(name.clone());
        if link_speed_mbps.is_none()
            && let Ok(s) = std::fs::read_to_string(format!("/sys/class/net/{}/speed", name))
            && let Ok(mbps) = s.trim().parse::<i64>()
            && mbps > 0
        {
            link_speed_mbps = Some(mbps as u64);
        }
    }
    (rx_bytes, tx_bytes, link_speed_mbps, active_ifaces)
}

fn collect_disk() -> Option<Value> {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .find(|d| d.mount_point() == std::path::Path::new("/"))
        .or_else(|| disks.iter().next())
        .map(|d| {
            let total = d.total_space();
            let used = total.saturating_sub(d.available_space());
            serde_json::json!({
                "mount":        d.mount_point().to_string_lossy(),
                "total_bytes":  total,
                "used_bytes":   used,
                "used_percent": percent(used, total),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prefixes have to match whole field names: `Cached:` must not pick
    /// up `SwapCached:`, and the sum is Buffers + Cached + SReclaimable —
    /// `free`'s buff/cache column, 226 700 kB for this excerpt.
    #[test]
    fn parse_meminfo_cache_sums_the_buff_cache_column() {
        let text = "\
MemTotal:        3998540 kB
MemFree:         3598416 kB
MemAvailable:    3580652 kB
Buffers:           21044 kB
Cached:           185424 kB
SwapCached:            0 kB
Active:           142172 kB
Shmem:             40296 kB
SReclaimable:      20232 kB
SUnreclaim:        19488 kB
";
        assert_eq!(parse_meminfo_cache(text), Some(226_700 * 1024));
    }

    /// A kernel too old to report reclaimable slab still gives buffers+cache.
    #[test]
    fn parse_meminfo_cache_tolerates_a_missing_sreclaimable() {
        let text = "MemTotal: 100 kB\nBuffers: 4 kB\nCached: 8 kB\n";
        assert_eq!(parse_meminfo_cache(text), Some(12 * 1024));
    }

    /// The numbers are one real reading from an idle router, in MiB:
    /// `free -m` there prints 170 used, 3514 free, 221 buff/cache, 3497
    /// available — note available *below* free, which is what made the old
    /// `total - available` read 408.
    #[test]
    fn memory_snapshot_excludes_page_cache_the_way_free_does() {
        let memory = memory_snapshot(3_905, 3_497, 3_514, Some(221));

        assert_eq!(memory["used_bytes"].as_u64(), Some(170));
        assert_eq!(memory["allocated_bytes"].as_u64(), Some(391));
        assert_eq!(memory["reclaimable_bytes"].as_u64(), Some(221));
    }

    /// No `/proc` to read the cache from: MemAvailable carries the estimate.
    #[test]
    fn memory_snapshot_falls_back_to_available_memory() {
        let memory = memory_snapshot(3_905, 3_264, 2_795, None);

        assert_eq!(memory["used_bytes"].as_u64(), Some(641));
        assert_eq!(memory["allocated_bytes"].as_u64(), Some(1_110));
        assert_eq!(memory["reclaimable_bytes"].as_u64(), Some(469));
    }
}
