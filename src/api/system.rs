use std::time::{Duration, Instant};

use axum::extract::State;
use axum::Json;
use serde_json::Value;

use crate::api::ApiError;
use crate::app::AppState;
use crate::error::FeriteError;

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
        if let Some((ts, ref val)) = *cache {
            if ts.elapsed() < SYSTEM_STATS_TTL {
                return Ok(Json(val.clone()));
            }
        }
    }

    let global_cpu = state.cpu_sampler.global_cpu_percent();
    let process_cpu = state.cpu_sampler.process_cpu_percent();

    let stats = tokio::task::spawn_blocking(move || system_snapshot(global_cpu, process_cpu))
        .await
        .map_err(|e| ApiError(FeriteError::Internal(e.to_string())))?;

    *state.system_stats_cache.lock() = Some((Instant::now(), stats.clone()));

    Ok(Json(stats))
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
        "memory": memory_snapshot(total_mem, available_mem, free_mem),
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

fn memory_snapshot(total: u64, available: u64, free: u64) -> Value {
    // For dashboard pressure, prefer MemAvailable semantics: reclaimable page
    // cache should not make the machine look more loaded than it is.
    let used = total.saturating_sub(available);
    let allocated = total.saturating_sub(free);
    let reclaimable = available.saturating_sub(free);

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
        if link_speed_mbps.is_none() {
            if let Ok(s) = std::fs::read_to_string(format!("/sys/class/net/{}/speed", name)) {
                if let Ok(mbps) = s.trim().parse::<i64>() {
                    if mbps > 0 {
                        link_speed_mbps = Some(mbps as u64);
                    }
                }
            }
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

    #[test]
    fn memory_snapshot_uses_available_memory_for_pressure() {
        let memory = memory_snapshot(3_905, 3_264, 2_795);

        assert_eq!(memory["used_bytes"].as_u64(), Some(641));
        assert_eq!(memory["allocated_bytes"].as_u64(), Some(1_110));
        assert_eq!(memory["reclaimable_bytes"].as_u64(), Some(469));
    }
}
