use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

struct Inner {
    sys: System,
    pid: Option<Pid>,
}

/// Tracks global and ferrite-process CPU usage by periodically calling sysinfo.
///
/// Both values are sampled in the same `tick()`. The process value is
/// normalized to the whole machine (sysinfo reports it as a percentage of a
/// single core) and then clamped to the global figure: the two come from
/// separate refreshes whose delta windows don't align exactly, so without the
/// clamp the normalized process value can momentarily exceed global. With it,
/// `process <= global` always holds.
///
/// sysinfo 0.32 computes process CPU deltas only on `ProcessesToUpdate::All`;
/// refreshing only the current PID updates process fields but leaves
/// `Process::cpu_usage()` at zero. Keep this sampler CPU-only so the global
/// process refresh stays cheap.
///
/// `tick()` takes `&self` and uses an internal `std::sync::Mutex` so the
/// caller never needs to hold an external lock. Results are cached in
/// `AtomicU32`s so the getters are always lock-free and safe to call from
/// async context without blocking the tokio worker thread.
pub struct CpuSampler {
    inner: Mutex<Inner>,
    cached_process_cpu: AtomicU32,
    cached_global_cpu: AtomicU32,
}

impl CpuSampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        let pid = sysinfo::get_current_pid().ok();
        // Baseline refresh: the first tick() computes deltas against this.
        sys.refresh_cpu_usage();
        refresh_process_cpu(&mut sys);
        Self {
            inner: Mutex::new(Inner { sys, pid }),
            cached_process_cpu: AtomicU32::new(0),
            cached_global_cpu: AtomicU32::new(0),
        }
    }

    /// Refresh the sysinfo snapshot and cache the new CPU values.
    /// Designed to be called from `tokio::task::spawn_blocking`.
    pub fn tick(&self) {
        let Ok(mut g) = self.inner.lock() else { return };
        g.sys.refresh_cpu_usage();
        refresh_process_cpu(&mut g.sys);

        let global = g.sys.global_cpu_usage();
        self.cached_global_cpu
            .store(global.to_bits(), Ordering::Relaxed);

        if let Some(pid) = g.pid {
            let cores = g.sys.cpus().len().max(1) as f32;
            let per_core = g.sys.process(pid).map(|p| p.cpu_usage()).unwrap_or(0.0);
            // The process is part of the global figure, so it can never legitimately
            // exceed it. The global and per-process values come from two separate
            // refreshes whose delta windows don't line up exactly, so the normalized
            // process value can momentarily read higher than global; clamp to [0,
            // global] to absorb that skew and keep `process <= global` from inverting.
            let process = (per_core / cores).clamp(0.0, global.max(0.0));
            self.cached_process_cpu
                .store(process.to_bits(), Ordering::Relaxed);
        }
    }

    /// Ferrite process CPU as a share of the whole machine, from the last tick.
    /// Lock-free — safe from async context.
    pub fn process_cpu_percent(&self) -> f32 {
        f32::from_bits(self.cached_process_cpu.load(Ordering::Relaxed))
    }

    /// Global CPU usage averaged over all cores, from the last tick.
    /// Lock-free — safe from async context.
    pub fn global_cpu_percent(&self) -> f32 {
        f32::from_bits(self.cached_global_cpu.load(Ordering::Relaxed))
    }
}

fn refresh_process_cpu(sys: &mut System) {
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        false,
        ProcessRefreshKind::nothing().with_cpu(),
    );
}
