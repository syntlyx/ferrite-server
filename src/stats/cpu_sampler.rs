use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

struct Inner {
    sys: System,
    pid: Option<Pid>,
}

/// Tracks ferrite process CPU usage by periodically calling sysinfo.
///
/// sysinfo 0.32 computes process CPU deltas only on `ProcessesToUpdate::All`;
/// refreshing only the current PID updates process fields but leaves
/// `Process::cpu_usage()` at zero. Keep this sampler CPU-only so the global
/// process refresh stays cheap.
///
/// `tick()` takes `&self` and uses an internal `std::sync::Mutex` so the
/// caller never needs to hold an external lock. The result is cached in an
/// `AtomicU32` so `cpu_percent()` is always lock-free and safe to call from
/// async context without blocking the tokio worker thread.
pub struct CpuSampler {
    inner: Mutex<Inner>,
    cached_cpu: AtomicU32,
}

impl CpuSampler {
    pub fn new() -> Self {
        let mut sys = System::new();
        let pid = sysinfo::get_current_pid().ok();
        refresh_process_cpu(&mut sys);
        Self {
            inner: Mutex::new(Inner { sys, pid }),
            cached_cpu: AtomicU32::new(0),
        }
    }

    /// Refresh the sysinfo snapshot and cache the new CPU value.
    /// Designed to be called from `tokio::task::spawn_blocking`.
    pub fn tick(&self) {
        let Ok(mut g) = self.inner.lock() else { return };
        refresh_process_cpu(&mut g.sys);
        if let Some(pid) = g.pid {
            let cpu = g.sys.process(pid).map(|p| p.cpu_usage()).unwrap_or(0.0);
            self.cached_cpu.store(cpu.to_bits(), Ordering::Relaxed);
        }
    }

    /// Return the last sampled CPU usage. Lock-free — safe from async context.
    pub fn cpu_percent(&self) -> f32 {
        f32::from_bits(self.cached_cpu.load(Ordering::Relaxed))
    }
}

fn refresh_process_cpu(sys: &mut System) {
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        false,
        ProcessRefreshKind::new().with_cpu(),
    );
}
