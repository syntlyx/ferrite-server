//! Process-level memory introspection: a counting global-allocator wrapper,
//! RAII connection gauges, and /proc-based fd counting. Powers the `ferrite`
//! section of `GET /api/stats/system`, so "RSS grew — where?" is answerable
//! from the panel instead of a heap profiler on the router.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Live heap bytes (allocated minus freed), maintained by [`CountingAlloc`].
static HEAP_LIVE: AtomicUsize = AtomicUsize::new(0);
/// High-water mark of [`HEAP_LIVE`].
static HEAP_PEAK: AtomicUsize = AtomicUsize::new(0);

/// Global-allocator wrapper that keeps a live-bytes counter next to the real
/// allocator (two relaxed atomics per alloc/free — noise next to the allocation
/// itself). The counter separates the two failure modes that look identical
/// from outside: "the code is holding memory" (live grows with RSS) vs "the
/// allocator isn't returning freed pages to the OS" (live flat, RSS grows).
pub struct CountingAlloc<A>(pub A);

impl<A> CountingAlloc<A> {
    fn add(size: usize) {
        let now = HEAP_LIVE.fetch_add(size, Ordering::Relaxed) + size;
        HEAP_PEAK.fetch_max(now, Ordering::Relaxed);
    }

    fn sub(size: usize) {
        HEAP_LIVE.fetch_sub(size, Ordering::Relaxed);
    }
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for CountingAlloc<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { self.0.alloc(layout) };
        if !p.is_null() {
            Self::add(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { self.0.alloc_zeroed(layout) };
        if !p.is_null() {
            Self::add(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.0.dealloc(ptr, layout) };
        Self::sub(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { self.0.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            Self::sub(layout.size());
            Self::add(new_size);
        }
        p
    }
}

pub fn heap_live_bytes() -> usize {
    HEAP_LIVE.load(Ordering::Relaxed)
}

pub fn heap_peak_bytes() -> usize {
    HEAP_PEAK.load(Ordering::Relaxed)
}

/// An up/down counter with RAII decrement — for "how many X are alive right
/// now" gauges. Holding the [`GaugeGuard`] in the object being counted makes
/// every exit path (clean close, error, task abort, whole-tunnel teardown)
/// decrement exactly once.
pub struct Gauge(AtomicUsize);

impl Gauge {
    pub const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    pub fn guard(&'static self) -> GaugeGuard {
        self.0.fetch_add(1, Ordering::Relaxed);
        GaugeGuard(self)
    }

    pub fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

pub struct GaugeGuard(&'static Gauge);

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        (self.0).0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Intercepted proxy connections currently alive (client ⇄ egress splices).
pub static PROXY_CONNS: Gauge = Gauge::new();
/// Virtual TCP connections currently open inside WireGuard tunnels.
pub static WG_CONNS: Gauge = Gauge::new();

/// Total and anonymous resident set from `/proc/self/smaps_rollup` (Linux
/// only; `None` elsewhere). Anonymous is the process's "real" memory (heaps,
/// thread stacks); `rss - anonymous` is file-backed pages (mmap'd FSTs,
/// binary text) that the kernel reclaims under memory pressure for free.
pub struct SmapsRollup {
    pub rss_bytes: u64,
    pub anonymous_bytes: u64,
}

pub fn smaps_rollup() -> Option<SmapsRollup> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let text = std::fs::read_to_string("/proc/self/smaps_rollup").ok()?;
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
    Some(SmapsRollup {
        rss_bytes: field("Rss:")?,
        anonymous_bytes: field("Anonymous:")?,
    })
}

/// mimalloc's internal committed-slices counter (`stats.committed`). NOT
/// residency: on overcommit Linux it behaves as a high-water mark of arena
/// slice usage and can sit far above resident anonymous memory (observed
/// 98 MB while only 16 MB was resident). Useful as a trend/ceiling signal;
/// for "how much RAM does the allocator actually hold" use
/// [`smaps_rollup`]'s `anonymous_bytes` minus [`heap_live_bytes`].
pub struct AllocatorCommit {
    pub commit_bytes: usize,
    pub commit_peak_bytes: usize,
}

pub fn mimalloc_commit() -> AllocatorCommit {
    let mut commit = 0usize;
    let mut peak = 0usize;
    let null = std::ptr::null_mut();
    unsafe {
        libmimalloc_sys::mi_process_info(
            null,
            null,
            null,
            null,
            null,
            &mut commit,
            &mut peak,
            null,
        );
    }
    AllocatorCommit {
        commit_bytes: commit,
        commit_peak_bytes: peak,
    }
}

/// Open file descriptors of this process (Linux only; `None` elsewhere).
/// A steadily growing count is the cheapest possible leak signal for
/// sockets/files, independent of any allocator accounting.
pub fn fd_count() -> Option<usize> {
    if cfg!(target_os = "linux") {
        std::fs::read_dir("/proc/self/fd").ok().map(|d| d.count())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gauge_counts_guards_across_all_drop_paths() {
        static G: Gauge = Gauge::new();
        assert_eq!(G.get(), 0);
        let a = G.guard();
        let b = G.guard();
        assert_eq!(G.get(), 2);
        drop(a);
        assert_eq!(G.get(), 1);
        drop(b);
        assert_eq!(G.get(), 0);
    }

    #[test]
    fn heap_counter_tracks_a_real_allocation() {
        // The counter is global and other tests allocate/free on it
        // concurrently, so a single sample can see net-negative interference
        // (someone else freeing >0 bytes inside our window). Retry: real
        // breakage (the allocator wrapper not counting) fails every attempt.
        for attempt in 1.. {
            let before = heap_live_bytes();
            let v = vec![0u8; 1 << 20];
            let during = heap_live_bytes();
            drop(v);
            if during >= before + (1 << 20) {
                assert!(
                    heap_peak_bytes() >= during,
                    "peak must cover the high-water mark"
                );
                return;
            }
            assert!(
                attempt < 20,
                "1 MiB allocation never became visible in the live counter"
            );
        }
    }
}
