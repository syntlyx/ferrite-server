//! Per-egress circuit breaker.
//!
//! Lock-free (atomics only) so it can be read on the connection hot path
//! without ever holding a guard across an `.await`. A run of connect failures
//! trips the breaker open for a cooldown; while open, `fail_closed` rules refuse
//! to connect rather than leak traffic directly.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const FAILURE_THRESHOLD: u32 = 3;
const COOLDOWN_SECS: u64 = 30;

#[derive(Default)]
pub struct Breaker {
    consecutive_failures: AtomicU32,
    /// Unix seconds until which the breaker is open; 0 = closed.
    opened_until: AtomicU64,
}

impl Breaker {
    pub fn is_healthy(&self) -> bool {
        let until = self.opened_until.load(Ordering::Relaxed);
        until == 0 || now_secs() >= until
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.opened_until.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= FAILURE_THRESHOLD {
            self.opened_until
                .store(now_secs() + COOLDOWN_SECS, Ordering::Relaxed);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
