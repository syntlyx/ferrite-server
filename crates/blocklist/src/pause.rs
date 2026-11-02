//! Temporary pauses of filtering — for the whole box or for single devices —
//! that lapse on their own. "A site is broken, let me through for five
//! minutes" should not mean editing config and remembering to undo it, so a
//! pause is never persisted: a restart resumes filtering.
//!
//! The DNS hot path pays two relaxed atomic loads for this; the map behind the
//! per-device flag is only read when some device is actually paused.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::RwLock;
use serde::Serialize;

use ferrite_core::net::normalize_client_key;

/// Current wall-clock time in unix seconds — the unit pause deadlines use.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[derive(Default)]
struct State {
    /// Unix seconds when the box-wide pause ends.
    global_until: Option<i64>,
    /// Normalised client key (IP or MAC) → unix seconds when its pause ends.
    clients: HashMap<String, i64>,
}

#[derive(Default)]
pub struct Pauses {
    global: AtomicBool,
    any_clients: AtomicBool,
    state: RwLock<State>,
}

/// What is paused right now, for the API.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PauseSnapshot {
    pub global_until: Option<i64>,
    pub clients: Vec<ClientPause>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientPause {
    pub key: String,
    pub until: i64,
}

impl Pauses {
    /// Is filtering paused box-wide? Hot path.
    pub(crate) fn global_active(&self) -> bool {
        self.global.load(Ordering::Relaxed)
    }

    /// Is any device paused? Hot path — gates the map lookup below.
    pub(crate) fn any_clients(&self) -> bool {
        self.any_clients.load(Ordering::Relaxed)
    }

    /// Is this client (normalised IP, optional normalised MAC) paused?
    pub(crate) fn client_paused(&self, client_ip: &str, mac: Option<&str>) -> bool {
        if !self.any_clients() {
            return false;
        }
        let state = self.state.read();
        state.clients.contains_key(client_ip) || mac.is_some_and(|m| state.clients.contains_key(m))
    }

    /// Pause filtering box-wide until `until` (unix seconds).
    pub fn pause_global(&self, until: i64) {
        self.state.write().global_until = Some(until);
        self.global.store(true, Ordering::Relaxed);
    }

    /// Pause filtering for these devices (IPs and/or MACs) until `until`.
    /// Returns the keys that were accepted, normalised.
    pub fn pause_clients(&self, keys: &[String], until: i64) -> Vec<String> {
        let keys: Vec<String> = keys
            .iter()
            .filter_map(|k| normalize_client_key(k))
            .collect();
        if keys.is_empty() {
            return keys;
        }
        let mut state = self.state.write();
        for key in &keys {
            state.clients.insert(key.clone(), until);
        }
        self.any_clients.store(true, Ordering::Relaxed);
        keys
    }

    pub fn resume_global(&self) {
        self.state.write().global_until = None;
        self.global.store(false, Ordering::Relaxed);
    }

    pub fn resume_clients(&self, keys: &[String]) {
        let mut state = self.state.write();
        for key in keys.iter().filter_map(|k| normalize_client_key(k)) {
            state.clients.remove(&key);
        }
        self.any_clients
            .store(!state.clients.is_empty(), Ordering::Relaxed);
    }

    /// Drop every pause that has run out by `now`. Returns `true` when
    /// something lapsed, so the caller can say so in the log.
    pub fn expire(&self, now: i64) -> bool {
        if !self.global_active() && !self.any_clients() {
            return false;
        }
        let mut state = self.state.write();
        let mut lapsed = false;
        if state.global_until.is_some_and(|until| until <= now) {
            state.global_until = None;
            self.global.store(false, Ordering::Relaxed);
            lapsed = true;
        }
        let before = state.clients.len();
        state.clients.retain(|_, until| *until > now);
        lapsed |= state.clients.len() != before;
        self.any_clients
            .store(!state.clients.is_empty(), Ordering::Relaxed);
        lapsed
    }

    pub fn snapshot(&self) -> PauseSnapshot {
        let state = self.state.read();
        let mut clients: Vec<ClientPause> = state
            .clients
            .iter()
            .map(|(key, until)| ClientPause {
                key: key.clone(),
                until: *until,
            })
            .collect();
        clients.sort_by(|a, b| a.key.cmp(&b.key));
        PauseSnapshot {
            global_until: state.global_until,
            clients,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_pause_lapses_at_its_deadline() {
        let p = Pauses::default();
        assert!(!p.global_active());
        p.pause_global(100);
        assert!(p.global_active());
        assert!(!p.expire(99), "nothing lapses before the deadline");
        assert!(p.global_active());
        assert!(p.expire(100));
        assert!(!p.global_active());
        assert_eq!(p.snapshot().global_until, None);
    }

    #[test]
    fn client_pause_matches_ip_or_mac_and_normalises_keys() {
        let p = Pauses::default();
        assert!(!p.client_paused("192.168.1.10", None));
        let accepted = p.pause_clients(
            &[
                "AA-BB-CC-DD-EE-FF".into(),
                " 192.168.1.10 ".into(),
                "".into(),
            ],
            100,
        );
        assert_eq!(accepted.len(), 2, "blank keys are dropped");
        assert!(p.any_clients());
        assert!(p.client_paused("192.168.1.10", None));
        assert!(p.client_paused("10.0.0.9", Some("aa:bb:cc:dd:ee:ff")));
        assert!(!p.client_paused("10.0.0.9", None));
        p.resume_clients(&["192.168.1.10".into()]);
        assert!(!p.client_paused("192.168.1.10", None));
        assert!(p.any_clients(), "the MAC is still paused");
        assert!(p.expire(100));
        assert!(!p.any_clients());
    }

    #[test]
    fn resume_global_ends_the_pause_at_once() {
        let p = Pauses::default();
        p.pause_global(i64::MAX);
        p.resume_global();
        assert!(!p.global_active());
        assert!(!p.expire(0));
    }
}
