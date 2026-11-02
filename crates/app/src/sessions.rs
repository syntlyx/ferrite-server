//! Web-panel login sessions: in memory for the request path, written through
//! to storage so a restart — a deploy, an update from the panel — doesn't sign
//! everyone out. Keys are whatever the API hands in (the SHA-256 of the
//! token); this type neither sees nor stores a token.

use std::sync::Arc;

use dashmap::DashMap;

use ferrite_storage::{Storage, StoredSession};

/// One live session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    /// Fingerprint of the password hash it was issued under.
    pub password_fp: String,
    /// Unix seconds it lapses at.
    pub expires: i64,
    /// Unix seconds it signed in at.
    pub created: i64,
    /// Unix seconds it was last used at. Kept current in memory; written to
    /// storage with each renewal, so after a restart it can be up to a day old.
    pub last_seen: i64,
    /// The browser's User-Agent at sign-in.
    pub agent: String,
    /// The address it signed in from.
    pub ip: String,
}

pub struct Sessions {
    map: DashMap<String, Session>,
    storage: Arc<dyn Storage>,
}

impl Sessions {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            map: DashMap::new(),
            storage,
        }
    }

    /// Load every session still valid at `now` from storage. A failure is
    /// logged, not fatal: the cost is signing in again.
    pub async fn restore(&self, now: i64) {
        match self.storage.load_sessions(now).await {
            Ok(rows) => {
                for row in rows {
                    self.map.insert(
                        row.token_hash,
                        Session {
                            password_fp: row.password_fp,
                            expires: row.expires,
                            created: row.created,
                            last_seen: row.last_seen,
                            agent: row.agent,
                            ip: row.ip,
                        },
                    );
                }
                if !self.map.is_empty() {
                    tracing::info!("restored {} login session(s)", self.map.len());
                }
            }
            Err(e) => tracing::warn!("could not restore login sessions: {}", e),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// A copy of the session under `key`. Copied out so no map guard outlives
    /// the call (a later `remove` on the same shard would deadlock on it).
    pub fn get(&self, key: &str) -> Option<Session> {
        self.map.get(key).map(|e| e.clone())
    }

    /// Every live session with its key, oldest sign-in first.
    pub fn list(&self) -> Vec<(String, Session)> {
        let mut all: Vec<(String, Session)> = self
            .map
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        all.sort_by_key(|(_, s)| s.created);
        all
    }

    /// Note that a session was just used. Memory only — the request path
    /// shouldn't write to the database; the next renewal carries it.
    pub fn touch(&self, key: &str, now: i64) {
        if let Some(mut s) = self.map.get_mut(key) {
            s.last_seen = now;
        }
    }

    /// Add a session and wait for it to be stored.
    pub async fn insert(&self, key: String, session: Session) {
        self.map.insert(key.clone(), session.clone());
        self.persist(key, session).await;
    }

    /// Update a session from the request path: memory now, storage in the
    /// background (losing the write only shortens a session).
    pub fn update(&self, key: &str, session: Session) {
        self.map.insert(key.to_string(), session.clone());
        let storage = Arc::clone(&self.storage);
        let key = key.to_string();
        tokio::spawn(async move { persist(&*storage, key, session).await });
    }

    /// Drop a session from the request path; storage follows in the background.
    pub fn forget(&self, key: &str) {
        self.map.remove(key);
        let storage = Arc::clone(&self.storage);
        let key = key.to_string();
        tokio::spawn(async move {
            if let Err(e) = storage.delete_session(&key).await {
                tracing::debug!("could not delete a session: {}", e);
            }
        });
    }

    /// Drop a session and wait for storage to follow.
    pub async fn remove(&self, key: &str) {
        self.map.remove(key);
        if let Err(e) = self.storage.delete_session(key).await {
            tracing::debug!("could not delete a session: {}", e);
        }
    }

    async fn persist(&self, key: String, session: Session) {
        persist(&*self.storage, key, session).await;
    }
}

async fn persist(storage: &dyn Storage, key: String, session: Session) {
    let row = StoredSession {
        token_hash: key,
        password_fp: session.password_fp,
        expires: session.expires,
        created: session.created,
        last_seen: session.last_seen,
        agent: session.agent,
        ip: session.ip,
    };
    if let Err(e) = storage.save_session(&row).await {
        tracing::warn!("could not save a login session: {}", e);
    }
}
