//! `/api/blocklist/profiles` — view and replace per-device blocking profiles.
//!
//! A profile applies a *subset* of the subscription lists to specific clients;
//! devices matching no profile use all enabled lists (the default). The web UI
//! GETs the whole set and PUTs it back, mirroring `/api/proxy`. Applying is hot:
//! [`Blocklist::set_profiles`] recompiles each profile's FST from the per-list
//! disk caches the last refresh wrote — no network fetch, no restart.

use std::collections::HashSet;

use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::api::ApiError;
use crate::app::AppState;
use crate::config::BlocklistProfileConfig;
use crate::error::FeriteError;

/// GET /api/blocklist/profiles — the configured profiles plus the blocklist and
/// allowlist names available to build them from (so the UI can offer checkboxes).
pub async fn get_profiles(State(state): State<AppState>) -> Json<Value> {
    let profiles = state.inner.blocklist.get_profiles();
    let available_lists: Vec<String> = state
        .inner
        .blocklist
        .get_lists()
        .into_iter()
        .map(|l| l.name)
        .collect();
    let available_allowlists: Vec<String> = state
        .inner
        .blocklist
        .get_allow_lists()
        .into_iter()
        .map(|l| l.name)
        .collect();
    Json(json!({
        "profiles": profiles,
        "available_lists": available_lists,
        "available_allowlists": available_allowlists,
    }))
}

/// PUT /api/blocklist/profiles — replace the whole profile set.
pub async fn put_profiles(
    State(state): State<AppState>,
    Json(profiles): Json<Vec<BlocklistProfileConfig>>,
) -> Result<Json<Value>, ApiError> {
    let known: HashSet<String> = state
        .inner
        .blocklist
        .get_lists()
        .into_iter()
        .map(|l| l.name)
        .collect();
    let known_allow: HashSet<String> = state
        .inner
        .blocklist
        .get_allow_lists()
        .into_iter()
        .map(|l| l.name)
        .collect();
    let profiles = validate(profiles, &known, &known_allow)?;

    // Apply live (recompiles FSTs from the on-disk per-list caches), then
    // persist. The recompile merges potentially multi-million-domain FSTs, so
    // it runs on the blocking pool — inline it would stall a runtime worker
    // (and every DNS query scheduled there) for seconds.
    {
        let blocklist = std::sync::Arc::clone(&state.inner.blocklist);
        let applied = profiles.clone();
        tokio::task::spawn_blocking(move || blocklist.set_profiles(applied))
            .await
            .map_err(|e| {
                ApiError(FeriteError::Internal(format!(
                    "profile rebuild task failed: {e}"
                )))
            })?;
    }
    state.live_config.write().blocklist.profiles = profiles;
    let saved_to = persist(&state).await;

    Ok(Json(json!({
        "status": "ok",
        "persisted": saved_to.is_some(),
        "saved_to": saved_to,
    })))
}

/// Normalise and reject broken profiles with a 400: each needs a slug id and a
/// name, ids must be unique, and every referenced list must exist (a typo would
/// otherwise silently apply an empty subset — i.e. block nothing, or for a
/// default-deny profile's allowlists, allow nothing).
fn validate(
    mut profiles: Vec<BlocklistProfileConfig>,
    known_lists: &HashSet<String>,
    known_allowlists: &HashSet<String>,
) -> Result<Vec<BlocklistProfileConfig>, ApiError> {
    let mut ids: HashSet<String> = HashSet::new();
    for p in &mut profiles {
        p.id = slugify(&p.id);
        if p.id.is_empty() {
            return Err(bad("a profile is missing its id/name"));
        }
        if p.name.trim().is_empty() {
            p.name = p.id.clone();
        } else {
            p.name = p.name.trim().to_string();
        }
        if !ids.insert(p.id.clone()) {
            return Err(bad(&format!("duplicate profile id '{}'", p.id)));
        }
        for list in &p.lists {
            if !known_lists.contains(list) {
                return Err(bad(&format!(
                    "profile '{}' references unknown list '{}'",
                    p.id, list
                )));
            }
        }
        for list in &p.allowlists {
            if !known_allowlists.contains(list) {
                return Err(bad(&format!(
                    "profile '{}' references unknown allowlist '{}'",
                    p.id, list
                )));
            }
        }
    }
    Ok(profiles)
}

/// Lowercase slug: non-alphanumerics collapse to single dashes, trimmed. Matches
/// the web UI's `slug()` so a name entered there and an id sent here agree.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for c in s.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

async fn persist(state: &AppState) -> Option<String> {
    let cfg = state.live_config.read().clone();
    let path = state.config_path.as_ref().clone().or_else(|| {
        crate::config::Config::config_candidates()
            .into_iter()
            .next()
    })?;
    let path_clone = path.clone();
    match tokio::task::spawn_blocking(move || cfg.save(&path_clone)).await {
        Ok(Ok(())) => {
            tracing::info!("blocklist profiles saved to {}", path.display());
            Some(path.display().to_string())
        }
        Ok(Err(e)) => {
            tracing::error!("failed to save blocklist profiles: {}", e);
            None
        }
        Err(e) => {
            tracing::error!("config save task panicked: {}", e);
            None
        }
    }
}

fn bad(msg: &str) -> ApiError {
    ApiError(FeriteError::Config(msg.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[test]
    fn slugify_matches_web_convention() {
        assert_eq!(slugify("Kids' Tablet"), "kids-tablet");
        assert_eq!(slugify("  TV  "), "tv");
        assert_eq!(slugify("a__b"), "a-b");
        assert_eq!(slugify("!!!"), "");
    }

    #[tokio::test]
    async fn put_rejects_unknown_allowlist_and_accepts_known_one() {
        let (state, db) = test_support::app_state("profiles-api-allowlists").await;

        state
            .inner
            .blocklist
            .add_allow_list(crate::config::ListConfig {
                name: "KidSafe".into(),
                url: "https://x.test/kidsafe".into(),
                enabled: true,
            })
            .unwrap();

        let profile = |allowlists: Vec<String>| BlocklistProfileConfig {
            id: "kid".into(),
            name: "Kid".into(),
            lists: Vec::new(),
            clients: vec!["10.0.0.2".into()],
            block: Vec::new(),
            allow: Vec::new(),
            allowlists,
            default_deny: true,
        };

        // Unknown allowlist name → 400 (a typo would silently allow nothing).
        let bad = put_profiles(
            State(state.clone()),
            Json(vec![profile(vec!["Ghost".into()])]),
        )
        .await;
        assert!(matches!(bad, Err(ApiError(FeriteError::Config(_)))));

        // Known allowlist + default_deny round-trips into live_config.
        let Json(v) = put_profiles(
            State(state.clone()),
            Json(vec![profile(vec!["KidSafe".into()])]),
        )
        .await
        .unwrap();
        assert_eq!(v["status"], json!("ok"));
        let saved = state.live_config.read().blocklist.profiles.clone();
        assert_eq!(saved[0].allowlists, vec!["KidSafe"]);
        assert!(saved[0].default_deny);

        drop(state);
        test_support::cleanup_sqlite(&db);
    }

    #[tokio::test]
    async fn put_rejects_unknown_list_and_persists_valid_set() {
        let (state, db) = test_support::app_state("profiles-api").await;

        // Seed a known list so validation has something to accept.
        state
            .live_config
            .write()
            .blocklist
            .lists
            .push(crate::config::ListConfig {
                name: "Ads".into(),
                url: "https://x.test/ads".into(),
                enabled: true,
            });
        state
            .inner
            .blocklist
            .add_list(crate::config::ListConfig {
                name: "Ads".into(),
                url: "https://x.test/ads".into(),
                enabled: true,
            })
            .unwrap();

        // Unknown list → 400.
        let bad = put_profiles(
            State(state.clone()),
            Json(vec![BlocklistProfileConfig {
                id: "kids".into(),
                name: "Kids".into(),
                lists: vec!["Ghost".into()],
                clients: vec!["10.0.0.5".into()],
                block: Vec::new(),
                allow: Vec::new(),
                allowlists: Vec::new(),
                default_deny: false,
            }]),
        )
        .await;
        assert!(matches!(bad, Err(ApiError(FeriteError::Config(_)))));

        // Valid set applies and lands in live_config.
        let Json(v) = put_profiles(
            State(state.clone()),
            Json(vec![BlocklistProfileConfig {
                id: "Kids Tablet".into(), // slugified server-side
                name: "Kids Tablet".into(),
                lists: vec!["Ads".into()],
                clients: vec!["10.0.0.5".into()],
                block: Vec::new(),
                allow: Vec::new(),
                allowlists: Vec::new(),
                default_deny: false,
            }]),
        )
        .await
        .unwrap();
        assert_eq!(v["status"], json!("ok"));

        let saved = state.live_config.read().blocklist.profiles.clone();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].id, "kids-tablet");
        assert!(state.inner.blocklist.has_profiles());
        assert!(
            state
                .inner
                .blocklist
                .profile_for("10.0.0.5", None)
                .is_some()
        );

        drop(state);
        test_support::cleanup_sqlite(&db);
    }
}
