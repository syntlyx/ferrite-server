mod api;
mod app;
mod blocklist;
mod clients;
mod config;
mod dns;
mod error;
mod setup;
mod snapshot;
mod stats;
mod storage;
#[cfg(test)]
mod test_support;
mod updater;
mod upstream;
mod web;

use std::{sync::Arc, time::Duration};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("passwd") => return cmd_passwd(),
        Some("setup") => return setup::cmd_setup(),
        _ => {}
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // Ensure at least 2 worker threads even on single-core hosts.
        // Without this, one blocking call on the sole worker freezes the entire runtime.
        .worker_threads(std::thread::available_parallelism().map_or(2, |n| n.get().max(2)))
        // Cap blocking workers so list refreshes/sysinfo/snapshots cannot grow
        // an unnecessarily large stack footprint on small home servers.
        .max_blocking_threads(8)
        .build()?
        .block_on(run())
}

/// `ferrite passwd` — set or clear the web UI password.
fn cmd_passwd() -> anyhow::Result<()> {
    use std::io::{self, Write};

    print!("New password (leave empty to disable auth): ");
    io::stdout().flush()?;
    let password = rpassword_read_line()?;

    let config_path = config::Config::config_candidates()
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| {
            dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/etc"))
                .join("ferrite")
                .join("config.toml")
        });

    // Load existing config (or default).
    let mut cfg = if config_path.exists() {
        let raw = std::fs::read_to_string(&config_path)?;
        toml::from_str::<config::Config>(&raw)?.normalized()
    } else {
        config::Config::default()
    };

    if password.is_empty() {
        cfg.api.password_hash = None;
        println!("Password cleared — authentication disabled.");
    } else {
        let hash = api::auth::hash_password(&password)?;
        cfg.api.password_hash = Some(hash);
        println!("Password set.");
    }

    cfg.save(&config_path)?;
    println!("Saved to {}", config_path.display());
    Ok(())
}

/// Read a line from stdin without echoing (falls back to normal readline on non-TTY).
fn rpassword_read_line() -> anyhow::Result<String> {
    // rpassword is not a dep, so we use a simple cross-platform approach:
    // read from stdin directly.  For a real TTY the shell will echo, but
    // this is a CLI admin command — acceptable.
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ferrite=info")),
        )
        .init();

    let persistent_config = config::Config::load()?;
    let mut runtime_config = persistent_config.clone();
    tracing::info!("ferrite v{} starting", env!("CARGO_PKG_VERSION"));

    // Auto-detect local zones when none are configured.
    // Runs only once at startup; nothing is written to disk.
    if runtime_config.zones.is_empty() {
        let detected = setup::detect_zones();
        if !detected.is_empty() {
            let names: Vec<&str> = detected.iter().map(|z| z.name.as_str()).collect();
            tracing::info!(
                "auto-detected {} zone(s): {} — run `ferrite setup` to persist",
                detected.len(),
                names.join(", ")
            );
            runtime_config.zones = detected;
        }
    }

    let state = app::AppState::init(&runtime_config, persistent_config).await?;

    // ── Warm restart: restore snapshot ───────────────────────────────────────
    {
        let snap_path = state.inner.snapshot_path.clone();
        match snapshot::restore::load_snapshot(&snap_path) {
            Ok(Some(snap)) => {
                snapshot::restore::apply_snapshot(&state, &snap);
                // Remove snapshot after applying so stale data isn't re-applied.
                let _ = std::fs::remove_file(&snap_path);
            }
            Ok(None) => tracing::debug!("no snapshot found, starting fresh"),
            Err(e) => tracing::warn!("failed to load snapshot: {}", e),
        }
    }

    // ── Initial blocklist load ────────────────────────────────────────────────
    {
        let blocklist = Arc::clone(&state.inner.blocklist);
        if !blocklist.load_from_disk() {
            // No cached FST on disk — fetch and build in the background.
            tokio::spawn(async move {
                match blocklist.refresh(false).await {
                    Ok(n) => tracing::info!("initial blocklist loaded: {} domains", n),
                    Err(e) => tracing::error!("initial blocklist load failed: {}", e),
                }
            });
        }
    }

    // ── Shutdown handler ─────────────────────────────────────────────────────
    {
        let state_for_shutdown = state.clone();
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            tracing::info!("shutdown signal received, flushing stats…");
            // Signal the stats writer to flush its in-flight batch immediately.
            state_for_shutdown.flush_notify.notify_one();
            // Wait for the writer to confirm it has finished — with a safety timeout
            // in case the writer task crashed before we got here.
            tokio::select! {
                _ = state_for_shutdown.flush_done.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    tracing::warn!("stats flush timed out, proceeding with snapshot anyway");
                }
            }
            tracing::info!("saving snapshot…");
            let path = state_for_shutdown.inner.snapshot_path.clone();
            let save_task = tokio::task::spawn_blocking(move || {
                snapshot::save::save(&state_for_shutdown, &path)
            });
            match tokio::time::timeout(std::time::Duration::from_secs(10), save_task).await {
                Ok(Ok(Ok(()))) => tracing::info!("snapshot saved, exiting"),
                Ok(Ok(Err(e))) => tracing::error!("failed to save snapshot: {}", e),
                Ok(Err(e)) => tracing::error!("snapshot task panicked: {}", e),
                Err(_) => tracing::warn!("snapshot save timed out after 10s, exiting anyway"),
            }
            std::process::exit(0);
        });
    }

    // ── Log retention ────────────────────────────────────────────────────────
    // Always spawn — the loop checks live_config on each iteration,
    // so log_retention_days can be changed via PATCH /api/settings without restart.
    tokio::spawn(log_retention_loop(state.clone()));

    // ── CPU sampling ────────────────────────────────────────────────────────
    let sampler = state.cpu_sampler.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.tick().await; // skip the immediate first tick so the first sample covers a full interval
        loop {
            interval.tick().await;
            tokio::task::spawn_blocking({
                let s = sampler.clone();
                move || s.tick()
            })
            .await
            .ok();
        }
    });

    // ── Main services ────────────────────────────────────────────────────────
    let result = tokio::try_join!(
        dns::server::run(state.clone()),
        api::serve(state.clone()),
        stats::writer::run(state.clone()),
        updater::check_loop(state.clone()),
        periodic_snapshot(state.clone()),
    );

    // try_join returns on the first Err — log which service caused the exit.
    if let Err(ref e) = result {
        tracing::error!("service exited with error, shutting down: {}", e);
    }
    result?;
    Ok(())
}

/// Save a snapshot every 5 minutes so a crash loses at most 5 min of cache.
async fn periodic_snapshot(state: app::AppState) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
    interval.tick().await; // skip the immediate first tick
    loop {
        interval.tick().await;
        let state_clone = state.clone();
        let path = state.inner.snapshot_path.clone();
        // Use spawn_blocking: std::fs::write inside save() is a blocking syscall.
        // Calling it directly on a tokio worker thread would stall the runtime,
        // especially on slow storage (SD card, NFS).
        let result =
            tokio::task::spawn_blocking(move || snapshot::save::save(&state_clone, &path)).await;

        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("periodic snapshot failed: {}", e),
            Err(e) => tracing::warn!("periodic snapshot task panicked: {}", e),
        }
    }
}

/// Delete query log entries older than `log_retention_days`.
/// Runs once shortly after startup, then every 24 hours.
/// Reads `log_retention_days` from `live_config` on each iteration — changes
/// made via PATCH /api/settings take effect without restart.
async fn log_retention_loop(state: app::AppState) {
    // Small initial delay so startup I/O settles first.
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    loop {
        let days = state.live_config.read().storage.log_retention_days;
        if days > 0 {
            let cutoff = chrono::Utc::now().timestamp() - (days as i64 * 86_400);
            match state.inner.storage.delete_queries_older_than(cutoff).await {
                Ok(0) => tracing::debug!("log retention: no entries older than {} days", days),
                Ok(n) => tracing::info!(
                    "log retention: deleted {} entries older than {} days",
                    n,
                    days
                ),
                Err(e) => tracing::warn!("log retention failed: {}", e),
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM"),
            _ = sigint.recv()  => tracing::info!("SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
