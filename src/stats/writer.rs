use std::collections::HashSet;
use std::time::Duration;

use tokio::time::timeout;

use crate::app::AppState;
use crate::clients::{parse_ip, ClientRegistry};
use crate::dns::types::QueryEntry;

const BATCH_SIZE: usize = 500;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

pub async fn run(state: AppState) -> anyhow::Result<()> {
    let mut rx = state
        .query_rx
        .lock()
        .take()
        .ok_or_else(|| anyhow::anyhow!("stats writer: query_rx already consumed"))?;

    tracing::info!("stats writer started");

    let mut batch: Vec<QueryEntry> = Vec::with_capacity(BATCH_SIZE);
    let flush_notify = state.flush_notify.clone();

    loop {
        tokio::select! {
            // Flush signal from shutdown handler — drain everything then return.
            _ = flush_notify.notified() => {
                // Drain any remaining entries queued before the signal.
                while let Ok(entry) = rx.try_recv() {
                    state.inner.live_stats.push_entry(entry.clone());
                    batch.push(entry);
                }
                tracing::info!("stats writer flush requested, writing {} entries", batch.len());
                flush_batch(&state, &mut batch).await;
                // Signal shutdown handler that the flush is done.
                state.flush_done.notify_one();
                return Ok(());
            }

            // Normal batch accumulation loop.
            result = async {
                loop {
                    match timeout(FLUSH_INTERVAL, rx.recv()).await {
                        Ok(Some(entry)) => {
                            state.inner.live_stats.push_entry(entry.clone());
                            batch.push(entry);
                            if batch.len() >= BATCH_SIZE {
                                break true; // flush now
                            }
                        }
                        Ok(None) => {
                            // Channel closed — sender dropped.
                            break false;
                        }
                        Err(_elapsed) => break true, // timeout
                    }
                }
            } => {
                if !result {
                    tracing::info!("query channel closed, flushing final batch");
                    flush_batch(&state, &mut batch).await;
                    return Ok(());
                }
                if !batch.is_empty() {
                    flush_batch(&state, &mut batch).await;
                    batch = Vec::with_capacity(BATCH_SIZE);
                }
            }
        }
    }
}

async fn flush_batch(state: &AppState, batch: &mut Vec<QueryEntry>) {
    if batch.is_empty() {
        return;
    }

    let to_write = std::mem::take(batch);

    // Trigger background PTR resolution for each unique client IP in this batch.
    // This is best-effort and never delays the write.
    let mut seen: HashSet<&str> = HashSet::new();
    for entry in &to_write {
        if seen.insert(entry.client_ip.as_str()) {
            if let Some(ip) = parse_ip(&entry.client_ip) {
                ClientRegistry::trigger_resolve(&state.inner.client_registry, ip);
            }
        }
    }

    if let Err(e) = state.inner.storage.write_batch(&to_write).await {
        tracing::error!(
            "failed to write query batch ({} entries): {}",
            to_write.len(),
            e
        );
    } else {
        tracing::debug!("flushed {} query entries to storage", to_write.len());
    }
}
