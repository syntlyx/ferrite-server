//! One set of assertions, run against every storage backend.
//!
//! The backends are meant to be interchangeable: whichever one is configured,
//! the dashboard and the Queries page must read the same. That only stays true
//! if the same tests cover both, so the cases here take an `Arc<dyn Storage>`
//! and each one is driven twice — once over SQLite, once over RAM.
//!
//! When a third backend arrives, it earns its place by passing this file.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;

use ferrite_core::recording::RecordScope;
use ferrite_core::types::{QueryEntry, QueryStatus};

use crate::{MemoryStorage, QueryFilter, SqliteStorage, Storage};

/// Build both backends and run `case` against each, so a divergence names the
/// backend that broke rather than just failing somewhere.
async fn for_each_backend<F, Fut>(name: &str, case: F)
where
    F: Fn(Arc<dyn Storage>) -> Fut,
    Fut: Future<Output = ()>,
{
    let path = temp_db_path(name);
    let sqlite = SqliteStorage::open(&path).await.unwrap();
    case(sqlite as Arc<dyn Storage>).await;
    cleanup(&path);

    case(MemoryStorage::open(0) as Arc<dyn Storage>).await;
}

#[tokio::test]
async fn rollups_answer_the_dashboard_the_same_way() {
    for_each_backend("conformance-rollups", |storage| async move {
        let bucket = align(Utc::now().timestamp());
        storage
            .write_batch(
                vec![
                    entry(
                        bucket + 1,
                        "example.test",
                        "192.168.1.10",
                        QueryStatus::Cached,
                    ),
                    entry(
                        bucket + 2,
                        "example.test",
                        "192.168.1.10",
                        QueryStatus::Upstream,
                    ),
                    entry(bucket + 3, "ads.test", "192.168.1.11", QueryStatus::Blocked),
                    entry(bucket + 4, "ads.test", "192.168.1.11", QueryStatus::Blocked),
                    // A third for .11 so the top lists are ordered by count,
                    // not by a tiebreak — the ordering is what is under test.
                    entry(bucket + 5, "ads.test", "192.168.1.11", QueryStatus::Blocked),
                ],
                RecordScope::ALL,
            )
            .await
            .unwrap();

        let counts = storage.summary_counts(bucket, bucket + 599).await.unwrap();
        assert_eq!((counts.total, counts.blocked), (5, 3));
        assert_eq!((counts.cached, counts.upstream), (1, 1));
        assert_eq!(storage.summary(3600).await.unwrap(), (5, 3));

        let top = storage.top_domains(bucket, bucket + 599, 10).await.unwrap();
        assert_eq!(
            top,
            vec![("ads.test".to_string(), 3), ("example.test".to_string(), 2)]
        );

        // A domain that was never blocked is not a top *blocked* domain,
        // however often it was resolved.
        let blocked = storage
            .top_blocked_domains(bucket, bucket + 599, 10)
            .await
            .unwrap();
        assert_eq!(blocked, vec![("ads.test".to_string(), 3)]);

        let clients = storage.top_clients(bucket, bucket + 599, 10).await.unwrap();
        assert_eq!(clients[0].device, "192.168.1.11");
        assert_eq!((clients[0].total, clients[0].blocked), (3, 3));
        assert_eq!(clients[1].device, "192.168.1.10");

        let one = storage.client_stats("192.168.1.10").await.unwrap().unwrap();
        assert_eq!((one.total, one.blocked), (2, 0));
        assert!(
            storage
                .client_stats("no.such.device")
                .await
                .unwrap()
                .is_none()
        );

        let series = storage.timeseries(600).await.unwrap();
        let current = series.iter().find(|b| b.bucket == bucket as u64).unwrap();
        assert_eq!((current.total, current.blocked), (5, 3));
        assert_eq!((current.cached, current.upstream), (1, 1));
    })
    .await;
}

#[tokio::test]
async fn query_filters_and_keyset_pagination_agree() {
    for_each_backend("conformance-filters", |storage| async move {
        let ts = align(Utc::now().timestamp());
        storage
            .write_batch(
                vec![
                    entry(ts, "old.test", "192.168.1.10", QueryStatus::Upstream),
                    entry(ts, "middle.test", "192.168.1.10", QueryStatus::Blocked),
                    entry(ts, "new.test", "192.168.1.11", QueryStatus::Upstream),
                ],
                RecordScope::ALL,
            )
            .await
            .unwrap();

        // Newest first, ids breaking the timestamp tie.
        let page = storage
            .query_range(&QueryFilter {
                limit: Some(2),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].domain, "new.test");
        assert_eq!(page[1].domain, "middle.test");

        // Keyset cursor continues without repeating a row.
        let cursor = &page[1];
        let next = storage
            .query_range(&QueryFilter {
                limit: Some(2),
                before_id: Some(cursor.id),
                before_ts: Some(cursor.timestamp.timestamp()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].domain, "old.test");
        assert!(!page.iter().any(|e| e.id == next[0].id));

        // Substring match on the domain, and case-insensitive like SQL LIKE.
        let found = storage
            .query_range(&QueryFilter {
                domain: Some("IDDL".to_string()),
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].domain, "middle.test");

        let blocked = storage
            .query_range(&QueryFilter {
                status: Some("blocked".to_string()),
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].domain, "middle.test");

        let by_client = storage
            .query_range(&QueryFilter {
                client_ips: vec!["192.168.1.11".to_string()],
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_client.len(), 1);
        assert_eq!(by_client[0].domain, "new.test");

        // Client and device filters are OR-combined, so asking for a device
        // and an IP returns both sets.
        let either = storage
            .query_range(&QueryFilter {
                client_ips: vec!["192.168.1.11".to_string()],
                devices: vec!["192.168.1.10".to_string()],
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(either.len(), 3);

        let windowed = storage
            .query_range(&QueryFilter {
                from_ts: Some(ts + 1),
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(windowed.is_empty());
    })
    .await;
}

#[tokio::test]
async fn privacy_switches_gate_both_backends_identically() {
    for_each_backend("conformance-scope", |storage| async move {
        let ts = align(Utc::now().timestamp());

        // Log off, stats on: no rows, but the aggregates still count.
        storage
            .write_batch(
                vec![entry(ts, "a.test", "192.168.1.10", QueryStatus::Blocked)],
                RecordScope {
                    queries: false,
                    stats: true,
                },
            )
            .await
            .unwrap();
        assert!(
            storage
                .query_range(&QueryFilter {
                    limit: Some(10),
                    ..Default::default()
                })
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(storage.summary_counts(ts, ts + 599).await.unwrap().total, 1);

        // Stats off, log on: the row lands, the aggregates do not move.
        storage
            .write_batch(
                vec![entry(
                    ts + 1,
                    "b.test",
                    "192.168.1.10",
                    QueryStatus::Upstream,
                )],
                RecordScope {
                    queries: true,
                    stats: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            storage
                .query_range(&QueryFilter {
                    limit: Some(10),
                    ..Default::default()
                })
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(storage.summary_counts(ts, ts + 599).await.unwrap().total, 1);

        // Both off: nothing at all.
        storage
            .write_batch(
                vec![entry(
                    ts + 2,
                    "c.test",
                    "192.168.1.10",
                    QueryStatus::Upstream,
                )],
                RecordScope {
                    queries: false,
                    stats: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            storage
                .query_range(&QueryFilter {
                    limit: Some(10),
                    ..Default::default()
                })
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(storage.summary_counts(ts, ts + 599).await.unwrap().total, 1);
    })
    .await;
}

#[tokio::test]
async fn retention_and_clearing_behave_the_same() {
    for_each_backend("conformance-retention", |storage| async move {
        let now = align(Utc::now().timestamp());
        let old = now - 3 * 86_400;
        storage
            .write_batch(
                vec![
                    entry(old, "old.test", "192.168.1.10", QueryStatus::Upstream),
                    entry(now, "fresh.test", "192.168.1.10", QueryStatus::Upstream),
                ],
                RecordScope::ALL,
            )
            .await
            .unwrap();

        // Age-based retention takes the old row and its rollups, not the new.
        let deleted = storage
            .delete_queries_older_than(now - 86_400)
            .await
            .unwrap();
        assert_eq!(deleted, 1);
        let rows = storage
            .query_range(&QueryFilter {
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].domain, "fresh.test");
        assert_eq!(
            storage.summary_counts(old, old + 599).await.unwrap().total,
            0
        );
        assert_eq!(
            storage.summary_counts(now, now + 599).await.unwrap().total,
            1
        );

        // Clearing empties the log and every aggregate behind it.
        storage.delete_all_queries().await.unwrap();
        storage.vacuum().await.unwrap();
        assert!(
            storage
                .query_range(&QueryFilter {
                    limit: Some(10),
                    ..Default::default()
                })
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            storage.summary_counts(now, now + 599).await.unwrap().total,
            0
        );
        assert!(
            storage
                .top_domains(now, now + 599, 10)
                .await
                .unwrap()
                .is_empty()
        );
    })
    .await;
}

#[tokio::test]
async fn the_device_inventory_behaves_the_same() {
    for_each_backend("conformance-devices", |storage| async move {
        storage
            .upsert_device("aa:bb:cc:dd:ee:ff", Some("laptop"))
            .await
            .unwrap();
        storage
            .upsert_device("aa:bb:cc:dd:ee:ff", Some("laptop.lan"))
            .await
            .unwrap();
        storage
            .upsert_ip_binding("192.168.1.10", "aa:bb:cc:dd:ee:ff")
            .await
            .unwrap();

        assert_eq!(
            storage.load_devices().await.unwrap(),
            vec![(
                "aa:bb:cc:dd:ee:ff".to_string(),
                Some("laptop.lan".to_string())
            )]
        );
        assert_eq!(
            storage.load_ip_bindings().await.unwrap(),
            vec![("192.168.1.10".to_string(), "aa:bb:cc:dd:ee:ff".to_string())]
        );

        // A binding just touched is live and must survive the prune.
        storage
            .touch_ip_bindings(&["192.168.1.10".to_string()])
            .await
            .unwrap();
        let pruned = storage
            .delete_ip_bindings_older_than(Utc::now().timestamp() - 3600)
            .await
            .unwrap();
        assert!(pruned.is_empty());
        assert_eq!(storage.load_ip_bindings().await.unwrap().len(), 1);

        // Clearing bindings leaves the device names alone.
        storage.delete_all_ip_bindings().await.unwrap();
        assert!(storage.load_ip_bindings().await.unwrap().is_empty());
        assert_eq!(storage.load_devices().await.unwrap().len(), 1);

        storage.delete_all_devices().await.unwrap();
        assert!(storage.load_devices().await.unwrap().is_empty());
    })
    .await;
}

#[tokio::test]
async fn the_size_cap_bounds_both_backends() {
    for_each_backend("conformance-size-cap", |storage| async move {
        let base = align(Utc::now().timestamp()) - 40_000;
        let entries: Vec<QueryEntry> = (0..25_000)
            .map(|i| {
                entry(
                    base + i,
                    &format!("host{i}.example.test"),
                    "192.168.1.10",
                    QueryStatus::Upstream,
                )
            })
            .collect();
        storage
            .write_batch(entries, RecordScope::ALL)
            .await
            .unwrap();

        let before = storage.database_bytes().await.unwrap();
        assert!(before > 0);
        let cap = before / 3;

        storage.prepare_size_cap().await.unwrap();
        let trim = storage.enforce_size_cap(cap).await.unwrap();

        assert!(trim.rows_deleted > 0);
        assert!(
            trim.bytes_after <= cap,
            "{} bytes left against a {} cap",
            trim.bytes_after,
            cap
        );

        // Trimmed oldest-first: the newest query is still there.
        let newest = storage
            .query_range(&QueryFilter {
                limit: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(newest[0].domain, "host24999.example.test");

        // Already under the cap: a second pass is a no-op.
        let again = storage.enforce_size_cap(cap).await.unwrap();
        assert!(again.is_noop());
    })
    .await;
}

#[tokio::test]
async fn ids_resume_after_a_restart_on_both_backends() {
    for_each_backend("conformance-ids", |storage| async move {
        assert_eq!(storage.max_query_id().await.unwrap(), 0);
        let ts = align(Utc::now().timestamp());
        let e = entry(ts, "a.test", "192.168.1.10", QueryStatus::Upstream);
        let id = e.id;
        storage
            .write_batch(vec![e], RecordScope::ALL)
            .await
            .unwrap();
        assert_eq!(storage.max_query_id().await.unwrap(), id);
    })
    .await;
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn align(ts: i64) -> i64 {
    ts.div_euclid(600) * 600
}

fn entry(ts: i64, domain: &str, client_ip: &str, status: QueryStatus) -> QueryEntry {
    // Ids must be unique and rising: SQLite stores them verbatim under a
    // PRIMARY KEY, and both backends resume their counter from the maximum.
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    QueryEntry {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        timestamp: chrono::DateTime::from_timestamp(ts, 0).unwrap(),
        domain: domain.to_string(),
        query_type: 1,
        client_ip: client_ip.to_string(),
        device: client_ip.to_string(),
        status,
        latency_ms: 1,
        upstream: None,
        rcode: 0,
    }
}

fn temp_db_path(name: &str) -> std::path::PathBuf {
    let unique = format!(
        "ferrite-{}-{}-{}.db",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::env::temp_dir().join(unique)
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
}
