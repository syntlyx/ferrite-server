use super::migrations::SCHEMA_VERSION;
use super::*;

fn temp_db_path(name: &str) -> std::path::PathBuf {
    let unique = format!(
        "{}-{}-{}.db",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::env::temp_dir().join(unique)
}

fn query_entry(ts: i64, domain: &str, client_ip: &str, status: QueryStatus) -> QueryEntry {
    // Default device == client_ip, so device-keyed rollups match IP-keyed
    // expectations. Use `query_entry_dev` to attribute to an explicit device.
    query_entry_dev(ts, domain, client_ip, client_ip, status)
}

fn query_entry_dev(
    ts: i64,
    domain: &str,
    client_ip: &str,
    device: &str,
    status: QueryStatus,
) -> QueryEntry {
    // Unique monotonic ids: write_batch persists entry ids verbatim,
    // and queries.id is a PRIMARY KEY.
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    QueryEntry {
        id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        timestamp: chrono::DateTime::from_timestamp(ts, 0).unwrap(),
        domain: domain.to_string(),
        query_type: 1,
        client_ip: client_ip.to_string(),
        device: device.to_string(),
        status,
        latency_ms: 1,
        upstream: None,
        rcode: 0,
    }
}

#[tokio::test]
async fn summary_returns_zeroes_for_empty_database() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-empty-summary"))
        .await
        .unwrap();

    assert_eq!(storage.summary(3600).await.unwrap(), (0, 0));
}

#[tokio::test]
async fn sqlite_rollups_power_timeseries_and_top_lists() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-rollups"))
        .await
        .unwrap();
    let bucket = align_bucket(chrono::Utc::now().timestamp());
    let entries = vec![
        query_entry(
            bucket + 1,
            "example.test",
            "192.168.1.10",
            QueryStatus::Cached,
        ),
        query_entry(
            bucket + 2,
            "example.test",
            "192.168.1.10",
            QueryStatus::Upstream,
        ),
        query_entry(bucket + 3, "ads.test", "192.168.1.11", QueryStatus::Blocked),
        query_entry(bucket + 4, "ads.test", "192.168.1.11", QueryStatus::Blocked),
    ];

    storage.write_batch_all(entries).await.unwrap();

    let timeseries = storage.timeseries(600).await.unwrap();
    let current = timeseries
        .iter()
        .find(|b| b.bucket == bucket as u64)
        .unwrap();
    assert_eq!(current.total, 4);
    assert_eq!(current.blocked, 2);
    assert_eq!(current.cached, 1);
    assert_eq!(current.upstream, 1);

    let blocked = storage
        .top_blocked_domains(bucket, bucket + 599, 10)
        .await
        .unwrap();
    assert_eq!(blocked, vec![("ads.test".to_string(), 2)]);

    // Both devices sit on two queries here, so look the one up by name
    // rather than by position — the tie order is covered where it is the
    // thing under test (see the conformance suite).
    let clients = storage.top_clients(bucket, bucket + 599, 10).await.unwrap();
    let noisy = clients
        .iter()
        .find(|c| c.device == "192.168.1.11")
        .expect("device should be in the top list");
    assert_eq!(noisy.total, 2);
    assert_eq!(noisy.blocked, 2);

    assert_eq!(storage.summary(3600).await.unwrap(), (4, 2));
    let counts = storage.summary_counts(bucket, bucket + 599).await.unwrap();
    assert_eq!(counts.total, 4);
    assert_eq!(counts.blocked, 2);
    assert_eq!(counts.cached, 1);
    assert_eq!(counts.upstream, 1);
}

#[tokio::test]
async fn query_range_uses_keyset_cursor_without_duplicates() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-keyset"))
        .await
        .unwrap();
    let ts = align_bucket(chrono::Utc::now().timestamp());
    let entries = vec![
        query_entry(ts, "old.test", "192.168.1.10", QueryStatus::Upstream),
        query_entry(ts, "middle.test", "192.168.1.10", QueryStatus::Upstream),
        query_entry(ts, "new.test", "192.168.1.10", QueryStatus::Upstream),
    ];

    storage.write_batch_all(entries).await.unwrap();

    let first_page = storage
        .query_range(&QueryFilter {
            limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(first_page.len(), 2);
    assert_eq!(first_page[0].domain, "new.test");
    assert_eq!(first_page[1].domain, "middle.test");

    let cursor = &first_page[1];
    let next_page = storage
        .query_range(&QueryFilter {
            limit: Some(2),
            before_id: Some(cursor.id),
            before_ts: Some(cursor.timestamp.timestamp()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(next_page.len(), 1);
    assert_eq!(next_page[0].domain, "old.test");
    assert!(!first_page.iter().any(|e| e.id == next_page[0].id));
}

/// A fresh database is created incremental-auto-vacuum, so a size cap can
/// hand pages back without anyone paying for a full rewrite first.
#[tokio::test]
async fn a_new_database_is_ready_for_a_size_cap() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-autovacuum"))
        .await
        .unwrap();

    let mode: i64 = storage
        .conn
        .call(|c| {
            Ok::<i64, tokio_rusqlite::Error>(c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(mode, 2, "expected INCREMENTAL auto_vacuum");

    // Nothing to convert, so this is free and says so.
    assert!(!storage.prepare_size_cap().await.unwrap());
}

/// The cap drops oldest-first, stops once it fits, and keeps recent
/// history — the whole point being to bound growth, not to empty the log.
#[tokio::test]
async fn size_cap_trims_the_oldest_queries_until_it_fits() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-size-cap"))
        .await
        .unwrap();

    let base = align_bucket(chrono::Utc::now().timestamp()) - 40_000;
    let entries: Vec<QueryEntry> = (0..25_000)
        .map(|i| {
            query_entry(
                base + i,
                &format!("host{i}.example.test"),
                "192.168.1.10",
                QueryStatus::Upstream,
            )
        })
        .collect();
    storage.write_batch_all(entries).await.unwrap();

    let before = storage.database_bytes().await.unwrap();
    assert!(before > 1_000_000, "test needs a database worth trimming");

    // Cap at a third of what it grew to.
    let cap = before / 3;
    let trim = storage.enforce_size_cap(cap).await.unwrap();

    assert!(trim.rows_deleted > 0);
    assert!(
        trim.bytes_after <= cap,
        "still {} bytes against a {} cap",
        trim.bytes_after,
        cap
    );
    assert!(trim.bytes_after < trim.bytes_before);

    // The file itself gave the space back, not just the page accounting —
    // that is what a RAM-backed path needs, and the difference is easy to
    // get wrong: `PRAGMA incremental_vacuum` yields one row per freed page,
    // so a caller that doesn't drain it frees a single page and reports
    // success. Allow one page of slack, nothing more.
    let file_after = storage.database_bytes().await.unwrap();
    assert!(
        file_after <= cap + 4096,
        "page accounting says {} but the file is still {} against a {} cap",
        trim.bytes_after,
        file_after,
        cap
    );

    // Oldest gone, newest kept.
    let rows = storage
        .query_range(&QueryFilter {
            limit: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(rows[0].domain, "host24999.example.test");

    let remaining = storage
        .query_range(&QueryFilter {
            domain: Some("host0.example.test".to_string()),
            limit: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        remaining.is_empty(),
        "the oldest entry should have gone first"
    );
}

/// Already under the cap: no deletes, no rewrite, nothing to report.
#[tokio::test]
async fn size_cap_under_the_limit_does_nothing() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-size-cap-noop"))
        .await
        .unwrap();
    let ts = align_bucket(chrono::Utc::now().timestamp());
    storage
        .write_batch_all(vec![query_entry(
            ts,
            "example.test",
            "192.168.1.10",
            QueryStatus::Upstream,
        )])
        .await
        .unwrap();

    let trim = storage.enforce_size_cap(100_000_000).await.unwrap();
    assert!(trim.is_noop());
    assert_eq!(trim.rows_deleted, 0);

    let rows = storage
        .query_range(&QueryFilter {
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
}

/// A database written before the configuration tables moved into
/// `config.toml` still has to hand its rows over exactly once. Read them,
/// drop the tables, and a second boot must find nothing left to migrate.
#[tokio::test]
async fn legacy_config_rows_are_handed_over_then_the_tables_go() {
    let path = temp_db_path("ferrite-legacy-config");
    let storage = SqliteStorage::open(&path).await.unwrap();

    // Recreate a pre-v9 database: the five tables the baseline schema used
    // to carry, populated the way the old write paths populated them.
    storage
        .conn
        .call(|c| {
            c.execute_batch(
                "CREATE TABLE custom_entries (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     domain TEXT NOT NULL UNIQUE,
                     entry_type TEXT NOT NULL,
                     comment TEXT,
                     created_at INTEGER NOT NULL);
                 CREATE TABLE custom_dns_records (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     domain TEXT NOT NULL,
                     record_type TEXT NOT NULL,
                     value TEXT NOT NULL,
                     ttl INTEGER NOT NULL DEFAULT 300,
                     created_at INTEGER NOT NULL);
                 CREATE TABLE client_aliases (
                     key TEXT NOT NULL,
                     key_type TEXT NOT NULL DEFAULT 'ip',
                     name TEXT NOT NULL,
                     created_at INTEGER NOT NULL,
                     PRIMARY KEY (key, key_type));
                 CREATE TABLE blocklists (id INTEGER PRIMARY KEY, name TEXT);
                 CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

                 INSERT INTO custom_entries (domain, entry_type, created_at)
                     VALUES ('ads.test', 'blacklist', 1), ('safe.test', 'whitelist', 2);
                 INSERT INTO custom_dns_records (domain, record_type, value, ttl, created_at)
                     VALUES ('router.lan', 'A', '192.168.1.1', 60, 1);
                 INSERT INTO client_aliases (key, key_type, name, created_at)
                     VALUES ('192.168.1.10', 'ip', 'Laptop', 1),
                            ('aa:bb:cc:dd:ee:ff', 'mac', 'Phone', 2);",
            )?;
            Ok::<_, tokio_rusqlite::Error>(())
        })
        .await
        .unwrap();

    let rows = storage.load_legacy_config_rows().await.unwrap();
    assert!(!rows.is_empty());
    assert_eq!(
        rows.custom_entries,
        vec![
            ("ads.test".to_string(), "blacklist".to_string()),
            ("safe.test".to_string(), "whitelist".to_string()),
        ]
    );
    assert_eq!(rows.custom_records.len(), 1);
    assert_eq!(rows.custom_records[0].domain, "router.lan");
    assert_eq!(rows.custom_records[0].ttl, 60);
    assert_eq!(
        rows.client_aliases,
        vec![
            (
                "192.168.1.10".to_string(),
                "ip".to_string(),
                "Laptop".to_string()
            ),
            (
                "aa:bb:cc:dd:ee:ff".to_string(),
                "mac".to_string(),
                "Phone".to_string()
            ),
        ]
    );

    storage.drop_legacy_config_tables().await.unwrap();
    assert!(storage.load_legacy_config_rows().await.unwrap().is_empty());
}

/// A database created after the move never had those tables, and neither
/// the read nor the drop may trip over their absence.
#[tokio::test]
async fn legacy_hand_off_is_a_no_op_on_a_fresh_database() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-legacy-fresh"))
        .await
        .unwrap();

    assert!(storage.load_legacy_config_rows().await.unwrap().is_empty());
    storage.drop_legacy_config_tables().await.unwrap();
    assert!(storage.load_legacy_config_rows().await.unwrap().is_empty());
}

#[tokio::test]
async fn devices_and_ip_bindings_round_trip_and_last_binding_wins() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-devices"))
        .await
        .unwrap();

    // Learn a device name, then refine it — upsert should overwrite.
    storage
        .upsert_device("aa:bb:cc:dd:ee:ff", Some("laptop"))
        .await
        .unwrap();
    storage
        .upsert_device("aa:bb:cc:dd:ee:ff", Some("alex-laptop"))
        .await
        .unwrap();
    // A nameless re-learn must NOT blank an existing hostname (COALESCE).
    storage
        .upsert_device("aa:bb:cc:dd:ee:ff", None)
        .await
        .unwrap();
    // A device seen only by MAC, hostname not yet resolved.
    storage
        .upsert_device("11:22:33:44:55:66", None)
        .await
        .unwrap();

    let devices = storage.load_devices().await.unwrap();
    assert_eq!(devices.len(), 2);
    let laptop = devices
        .iter()
        .find(|(m, _)| m == "aa:bb:cc:dd:ee:ff")
        .unwrap();
    assert_eq!(laptop.1.as_deref(), Some("alex-laptop"));
    let nameless = devices
        .iter()
        .find(|(m, _)| m == "11:22:33:44:55:66")
        .unwrap();
    assert_eq!(nameless.1, None);

    // IP .50 first belongs to the laptop, then is reassigned ("last binding wins").
    storage
        .upsert_ip_binding("192.168.1.50", "aa:bb:cc:dd:ee:ff")
        .await
        .unwrap();
    storage
        .upsert_ip_binding("192.168.1.77", "aa:bb:cc:dd:ee:ff")
        .await
        .unwrap();
    storage
        .upsert_ip_binding("192.168.1.50", "11:22:33:44:55:66")
        .await
        .unwrap();

    let mut bindings = storage.load_ip_bindings().await.unwrap();
    bindings.sort();
    assert_eq!(
        bindings,
        vec![
            ("192.168.1.50".to_string(), "11:22:33:44:55:66".to_string()),
            ("192.168.1.77".to_string(), "aa:bb:cc:dd:ee:ff".to_string()),
        ]
    );
}

#[tokio::test]
async fn delete_all_ip_bindings_clears_bindings_but_keeps_devices() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-clear-bindings"))
        .await
        .unwrap();

    storage
        .upsert_device("aa:bb:cc:dd:ee:ff", Some("laptop"))
        .await
        .unwrap();
    storage
        .upsert_ip_binding("192.168.1.50", "aa:bb:cc:dd:ee:ff")
        .await
        .unwrap();

    storage.delete_all_ip_bindings().await.unwrap();

    // IP bindings are gone; the learned device name survives so a returning
    // device still resolves to its hostname.
    assert!(storage.load_ip_bindings().await.unwrap().is_empty());
    let devices = storage.load_devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].1.as_deref(), Some("laptop"));
}

#[tokio::test]
async fn prune_deletes_stale_bindings_and_touch_keeps_fresh() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-prune-bindings"))
        .await
        .unwrap();

    storage
        .upsert_ip_binding("192.168.1.50", "aa:bb:cc:dd:ee:ff")
        .await
        .unwrap();
    storage
        .upsert_ip_binding("192.168.1.51", "11:22:33:44:55:66")
        .await
        .unwrap();

    // A cutoff far in the past keeps every just-written binding (last_seen=now).
    let kept = storage.delete_ip_bindings_older_than(0).await.unwrap();
    assert!(kept.is_empty(), "nothing should be older than the epoch");
    assert_eq!(storage.load_ip_bindings().await.unwrap().len(), 2);

    // A cutoff in the future treats both as stale → deleted, and returned so
    // the caller can drop them from memory.
    let future = chrono::Utc::now().timestamp() + 3600;
    let mut deleted = storage.delete_ip_bindings_older_than(future).await.unwrap();
    deleted.sort();
    assert_eq!(deleted, vec!["192.168.1.50", "192.168.1.51"]);
    assert!(storage.load_ip_bindings().await.unwrap().is_empty());

    // Touch is a no-op on unknown/empty input (no panic, nothing created).
    storage.touch_ip_bindings(&[]).await.unwrap();
    storage
        .touch_ip_bindings(&["10.0.0.9".to_string()])
        .await
        .unwrap();
    assert!(storage.load_ip_bindings().await.unwrap().is_empty());
}

#[tokio::test]
async fn query_log_off_keeps_the_rollups_and_writes_no_rows() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-scope-log-off"))
        .await
        .unwrap();
    let bucket = align_bucket(chrono::Utc::now().timestamp());

    storage
        .write_batch(
            vec![query_entry(
                bucket + 1,
                "stats-only.test",
                "192.168.1.10",
                QueryStatus::Blocked,
            )],
            RecordScope {
                queries: false,
                stats: true,
            },
        )
        .await
        .unwrap();

    // No per-query history…
    assert!(
        storage
            .query_range(&QueryFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
    // …but the aggregate still counts the query.
    assert_eq!(storage.summary(3600).await.unwrap(), (1, 1));
    assert_eq!(
        storage.top_domains(bucket, bucket + 599, 10).await.unwrap(),
        vec![("stats-only.test".to_string(), 1)]
    );
}

#[tokio::test]
async fn stats_off_keeps_the_log_and_aggregates_nothing() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-scope-stats-off"))
        .await
        .unwrap();
    let bucket = align_bucket(chrono::Utc::now().timestamp());

    storage
        .write_batch(
            vec![query_entry(
                bucket + 1,
                "log-only.test",
                "192.168.1.10",
                QueryStatus::Blocked,
            )],
            RecordScope {
                queries: true,
                stats: false,
            },
        )
        .await
        .unwrap();

    let rows = storage.query_range(&QueryFilter::default()).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].domain, "log-only.test");
    // Rollups are the statistics surface — nothing there, so the dashboard
    // graphs and top lists have nothing to show.
    assert_eq!(storage.summary(3600).await.unwrap(), (0, 0));
    assert!(
        storage
            .top_domains(bucket, bucket + 599, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .top_clients(bucket, bucket + 599, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn recording_fully_off_writes_nothing_at_all() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-scope-none"))
        .await
        .unwrap();
    let bucket = align_bucket(chrono::Utc::now().timestamp());

    storage
        .write_batch(
            vec![query_entry(
                bucket + 1,
                "nowhere.test",
                "192.168.1.10",
                QueryStatus::Upstream,
            )],
            RecordScope::NONE,
        )
        .await
        .unwrap();

    assert!(
        storage
            .query_range(&QueryFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(storage.summary(3600).await.unwrap(), (0, 0));
}

#[tokio::test]
async fn vacuum_runs_after_a_clear_and_leaves_the_database_usable() {
    let path = temp_db_path("ferrite-vacuum");
    let storage = SqliteStorage::open(&path).await.unwrap();
    let bucket = align_bucket(chrono::Utc::now().timestamp());
    let entries: Vec<QueryEntry> = (0..500)
        .map(|i| {
            query_entry(
                bucket + 1,
                &format!("domain-{i}.test"),
                "192.168.1.10",
                QueryStatus::Upstream,
            )
        })
        .collect();
    storage.write_batch_all(entries).await.unwrap();
    storage.delete_all_queries().await.unwrap();

    storage.vacuum().await.unwrap();

    // Still writable and readable after the file was rebuilt.
    storage
        .write_batch_all(vec![query_entry(
            bucket + 2,
            "after-vacuum.test",
            "192.168.1.10",
            QueryStatus::Upstream,
        )])
        .await
        .unwrap();
    let rows = storage.query_range(&QueryFilter::default()).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].domain, "after-vacuum.test");
}

#[tokio::test]
async fn delete_all_queries_clears_history_and_rollups() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-delete-all"))
        .await
        .unwrap();
    let bucket = align_bucket(chrono::Utc::now().timestamp());
    storage
        .write_batch_all(vec![
            query_entry(
                bucket + 1,
                "one.test",
                "192.168.1.10",
                QueryStatus::Upstream,
            ),
            query_entry(bucket + 2, "two.test", "192.168.1.11", QueryStatus::Blocked),
        ])
        .await
        .unwrap();
    assert_eq!(storage.summary(3600).await.unwrap(), (2, 1));

    storage.delete_all_queries().await.unwrap();

    assert!(
        storage
            .query_range(&QueryFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(storage.summary(3600).await.unwrap(), (0, 0));
    assert!(
        storage
            .top_domains(bucket, bucket + 599, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .top_clients(bucket, bucket + 599, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn retention_delete_removes_old_queries_and_rollups_only() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-retention"))
        .await
        .unwrap();
    let now_bucket = align_bucket(chrono::Utc::now().timestamp());
    let old_bucket = now_bucket - 10 * 86400;
    storage
        .write_batch_all(vec![
            query_entry(
                old_bucket + 1,
                "old.test",
                "192.168.1.10",
                QueryStatus::Blocked,
            ),
            query_entry(
                now_bucket + 1,
                "new.test",
                "192.168.1.10",
                QueryStatus::Upstream,
            ),
        ])
        .await
        .unwrap();

    let deleted = storage
        .delete_queries_older_than(now_bucket - 86400)
        .await
        .unwrap();

    assert_eq!(deleted, 1);
    let remaining = storage
        .query_range(&QueryFilter {
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].domain, "new.test");
    assert!(
        storage
            .top_blocked_domains(old_bucket, old_bucket + 599, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        storage
            .top_domains(now_bucket, now_bucket + 599, 10)
            .await
            .unwrap(),
        vec![("new.test".to_string(), 1)]
    );
}

#[tokio::test]
async fn device_keyed_rollups_merge_a_devices_ips_across_an_ip_change() {
    let storage = SqliteStorage::open(&temp_db_path("ferrite-device-rollup"))
        .await
        .unwrap();
    let bucket = align_bucket(chrono::Utc::now().timestamp());
    let mac = "aa:bb:cc:dd:ee:ff";
    // One device, three queries spanning two different IPs (it changed IP),
    // plus a second device that has no MAC (IP fallback token).
    storage
        .write_batch_all(vec![
            query_entry_dev(
                bucket + 1,
                "a.test",
                "192.168.1.50",
                mac,
                QueryStatus::Upstream,
            ),
            query_entry_dev(
                bucket + 2,
                "b.test",
                "192.168.1.50",
                mac,
                QueryStatus::Blocked,
            ),
            query_entry_dev(
                bucket + 3,
                "c.test",
                "192.168.1.77",
                mac,
                QueryStatus::Upstream,
            ),
            query_entry_dev(
                bucket + 4,
                "d.test",
                "10.0.0.9",
                "10.0.0.9",
                QueryStatus::Upstream,
            ),
        ])
        .await
        .unwrap();

    // The device's three queries (two IPs) aggregate into a single row.
    let clients = storage.top_clients(bucket, bucket + 599, 10).await.unwrap();
    assert_eq!(clients.len(), 2);
    let dev = clients.iter().find(|c| c.device == mac).unwrap();
    assert_eq!(dev.total, 3);
    assert_eq!(dev.blocked, 1);

    // Filtering the log by device returns every IP the device used.
    let rows = storage
        .query_range(&QueryFilter {
            devices: vec![mac.to_string()],
            limit: Some(100),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.device == mac));
    assert!(rows.iter().any(|r| r.client_ip == "192.168.1.50"));
    assert!(rows.iter().any(|r| r.client_ip == "192.168.1.77"));

    // Per-device stats are keyed by the device token.
    let cs = storage.client_stats(mac).await.unwrap().unwrap();
    assert_eq!(cs.device, mac);
    assert_eq!(cs.total, 3);
}

#[tokio::test]
async fn migration_upgrades_a_legacy_v0_database() {
    let path = temp_db_path("ferrite-migrate-v0");

    // Build a pre-versioning database: old single-`ip` client_aliases, a
    // `queries` table without the `device` column, and user_version = 0.
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE queries (
                 id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, domain TEXT NOT NULL,
                 query_type INTEGER NOT NULL, client_ip TEXT NOT NULL, status TEXT NOT NULL,
                 latency_ms INTEGER NOT NULL DEFAULT 0, upstream TEXT, rcode INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE client_aliases (ip TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
             INSERT INTO client_aliases (ip, name, created_at) VALUES ('192.168.1.10', 'Laptop', 0);
             INSERT INTO queries (id, timestamp, domain, query_type, client_ip, status, latency_ms, upstream, rcode)
                 VALUES (1, 1000, 'a.test', 1, '192.168.1.50', 'upstream', 0, NULL, 0),
                        (2, 1001, 'b.test', 1, '192.168.1.50', 'blocked', 0, NULL, 3);
             PRAGMA user_version = 0;",
        )
        .unwrap();
    }

    let storage = SqliteStorage::open(&path).await.unwrap();

    // user_version stamped to latest; `device` column added.
    let (version, has_device): (i64, bool) = {
        let c = rusqlite::Connection::open(&path).unwrap();
        let v = c
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        let d: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('queries') WHERE name='device'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (v, d > 0)
    };
    assert_eq!(version, SCHEMA_VERSION);
    assert!(has_device);

    // v6 removed the single-column indexes a composite already covers, and
    // left the ones that carry their own lookups. Checked on a database
    // that pre-dates them too: dropping what was never there must not fail.
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        let names: Vec<String> = c
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='queries'")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for gone in [
            "idx_queries_timestamp",
            "idx_queries_client_ip",
            "idx_queries_status",
            // v7: never used, see `migrate_v7_drop_unused_domain_index`.
            "idx_queries_domain",
        ] {
            assert!(!names.iter().any(|n| n == gone), "{gone} should be dropped");
        }
        for kept in [
            "idx_queries_time_id_desc",
            "idx_queries_status_time_id_desc",
            "idx_queries_client_time_id_desc",
            "idx_queries_device_time_id_desc",
        ] {
            assert!(names.iter().any(|n| n == kept), "{kept} should remain");
        }

        // The rollup keeps only the index its reads use.
        let rollup: Vec<String> = c
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='index'
                 AND tbl_name IN ('domain_buckets_10m', 'device_buckets_10m')",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            !rollup
                .iter()
                .any(|n| n == "idx_domain_buckets_domain_bucket"),
            "the domain rollup index is unused and should be dropped"
        );
        assert!(
            rollup
                .iter()
                .any(|n| n == "idx_device_buckets_device_bucket"),
            "per-device stats are read by device, so that index stays"
        );

        // And the lookups those single-column indexes used to serve still
        // go through an index, not a table scan.
        for (sql, expect) in [
            (
                "SELECT id FROM queries WHERE timestamp > 0 ORDER BY timestamp DESC, id DESC LIMIT 10",
                "idx_queries_time_id_desc",
            ),
            (
                "SELECT id FROM queries WHERE status = 'blocked' ORDER BY timestamp DESC, id DESC LIMIT 10",
                "idx_queries_status_time_id_desc",
            ),
            (
                "SELECT id FROM queries WHERE client_ip = '192.168.1.50' ORDER BY timestamp DESC, id DESC LIMIT 10",
                "idx_queries_client_time_id_desc",
            ),
            // The domain search the UI sends: a leading wildcard, which is
            // why an index on `domain` was worth nothing to it.
            (
                "SELECT id FROM queries WHERE domain LIKE '%ads%' ESCAPE '\\' ORDER BY timestamp DESC, id DESC LIMIT 10",
                "idx_queries_time_id_desc",
            ),
        ] {
            let plan: String = c
                .query_row(&format!("EXPLAIN QUERY PLAN {sql}"), [], |r| r.get(3))
                .unwrap();
            assert!(plan.contains(expect), "{sql}\n  planned as: {plan}");
        }
    }

    // client_aliases upgraded to (key, key_type) without losing data — read
    // back through the hand-off, which is all that still touches the table.
    assert_eq!(
        storage
            .load_legacy_config_rows()
            .await
            .unwrap()
            .client_aliases,
        vec![(
            "192.168.1.10".to_string(),
            "ip".to_string(),
            "Laptop".to_string()
        )]
    );

    // Legacy query rows backfilled to device = client_ip (no MAC history).
    let rows = storage
        .query_range(&QueryFilter {
            devices: vec!["192.168.1.50".to_string()],
            limit: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.device == "192.168.1.50"));

    // Device rollups were built from the backfilled rows.
    let cs = storage.client_stats("192.168.1.50").await.unwrap().unwrap();
    assert_eq!(cs.total, 2);
    assert_eq!(cs.blocked, 1);

    // Re-opening is a no-op: migrations are idempotent and data is preserved.
    drop(storage);
    let storage2 = SqliteStorage::open(&path).await.unwrap();
    assert_eq!(
        storage2
            .client_stats("192.168.1.50")
            .await
            .unwrap()
            .unwrap()
            .total,
        2
    );
}
