//! The versioned migration ladder on top of the baseline `SCHEMA`.

use super::table_exists;
use crate::ROLLUP_BUCKET_SECS;

/// Latest schema version. Bump when adding a migration step below.
pub(super) const SCHEMA_VERSION: i64 = 11;

/// Apply versioned migrations on top of the baseline `SCHEMA`.
///
/// Versioning uses the built-in `PRAGMA user_version` (a free integer in the DB
/// header — no extra table). Each step runs in its own transaction together with
/// the version bump, so a crash mid-migration rolls the step back cleanly. Every
/// step is written to be **idempotent / guarded** so it is safe on a fresh DB, on
/// an old DB, and on a half-migrated DB (e.g. tables added out-of-band while
/// `user_version` was still 0).
pub(super) fn run_migrations(c: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let mut version: i64 = c.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    while version < SCHEMA_VERSION {
        let next = version + 1;
        let tx = c.unchecked_transaction()?;
        match next {
            1 => migrate_v1_client_aliases(&tx)?,
            2 => migrate_v2_backfill_rollups(&tx)?,
            3 => migrate_v3_device_column(&tx)?,
            4 => migrate_v4_device_buckets(&tx)?,
            5 => migrate_v5_backfill_devices(&tx)?,
            6 => migrate_v6_drop_redundant_query_indexes(&tx)?,
            7 => migrate_v7_drop_unused_domain_index(&tx)?,
            8 => migrate_v8_drop_unused_domain_bucket_index(&tx)?,
            9 => migrate_v9_drop_unread_client_rollups(&tx)?,
            10 => migrate_v10_device_first_seen(&tx)?,
            11 => migrate_v11_sessions(&tx)?,
            _ => unreachable!("no migration step for v{next}"),
        }
        // PRAGMA can't be parameter-bound; the value is our own constant.
        tx.execute_batch(&format!("PRAGMA user_version = {next}"))?;
        tx.commit()?;
        tracing::info!("migrated database schema to v{next}");
        version = next;
    }
    Ok(())
}

/// v1: upgrade `client_aliases` from single `ip` PK to `(key, key_type)` PK.
fn migrate_v1_client_aliases(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    // Databases created after the table moved to `config.toml` never have it,
    // and a pre-v9 one that still does is handed over by
    // `load_legacy_config_rows` — either way there is nothing to reshape here.
    if !table_exists(tx, "client_aliases")? {
        return Ok(());
    }
    let has_key_col: bool = tx
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('client_aliases') WHERE name='key'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !has_key_col {
        tx.execute_batch(
            "ALTER TABLE client_aliases RENAME TO client_aliases_old;
             CREATE TABLE client_aliases (
                 key         TEXT    NOT NULL,
                 key_type    TEXT    NOT NULL DEFAULT 'ip',
                 name        TEXT    NOT NULL,
                 created_at  INTEGER NOT NULL,
                 PRIMARY KEY (key, key_type)
             );
             INSERT INTO client_aliases (key, key_type, name, created_at)
                 SELECT ip, 'ip', name, created_at FROM client_aliases_old;
             DROP TABLE client_aliases_old;",
        )?;
    }
    Ok(())
}

/// v2: backfill the original rollup tables from existing query rows (one-time).
fn migrate_v2_backfill_rollups(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    let query_count: i64 = tx.query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))?;
    if query_count == 0 {
        return Ok(());
    }
    let rollup_count: i64 = tx.query_row("SELECT COUNT(*) FROM query_buckets_10m", [], |row| {
        row.get(0)
    })?;
    if rollup_count > 0 {
        return Ok(());
    }

    tracing::info!(
        "backfilling SQLite query rollups from {} existing query rows",
        query_count
    );
    let sql = format!(
        r#"
        DELETE FROM query_buckets_10m;
        DELETE FROM domain_buckets_10m;

        INSERT INTO query_buckets_10m (bucket, total, blocked, cached, upstream)
        SELECT (timestamp / {bucket_secs}) * {bucket_secs} as bucket,
               COUNT(*) as total,
               SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) as blocked,
               SUM(CASE WHEN status='cached' THEN 1 ELSE 0 END) as cached,
               SUM(CASE WHEN status='upstream' THEN 1 ELSE 0 END) as upstream
        FROM queries
        GROUP BY bucket;

        INSERT INTO domain_buckets_10m (bucket, domain, total, blocked)
        SELECT (timestamp / {bucket_secs}) * {bucket_secs} as bucket,
               domain,
               COUNT(*) as total,
               SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) as blocked
        FROM queries
        GROUP BY bucket, domain;
        "#,
        bucket_secs = ROLLUP_BUCKET_SECS
    );
    tx.execute_batch(&sql)?;
    Ok(())
}

/// v3: add the per-query `device` column + its keyset index.
fn migrate_v3_device_column(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    let has_device: bool = tx
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('queries') WHERE name='device'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if !has_device {
        tx.execute_batch("ALTER TABLE queries ADD COLUMN device TEXT")?;
    }
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_queries_device_time_id_desc
             ON queries (device, timestamp DESC, id DESC)",
    )?;
    Ok(())
}

/// v6: drop the single-column `queries` indexes that a composite already covers.
///
/// `timestamp`, `client_ip` and `status` each lead one of the `…_time_id_desc`
/// composites, and SQLite answers a lookup from a leftmost prefix — so those
/// three indexes only added b-tree writes to every logged query and bytes to
/// the file. Dropping them is safe to repeat and safe on a database that never
/// had them.
fn migrate_v6_drop_redundant_query_indexes(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    tx.execute_batch(
        "DROP INDEX IF EXISTS idx_queries_timestamp;
         DROP INDEX IF EXISTS idx_queries_client_ip;
         DROP INDEX IF EXISTS idx_queries_status;",
    )
}

/// v7: drop `idx_queries_domain`, which every logged query paid for and no read
/// ever used.
///
/// The query log's only domain filter is `domain LIKE '%…%'` — a leading
/// wildcard, which a b-tree cannot answer, so the planner scans the timestamp
/// index either way (pinned by the plan assertions in the migration test). Of
/// all the indexes on this table it was the priciest to maintain: a string key
/// arriving in random order splits pages on nearly every insert.
fn migrate_v7_drop_unused_domain_index(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    tx.execute_batch("DROP INDEX IF EXISTS idx_queries_domain;")
}

/// v8: drop `idx_domain_buckets_domain_bucket`, the rollup's counterpart to v7.
///
/// The domain rollup is read one way — a bucket range grouped by domain, which
/// the primary key already covers — and written once per distinct domain per
/// flush. The extra index doubled the cost of every one of those upserts
/// (3.0 µs → 1.4 µs without it) and the table on disk (−43%), for a lookup
/// nothing performs. The device rollup keeps its index: per-device stats are
/// genuinely fetched by device.
fn migrate_v8_drop_unused_domain_bucket_index(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    tx.execute_batch("DROP INDEX IF EXISTS idx_domain_buckets_domain_bucket;")
}

/// v9: drop the two client rollup tables nothing reads.
///
/// `client_buckets_10m` was superseded by `device_buckets_10m` in v4 — rollups
/// keyed by device rather than by IP, so a phone keeps one row across a DHCP
/// change. Every read moved over; the IP-keyed table kept being written and
/// never read. `client_stats` never had a reader at all: `top_clients` and
/// `client_stats()` both aggregate `device_buckets_10m` directly.
fn migrate_v9_drop_unread_client_rollups(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    tx.execute_batch(
        "DROP TABLE IF EXISTS client_buckets_10m;
         DROP TABLE IF EXISTS client_stats;",
    )
}

/// v4: per-device rollup table — the same shape as the IP-keyed rollups it
/// replaces, but keyed by device so a phone keeps one row across a DHCP change.
/// The IP-keyed table is dropped in v9.
/// v10: devices remember when they were first seen, and every MAC the box has
/// a binding for becomes a device row. "A new device joined" is then a MAC
/// with no row — so the backfill is what keeps an upgrade from announcing
/// every device already on the network. Rows that predate this keep
/// `first_seen = 0`: known, but not since when.
fn migrate_v10_device_first_seen(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    let has_col: bool = tx.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name='first_seen'",
        [],
        |row| row.get::<_, i64>(0),
    )? > 0;
    if !has_col {
        tx.execute_batch("ALTER TABLE devices ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0")?;
    }
    tx.execute_batch(
        "INSERT OR IGNORE INTO devices (mac, hostname, last_seen, first_seen)
         SELECT mac, NULL, MAX(last_seen), 0 FROM ip_bindings GROUP BY mac",
    )
}

/// v11: web-panel login sessions are kept in the database.
fn migrate_v11_sessions(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS sessions (
             token_hash  TEXT    PRIMARY KEY,
             password_fp TEXT    NOT NULL,
             expires     INTEGER NOT NULL
         )",
    )
}

fn migrate_v4_device_buckets(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS device_buckets_10m (
             bucket     INTEGER NOT NULL,
             device     TEXT    NOT NULL,
             total      INTEGER NOT NULL DEFAULT 0,
             blocked    INTEGER NOT NULL DEFAULT 0,
             last_seen  INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY (bucket, device)
         );
         CREATE INDEX IF NOT EXISTS idx_device_buckets_device_bucket
             ON device_buckets_10m (device, bucket);",
    )?;
    Ok(())
}

/// v5: tag legacy query rows with a device and build the device rollups.
///
/// Old rows predate device tagging: map each `client_ip` to its last-known MAC
/// via `ip_bindings` if known, else fall back to the IP itself. On databases that
/// predate `ip_bindings` it is empty, so virtually all historical rows fall back
/// to `device = client_ip` — accepted; accuracy improves for rows written later.
fn migrate_v5_backfill_devices(tx: &rusqlite::Transaction) -> rusqlite::Result<()> {
    tx.execute_batch(
        "UPDATE queries
         SET device = COALESCE((SELECT mac FROM ip_bindings WHERE ip = client_ip), client_ip)
         WHERE device IS NULL",
    )?;

    let device_rollup_count: i64 =
        tx.query_row("SELECT COUNT(*) FROM device_buckets_10m", [], |row| {
            row.get(0)
        })?;
    if device_rollup_count == 0 {
        let sql = format!(
            "INSERT INTO device_buckets_10m (bucket, device, total, blocked, last_seen)
             SELECT (timestamp / {bucket_secs}) * {bucket_secs} as bucket,
                    device,
                    COUNT(*) as total,
                    SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) as blocked,
                    MAX(timestamp) as last_seen
             FROM queries
             WHERE device IS NOT NULL
             GROUP BY bucket, device",
            bucket_secs = ROLLUP_BUCKET_SECS
        );
        tx.execute_batch(&sql)?;
    }
    Ok(())
}
