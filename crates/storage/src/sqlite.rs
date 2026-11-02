use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

use crate::schema::SCHEMA;
use crate::{
    ClientStats, LegacyConfigRows, QueryFilter, SizeTrim, Storage, StoredDevice, SummaryStats,
    align_bucket,
};
use ferrite_core::error::{FeriteError, Result};
use ferrite_core::recording::RecordScope;
use ferrite_core::types::TimeseriesBucket;
use ferrite_core::types::{QueryEntry, QueryStatus};
use migrations::run_migrations;

/// Query rows a single size-cap pass drops per round. Big enough that a
/// database far over its cap converges in a few rounds, small enough that each
/// DELETE holds the single connection briefly.
const SIZE_TRIM_BATCH: i64 = 10_000;

/// Rounds one size-cap pass will do before returning. Bounds how long the
/// connection can be busy trimming; the next pass (a minute later) continues.
const SIZE_TRIM_MAX_ROUNDS: usize = 64;

pub struct SqliteStorage {
    conn: Connection,
}

#[derive(Default)]
struct QueryBucketAgg {
    total: u64,
    blocked: u64,
    cached: u64,
    upstream: u64,
}

#[derive(Default)]
struct DomainBucketAgg {
    total: u64,
    blocked: u64,
}

#[derive(Default)]
struct ClientBucketAgg {
    total: u64,
    blocked: u64,
    last_seen: i64,
}

impl SqliteStorage {
    pub async fn open(path: &Path) -> Result<Arc<Self>> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let conn = Connection::open(path).await?;

        // Apply the baseline schema (all CREATE … IF NOT EXISTS, idempotent),
        // then run the versioned migration ladder. See `run_migrations`.
        conn.call(|c| c.execute_batch(SCHEMA)).await?;
        conn.call(run_migrations).await?;

        tracing::info!("SQLite storage opened at {}", path.display());
        Ok(Arc::new(Self { conn }))
    }
}

#[cfg(any(test, feature = "testutil"))]
impl SqliteStorage {
    /// Recreate the pre-v9 configuration tables and fill them from `rows`, so
    /// the one-time hand-off into `config.toml` can be exercised end to end.
    pub async fn seed_legacy_config_tables(&self, rows: &LegacyConfigRows) -> Result<()> {
        let rows = rows.clone();
        self.conn
            .call(move |c| {
                c.execute_batch(
                    "CREATE TABLE IF NOT EXISTS custom_entries (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         domain TEXT NOT NULL UNIQUE,
                         entry_type TEXT NOT NULL,
                         comment TEXT,
                         created_at INTEGER NOT NULL);
                     CREATE TABLE IF NOT EXISTS custom_dns_records (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         domain TEXT NOT NULL,
                         record_type TEXT NOT NULL,
                         value TEXT NOT NULL,
                         ttl INTEGER NOT NULL DEFAULT 300,
                         created_at INTEGER NOT NULL);
                     CREATE TABLE IF NOT EXISTS client_aliases (
                         key TEXT NOT NULL,
                         key_type TEXT NOT NULL DEFAULT 'ip',
                         name TEXT NOT NULL,
                         created_at INTEGER NOT NULL,
                         PRIMARY KEY (key, key_type));
                     CREATE TABLE IF NOT EXISTS blocklists (id INTEGER PRIMARY KEY, name TEXT);
                     CREATE TABLE IF NOT EXISTS settings (
                         key TEXT PRIMARY KEY, value TEXT NOT NULL);",
                )?;
                // `created_at` orders the reads back, so count the inserts.
                for (i, (domain, entry_type)) in rows.custom_entries.iter().enumerate() {
                    c.execute(
                        "INSERT INTO custom_entries (domain, entry_type, created_at)
                         VALUES (?1, ?2, ?3)",
                        rusqlite::params![domain, entry_type, i as i64],
                    )?;
                }
                for (i, r) in rows.custom_records.iter().enumerate() {
                    c.execute(
                        "INSERT INTO custom_dns_records
                             (domain, record_type, value, ttl, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![r.domain, r.record_type, r.value, r.ttl as i64, i as i64],
                    )?;
                }
                for (i, (key, key_type, name)) in rows.client_aliases.iter().enumerate() {
                    c.execute(
                        "INSERT INTO client_aliases (key, key_type, name, created_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![key, key_type, name, i as i64],
                    )?;
                }
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn write_batch(&self, entries: Vec<QueryEntry>, scope: RecordScope) -> Result<()> {
        if entries.is_empty() || !scope.records_anything() {
            return Ok(());
        }

        self.conn
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                let mut query_buckets: HashMap<i64, QueryBucketAgg> = HashMap::new();
                let mut domain_buckets: HashMap<(i64, String), DomainBucketAgg> = HashMap::new();
                let mut device_buckets: HashMap<(i64, String), ClientBucketAgg> = HashMap::new();

                {
                    // Explicit id: keeps SQLite ids identical to in-memory ids
                    // (counter is seeded from MAX(id) at startup, so no collisions).
                    // Prepared only when the query log is on — with it off the
                    // batch is here purely to feed the rollups.
                    let mut stmt = if scope.queries {
                        Some(tx.prepare_cached(
                            "INSERT INTO queries (id, timestamp, domain, query_type, client_ip, device, status, latency_ms, upstream, rcode)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        )?)
                    } else {
                        None
                    };
                    for e in &entries {
                        // Defensive fallback: an untagged entry keys to its IP so it is
                        // never written with an empty device token.
                        let device = device_token(e);
                        if let Some(stmt) = stmt.as_mut() {
                            stmt.execute(rusqlite::params![
                                e.id as i64,
                                e.timestamp.timestamp(),
                                e.domain,
                                e.query_type as i64,
                                e.client_ip,
                                device,
                                e.status.as_str(),
                                e.latency_ms as i64,
                                e.upstream,
                                e.rcode as i64,
                            ])?;
                        }

                        if scope.stats {
                            collect_rollup_aggregates(
                                e,
                                device,
                                &mut query_buckets,
                                &mut domain_buckets,
                                &mut device_buckets,
                            );
                        }
                    }
                }
                if scope.stats {
                    let mut stmt = tx.prepare_cached(
                        "INSERT INTO query_buckets_10m (bucket, total, blocked, cached, upstream)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT(bucket) DO UPDATE SET
                            total = query_buckets_10m.total + excluded.total,
                            blocked = query_buckets_10m.blocked + excluded.blocked,
                            cached = query_buckets_10m.cached + excluded.cached,
                            upstream = query_buckets_10m.upstream + excluded.upstream",
                    )?;
                    for (bucket, agg) in &query_buckets {
                        stmt.execute(rusqlite::params![
                            bucket,
                            agg.total as i64,
                            agg.blocked as i64,
                            agg.cached as i64,
                            agg.upstream as i64,
                        ])?;
                    }
                }
                if scope.stats {
                    let mut stmt = tx.prepare_cached(
                        "INSERT INTO domain_buckets_10m (bucket, domain, total, blocked)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(bucket, domain) DO UPDATE SET
                            total = domain_buckets_10m.total + excluded.total,
                            blocked = domain_buckets_10m.blocked + excluded.blocked",
                    )?;
                    for ((bucket, domain), agg) in &domain_buckets {
                        stmt.execute(rusqlite::params![
                            bucket,
                            domain,
                            agg.total as i64,
                            agg.blocked as i64,
                        ])?;
                    }
                }
                if scope.stats {
                    let mut stmt = tx.prepare_cached(
                        "INSERT INTO device_buckets_10m (bucket, device, total, blocked, last_seen)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT(bucket, device) DO UPDATE SET
                            total = device_buckets_10m.total + excluded.total,
                            blocked = device_buckets_10m.blocked + excluded.blocked,
                            last_seen = MAX(device_buckets_10m.last_seen, excluded.last_seen)",
                    )?;
                    for ((bucket, device), agg) in &device_buckets {
                        stmt.execute(rusqlite::params![
                            bucket,
                            device,
                            agg.total as i64,
                            agg.blocked as i64,
                            agg.last_seen,
                        ])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn max_query_id(&self) -> Result<u64> {
        self.conn
            .call(|c| {
                // COALESCE keeps the empty table a clean 0 rather than a NULL.
                let id: i64 =
                    c.query_row("SELECT COALESCE(MAX(id), 0) FROM queries", [], |r| r.get(0))?;
                Ok(id as u64)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn query_range(&self, filter: &QueryFilter) -> Result<Vec<QueryEntry>> {
        let filter = filter.clone();
        let rows = self.conn
            .call(move |c| {
                let mut sql = String::from(
                    "SELECT id, timestamp, domain, query_type, client_ip, device, status, latency_ms, upstream, rcode FROM queries WHERE 1=1",
                );
                let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

                if let Some(from) = filter.from_ts {
                    sql.push_str(" AND timestamp >= ?");
                    params.push(Box::new(from));
                }
                if let Some(to) = filter.to_ts {
                    sql.push_str(" AND timestamp <= ?");
                    params.push(Box::new(to));
                }
                if let Some(ref domain) = filter.domain {
                    let escaped = domain
                        .replace('\\', "\\\\")
                        .replace('%', "\\%")
                        .replace('_', "\\_");
                    sql.push_str(" AND domain LIKE ? ESCAPE '\\'");
                    params.push(Box::new(format!("%{}%", escaped)));
                }
                // Identity filter: match by raw IP and/or by device token, OR-combined
                // so "all queries from device X" spans every IP it ever used.
                let mut id_clauses: Vec<String> = Vec::new();
                if !filter.client_ips.is_empty() {
                    let placeholders = filter.client_ips.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
                    id_clauses.push(format!("client_ip IN ({})", placeholders));
                    for ip in &filter.client_ips {
                        params.push(Box::new(ip.clone()));
                    }
                }
                if !filter.devices.is_empty() {
                    let placeholders = filter.devices.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
                    id_clauses.push(format!("device IN ({})", placeholders));
                    for d in &filter.devices {
                        params.push(Box::new(d.clone()));
                    }
                }
                if !id_clauses.is_empty() {
                    sql.push_str(&format!(" AND ({})", id_clauses.join(" OR ")));
                }
                if let Some(ref status) = filter.status {
                    sql.push_str(" AND status = ?");
                    params.push(Box::new(status.clone()));
                }

                let cursor = filter.before_ts.zip(filter.before_id);
                if let Some((before_ts, before_id)) = cursor {
                    sql.push_str(" AND (timestamp < ? OR (timestamp = ? AND id < ?))");
                    params.push(Box::new(before_ts));
                    params.push(Box::new(before_ts));
                    params.push(Box::new(before_id as i64));
                }

                sql.push_str(" ORDER BY timestamp DESC, id DESC LIMIT ?");
                params.push(Box::new(filter.limit.unwrap_or(100) as i64));
                if cursor.is_none() {
                    let offset = filter.offset.unwrap_or(0);
                    if offset > 0 {
                        sql.push_str(" OFFSET ?");
                        params.push(Box::new(offset as i64));
                    }
                }

                let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
                let mut stmt = c.prepare(&sql)?;
                let rows = stmt.query_map(refs.as_slice(), |row| {
                    let id: i64 = row.get(0)?;
                    let ts: i64 = row.get(1)?;
                    let domain: String = row.get(2)?;
                    let query_type: i64 = row.get(3)?;
                    let client_ip: String = row.get(4)?;
                    // Legacy rows may still be NULL until backfilled — fall back to the IP.
                    let device: Option<String> = row.get(5)?;
                    let status_str: String = row.get(6)?;
                    let latency_ms: i64 = row.get(7)?;
                    let upstream: Option<String> = row.get(8)?;
                    let rcode: i64 = row.get(9)?;

                    Ok((id, ts, domain, query_type, client_ip, device, status_str, latency_ms, upstream, rcode))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;

                Ok(rows)
            })
            .await
            .map_err(FeriteError::TokioDatabase)?;

        let entries = rows
            .into_iter()
            .map(
                |(
                    id,
                    ts,
                    domain,
                    query_type,
                    client_ip,
                    device,
                    status_str,
                    latency_ms,
                    upstream,
                    rcode,
                )| {
                    let status = match status_str.as_str() {
                        "blocked" => QueryStatus::Blocked,
                        "cached" => QueryStatus::Cached,
                        "allowed" => QueryStatus::Allowed,
                        "routed" => QueryStatus::Routed,
                        _ => QueryStatus::Upstream,
                    };
                    let device = device.unwrap_or_else(|| client_ip.clone());
                    QueryEntry {
                        id: id as u64,
                        timestamp: chrono::DateTime::from_timestamp(ts, 0)
                            .unwrap_or_default()
                            .with_timezone(&chrono::Utc),
                        domain,
                        query_type: query_type as u16,
                        client_ip,
                        device,
                        status,
                        latency_ms: latency_ms as u32,
                        upstream,
                        rcode: rcode.min(255) as u8,
                    }
                },
            )
            .collect();

        Ok(entries)
    }

    async fn top_domains(&self, from_ts: i64, to_ts: i64, n: usize) -> Result<Vec<(String, u64)>> {
        top_domains_rollup_query(&self.conn, from_ts, to_ts, n, false).await
    }

    async fn top_blocked_domains(
        &self,
        from_ts: i64,
        to_ts: i64,
        n: usize,
    ) -> Result<Vec<(String, u64)>> {
        top_domains_rollup_query(&self.conn, from_ts, to_ts, n, true).await
    }

    async fn top_clients(&self, from_ts: i64, to_ts: i64, n: usize) -> Result<Vec<ClientStats>> {
        let from_bucket = align_bucket(from_ts);
        let to_bucket = align_bucket(to_ts);
        let rows = self
            .conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT device,
                            SUM(total) as total,
                            SUM(blocked) as blocked,
                            MAX(last_seen) as last_seen
                     FROM device_buckets_10m
                     WHERE bucket >= ?1 AND bucket <= ?2
                     GROUP BY device
                     ORDER BY total DESC, device ASC LIMIT ?3",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![from_bucket, to_bucket, n as i64], |row| {
                        Ok(ClientStats {
                            device: row.get(0)?,
                            total: row.get::<_, i64>(1)? as u64,
                            blocked: row.get::<_, i64>(2)? as u64,
                            last_seen: row.get(3)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .map_err(FeriteError::TokioDatabase)?;
        Ok(rows)
    }

    async fn timeseries(&self, bucket_secs: u64) -> Result<Vec<TimeseriesBucket>> {
        let bs = bucket_secs as i64;
        let rows = self
            .conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT (bucket / ?1) * ?1 as out_bucket,
                            SUM(total) as total,
                            SUM(blocked) as blocked,
                            SUM(cached) as cached,
                            SUM(upstream) as upstream
                     FROM query_buckets_10m
                     WHERE bucket >= ((strftime('%s','now') - 86400) / ?1) * ?1
                     GROUP BY out_bucket
                     ORDER BY out_bucket ASC",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![bs], |row| {
                        Ok(TimeseriesBucket {
                            bucket: row.get::<_, i64>(0)? as u64,
                            total: row.get::<_, i64>(1)? as u64,
                            blocked: row.get::<_, i64>(2)? as u64,
                            cached: row.get::<_, i64>(3)? as u64,
                            upstream: row.get::<_, i64>(4)? as u64,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .map_err(FeriteError::TokioDatabase)?;
        Ok(rows)
    }

    async fn client_stats(&self, device: &str) -> Result<Option<ClientStats>> {
        let device = device.to_string();
        let result = self
            .conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT device,
                            SUM(total) as total,
                            SUM(blocked) as blocked,
                            MAX(last_seen) as last_seen
                     FROM device_buckets_10m WHERE device = ?1 GROUP BY device",
                )?;
                let row = stmt
                    .query_row(rusqlite::params![device], |row| {
                        Ok(ClientStats {
                            device: row.get(0)?,
                            total: row.get::<_, i64>(1)? as u64,
                            blocked: row.get::<_, i64>(2)? as u64,
                            last_seen: row.get(3)?,
                        })
                    })
                    .optional()?;
                Ok(row)
            })
            .await
            .map_err(FeriteError::TokioDatabase)?;
        Ok(result)
    }

    async fn delete_all_queries(&self) -> Result<()> {
        self.conn
            .call(|c| {
                c.execute_batch(
                    "DELETE FROM queries;
                     DELETE FROM query_buckets_10m;
                     DELETE FROM domain_buckets_10m;
                     DELETE FROM device_buckets_10m;",
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn vacuum(&self) -> Result<()> {
        self.conn
            .call(|c| {
                // Fold the WAL into the main file first: VACUUM rebuilds the
                // database but leaves a long WAL untouched, so a log cleared on a
                // busy box would still keep its pages (and its domains) on disk.
                // Then checkpoint again — the rebuild itself lands in the WAL, and
                // leaving that behind means the space never returns to the card.
                c.execute_batch(
                    "PRAGMA wal_checkpoint(TRUNCATE);
                     VACUUM;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn delete_queries_older_than(&self, cutoff_ts: i64) -> Result<u64> {
        self.conn
            .call(move |c| delete_before(c, cutoff_ts))
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn summary(&self, secs: u64) -> Result<(u64, u64)> {
        let from_bucket = align_bucket(chrono::Utc::now().timestamp() - secs as i64);
        let counts = self
            .summary_counts(from_bucket, chrono::Utc::now().timestamp())
            .await?;
        Ok((counts.total, counts.blocked))
    }

    async fn summary_counts(&self, from_ts: i64, to_ts: i64) -> Result<SummaryStats> {
        let from_bucket = align_bucket(from_ts);
        let to_bucket = align_bucket(to_ts);
        let result = self
            .conn
            .call(move |c| {
                let row = c.query_row(
                    "SELECT COALESCE(SUM(total), 0),
                            COALESCE(SUM(blocked), 0),
                            COALESCE(SUM(cached), 0),
                            COALESCE(SUM(upstream), 0)
                     FROM query_buckets_10m
                     WHERE bucket >= ?1 AND bucket <= ?2",
                    rusqlite::params![from_bucket, to_bucket],
                    |row| {
                        Ok(SummaryStats {
                            total: row.get::<_, i64>(0)? as u64,
                            blocked: row.get::<_, i64>(1)? as u64,
                            cached: row.get::<_, i64>(2)? as u64,
                            upstream: row.get::<_, i64>(3)? as u64,
                        })
                    },
                )?;
                Ok(row)
            })
            .await
            .map_err(FeriteError::TokioDatabase)?;
        Ok(result)
    }

    async fn upsert_device(&self, mac: &str, hostname: Option<&str>) -> Result<()> {
        let mac = mac.to_string();
        let hostname = hostname.map(|s| s.to_string());
        let now = chrono::Utc::now().timestamp();
        self.conn
            .call(move |c| {
                // COALESCE keeps a previously learned hostname if this call has none,
                // so a transient nameless resolve never blanks a known device.
                // `first_seen` is written on insert only; an update leaves it.
                c.execute(
                    "INSERT INTO devices (mac, hostname, last_seen, first_seen)
                     VALUES (?1, ?2, ?3, ?3)
                     ON CONFLICT(mac) DO UPDATE SET
                         hostname  = COALESCE(excluded.hostname, devices.hostname),
                         last_seen = excluded.last_seen",
                    rusqlite::params![mac, hostname, now],
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn upsert_ip_binding(&self, ip: &str, mac: &str) -> Result<()> {
        let ip = ip.to_string();
        let mac = mac.to_string();
        let now = chrono::Utc::now().timestamp();
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT INTO ip_bindings (ip, mac, last_seen)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(ip) DO UPDATE SET
                         mac       = excluded.mac,
                         last_seen = excluded.last_seen",
                    rusqlite::params![ip, mac, now],
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn delete_all_ip_bindings(&self) -> Result<()> {
        self.conn
            .call(|c| {
                c.execute("DELETE FROM ip_bindings", [])?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn database_bytes(&self) -> Result<u64> {
        self.conn
            .call(|c| {
                let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
                let page_size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
                Ok((pages.max(0) as u64) * (page_size.max(0) as u64))
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn delete_all_devices(&self) -> Result<()> {
        self.conn
            .call(|c| {
                c.execute("DELETE FROM devices", [])?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn touch_ip_bindings(&self, ips: &[String]) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let ips = ips.to_vec();
        let now = chrono::Utc::now().timestamp();
        self.conn
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                {
                    let mut stmt =
                        tx.prepare("UPDATE ip_bindings SET last_seen = ?1 WHERE ip = ?2")?;
                    for ip in &ips {
                        stmt.execute(rusqlite::params![now, ip])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn delete_ip_bindings_older_than(&self, cutoff_ts: i64) -> Result<Vec<String>> {
        self.conn
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                let deleted: Vec<String> = {
                    let mut stmt = tx.prepare("SELECT ip FROM ip_bindings WHERE last_seen < ?1")?;
                    stmt.query_map(rusqlite::params![cutoff_ts], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                tx.execute(
                    "DELETE FROM ip_bindings WHERE last_seen < ?1",
                    rusqlite::params![cutoff_ts],
                )?;
                tx.commit()?;
                Ok(deleted)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn load_devices(&self) -> Result<Vec<StoredDevice>> {
        self.conn
            .call(|c| {
                let mut stmt = c.prepare("SELECT mac, hostname, first_seen FROM devices")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(StoredDevice {
                            mac: row.get(0)?,
                            hostname: row.get(1)?,
                            first_seen: row.get(2)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn load_ip_bindings(&self) -> Result<Vec<(String, String)>> {
        self.conn
            .call(|c| {
                let mut stmt = c.prepare("SELECT ip, mac FROM ip_bindings")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn prepare_size_cap(&self) -> Result<bool> {
        self.conn
            .call(|c| {
                // 0 = none, 1 = full, 2 = incremental. Without incremental (or
                // full) auto-vacuum, deleting rows only moves pages onto the
                // freelist — the file never shrinks, so a size cap could never
                // be met and would delete the whole log trying.
                let mode: i64 = c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
                if mode == 2 {
                    return Ok(false);
                }
                // Changing it rewrites the whole file, which is why this is not
                // done on every database — only once, for one that opts into a
                // cap. New databases are created incremental by the schema.
                c.execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;")?;
                Ok(true)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn enforce_size_cap(&self, max_bytes: u64) -> Result<SizeTrim> {
        self.conn
            .call(move |c| {
                let bytes_before = used_bytes(c)?;
                let mut trim = SizeTrim {
                    rows_deleted: 0,
                    bytes_before,
                    bytes_after: bytes_before,
                };

                for _ in 0..SIZE_TRIM_MAX_ROUNDS {
                    if trim.bytes_after <= max_bytes {
                        break;
                    }

                    // The timestamp just past the oldest batch. `+ 1` so rows
                    // sharing that second go too: without it a batch boundary
                    // landing inside a run of equal timestamps deletes nothing
                    // and the loop makes no progress.
                    let cutoff: Option<i64> = c
                        .query_row(
                            "SELECT timestamp FROM queries
                             ORDER BY timestamp ASC, id ASC LIMIT 1 OFFSET ?1",
                            rusqlite::params![SIZE_TRIM_BATCH],
                            |r| r.get(0),
                        )
                        .optional()?;
                    // Fewer rows left than a batch: the log is not what is
                    // taking the space. Stop rather than delete all of it.
                    let Some(cutoff) = cutoff else { break };

                    let deleted = delete_before(c, cutoff + 1)?;
                    if deleted == 0 {
                        break;
                    }
                    trim.rows_deleted += deleted;

                    // Hand the freed pages back; `used_bytes` counts the
                    // freelist out anyway, but on a RAM-backed path the file
                    // itself has to shrink for the cap to mean anything.
                    release_free_pages(c)?;
                    trim.bytes_after = used_bytes(c)?;
                }

                Ok(trim)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn load_legacy_config_rows(&self) -> Result<LegacyConfigRows> {
        self.conn
            .call(|c| {
                let mut rows = LegacyConfigRows::default();

                if table_exists(c, "custom_entries")? {
                    let mut stmt = c.prepare(
                        "SELECT domain, entry_type FROM custom_entries ORDER BY created_at ASC",
                    )?;
                    rows.custom_entries = stmt
                        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                }

                if table_exists(c, "custom_dns_records")? {
                    let mut stmt = c.prepare(
                        "SELECT domain, record_type, value, ttl FROM custom_dns_records
                         ORDER BY created_at ASC",
                    )?;
                    rows.custom_records = stmt
                        .query_map([], |r| {
                            Ok(ferrite_core::config::CustomRecordConfig {
                                domain: r.get(0)?,
                                record_type: r.get(1)?,
                                value: r.get(2)?,
                                ttl: r.get::<_, i64>(3)? as u32,
                            })
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                }

                if table_exists(c, "client_aliases")? {
                    let mut stmt = c.prepare(
                        "SELECT key, key_type, name FROM client_aliases ORDER BY created_at ASC",
                    )?;
                    rows.client_aliases = stmt
                        .query_map([], |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, String>(2)?,
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                }

                Ok(rows)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn drop_legacy_config_tables(&self) -> Result<()> {
        self.conn
            .call(|c| {
                // `blocklists` and `settings` never had a reader — they were
                // created by the baseline schema and nothing ever wrote them.
                c.execute_batch(
                    "DROP TABLE IF EXISTS custom_entries;
                     DROP TABLE IF EXISTS custom_dns_records;
                     DROP TABLE IF EXISTS client_aliases;
                     DROP TABLE IF EXISTS blocklists;
                     DROP TABLE IF EXISTS settings;",
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return the freelist to the filesystem, shrinking the database file.
///
/// `PRAGMA incremental_vacuum` yields **one row per page it frees**, so it has
/// to be stepped to exhaustion: `execute_batch` steps a statement once, which
/// frees a single page and looks like it worked. Draining it is the difference
/// between a 51 MB file and an 8 MB one.
fn release_free_pages(c: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mut stmt = c.prepare("PRAGMA incremental_vacuum")?;
    let mut rows = stmt.query([])?;
    while rows.next()?.is_some() {}
    Ok(())
}

/// Bytes the database actually holds, excluding pages already on the freelist.
///
/// `database_bytes` reports the file's size; this reports what is in it. The
/// distinction is what makes a size cap terminate: right after a delete the
/// file has not shrunk yet, and a cap compared against the file size would
/// keep deleting rows that were already gone.
fn used_bytes(c: &rusqlite::Connection) -> rusqlite::Result<u64> {
    let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let page_size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok(((pages - free).max(0) as u64) * (page_size.max(0) as u64))
}

/// Delete query rows older than `cutoff_ts` and the rollup buckets they fed.
/// Shared by age-based retention and the size cap so the two can't drift on
/// what "delete old history" means.
fn delete_before(c: &rusqlite::Connection, cutoff_ts: i64) -> rusqlite::Result<u64> {
    let cutoff_bucket = align_bucket(cutoff_ts);
    let tx = c.unchecked_transaction()?;
    let n = tx.execute(
        "DELETE FROM queries WHERE timestamp < ?1",
        rusqlite::params![cutoff_ts],
    )?;
    for table in [
        "query_buckets_10m",
        "domain_buckets_10m",
        "device_buckets_10m",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE bucket < ?1"),
            rusqlite::params![cutoff_bucket],
        )?;
    }
    tx.commit()?;
    Ok(n as u64)
}

/// Does `name` exist as a table in this database? Used wherever code has to
/// cope with both a pre-v9 database and one created after the configuration
/// tables were removed from the baseline schema.
fn table_exists(c: &rusqlite::Connection, name: &str) -> rusqlite::Result<bool> {
    c.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        rusqlite::params![name],
        |row| row.get::<_, i64>(0),
    )
    .map(|n| n > 0)
}

/// The device identity token a query is written under: its tagged `device`
/// (set by the stats writer), falling back to the client IP when untagged.
fn device_token(entry: &QueryEntry) -> &str {
    if entry.device.is_empty() {
        &entry.client_ip
    } else {
        &entry.device
    }
}

fn collect_rollup_aggregates(
    entry: &QueryEntry,
    device: &str,
    query_buckets: &mut HashMap<i64, QueryBucketAgg>,
    domain_buckets: &mut HashMap<(i64, String), DomainBucketAgg>,
    device_buckets: &mut HashMap<(i64, String), ClientBucketAgg>,
) {
    let ts = entry.timestamp.timestamp();
    let bucket = align_bucket(ts);
    let is_blocked = entry.status == QueryStatus::Blocked;

    let query_agg = query_buckets.entry(bucket).or_default();
    query_agg.total += 1;
    match &entry.status {
        QueryStatus::Blocked => query_agg.blocked += 1,
        QueryStatus::Cached => query_agg.cached += 1,
        QueryStatus::Upstream => query_agg.upstream += 1,
        QueryStatus::Allowed | QueryStatus::Routed => {}
    }

    let domain_agg = domain_buckets
        .entry((bucket, entry.domain.clone()))
        .or_default();
    domain_agg.total += 1;
    if is_blocked {
        domain_agg.blocked += 1;
    }

    let device_agg = device_buckets
        .entry((bucket, device.to_string()))
        .or_default();
    device_agg.total += 1;
    if is_blocked {
        device_agg.blocked += 1;
    }
    device_agg.last_seen = device_agg.last_seen.max(ts);
}

async fn top_domains_rollup_query(
    conn: &Connection,
    from_ts: i64,
    to_ts: i64,
    n: usize,
    blocked_only: bool,
) -> Result<Vec<(String, u64)>> {
    let from_bucket = align_bucket(from_ts);
    let to_bucket = align_bucket(to_ts);
    let value_col = if blocked_only { "blocked" } else { "total" };
    let sql = format!(
        // `domain ASC` is not decoration: without a tiebreak, two domains on
        // the same count come back in whatever order the scan produced, so the
        // top list reshuffles between identical requests and the dashboard
        // jitters. It also keeps this answer identical to the memory backend's.
        "SELECT domain, SUM({value_col}) as cnt FROM domain_buckets_10m
         WHERE bucket >= ?1 AND bucket <= ?2
         GROUP BY domain HAVING cnt > 0
         ORDER BY cnt DESC, domain ASC LIMIT ?3",
    );

    let rows = conn
        .call(move |c| {
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params![from_bucket, to_bucket, n as i64], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
        .map_err(FeriteError::TokioDatabase)?;
    Ok(rows)
}

#[cfg(test)]
impl SqliteStorage {
    /// Persist a batch with every recording surface enabled — what a test means
    /// unless it is specifically exercising the privacy switches.
    async fn write_batch_all(&self, entries: Vec<QueryEntry>) -> Result<()> {
        self.write_batch(entries, RecordScope::ALL).await
    }
}

mod migrations;

#[cfg(test)]
mod tests;
