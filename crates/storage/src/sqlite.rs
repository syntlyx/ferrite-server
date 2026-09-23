use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

use crate::schema::SCHEMA;
use crate::{ClientStats, LegacyConfigRows, QueryFilter, SizeTrim, Storage, SummaryStats};
use ferrite_core::error::{FeriteError, Result};
use ferrite_core::recording::RecordScope;
use ferrite_core::types::TimeseriesBucket;
use ferrite_core::types::{QueryEntry, QueryStatus};

const ROLLUP_BUCKET_SECS: i64 = 600;

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
                c.execute(
                    "INSERT INTO devices (mac, hostname, last_seen)
                     VALUES (?1, ?2, ?3)
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

    async fn load_devices(&self) -> Result<Vec<(String, Option<String>)>> {
        self.conn
            .call(|c| {
                let mut stmt = c.prepare("SELECT mac, hostname FROM devices")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
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

fn align_bucket(ts: i64) -> i64 {
    (ts / ROLLUP_BUCKET_SECS) * ROLLUP_BUCKET_SECS
}

/// Latest schema version. Bump when adding a migration step below.
const SCHEMA_VERSION: i64 = 9;

/// Apply versioned migrations on top of the baseline `SCHEMA`.
///
/// Versioning uses the built-in `PRAGMA user_version` (a free integer in the DB
/// header — no extra table). Each step runs in its own transaction together with
/// the version bump, so a crash mid-migration rolls the step back cleanly. Every
/// step is written to be **idempotent / guarded** so it is safe on a fresh DB, on
/// an old DB, and on a half-migrated DB (e.g. tables added out-of-band while
/// `user_version` was still 0).
fn run_migrations(c: &mut rusqlite::Connection) -> rusqlite::Result<()> {
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

#[cfg(test)]
mod tests {
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
                Ok::<i64, tokio_rusqlite::Error>(
                    c.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?,
                )
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
}
