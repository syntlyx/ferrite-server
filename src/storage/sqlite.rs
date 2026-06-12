use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

use crate::dns::types::{QueryEntry, QueryStatus};
use crate::error::{FeriteError, Result};
use crate::stats::timeseries::TimeseriesBucket;
use crate::storage::schema::SCHEMA;
use crate::storage::{ClientStats, QueryFilter, Storage, SummaryStats};

const ROLLUP_BUCKET_SECS: i64 = 600;

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

        // Apply schema.
        conn.call(|c| c.execute_batch(SCHEMA)).await?;

        // Migration: upgrade client_aliases to keyed-by-key+key_type schema.
        conn.call(|c| {
            // If old schema (single 'ip' primary key column), migrate.
            let has_key_col: bool = c
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('client_aliases') WHERE name='key'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap_or(0)
                > 0;

            if !has_key_col {
                // Old schema: ip TEXT PRIMARY KEY. Recreate with new schema preserving data.
                c.execute_batch(
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
        })
        .await?;

        conn.call(backfill_rollups_if_needed).await?;

        tracing::info!("SQLite storage opened at {}", path.display());
        Ok(Arc::new(Self { conn }))
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn write_batch(&self, entries: &[QueryEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let entries = entries.to_vec();
        self.conn
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                let mut query_buckets: HashMap<i64, QueryBucketAgg> = HashMap::new();
                let mut domain_buckets: HashMap<(i64, String), DomainBucketAgg> = HashMap::new();
                let mut client_buckets: HashMap<(i64, String), ClientBucketAgg> = HashMap::new();

                {
                    let mut stmt = tx.prepare_cached(
                        "INSERT INTO queries (timestamp, domain, query_type, client_ip, status, latency_ms, upstream, rcode)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    )?;
                    for e in &entries {
                        let ts = e.timestamp.timestamp();
                        stmt.execute(rusqlite::params![
                            ts,
                            e.domain,
                            e.query_type as i64,
                            e.client_ip,
                            e.status.as_str(),
                            e.latency_ms as i64,
                            e.upstream,
                            e.rcode as i64,
                        ])?;

                        collect_rollup_aggregates(
                            e,
                            &mut query_buckets,
                            &mut domain_buckets,
                            &mut client_buckets,
                        );
                    }
                }
                {
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
                {
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
                {
                    let mut stmt = tx.prepare_cached(
                        "INSERT INTO client_buckets_10m (bucket, client_ip, total, blocked, last_seen)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT(bucket, client_ip) DO UPDATE SET
                            total = client_buckets_10m.total + excluded.total,
                            blocked = client_buckets_10m.blocked + excluded.blocked,
                            last_seen = MAX(client_buckets_10m.last_seen, excluded.last_seen)",
                    )?;
                    for ((bucket, client_ip), agg) in &client_buckets {
                        stmt.execute(rusqlite::params![
                            bucket,
                            client_ip,
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

    async fn query_range(&self, filter: &QueryFilter) -> Result<Vec<QueryEntry>> {
        let filter = filter.clone();
        let rows = self.conn
            .call(move |c| {
                let mut sql = String::from(
                    "SELECT id, timestamp, domain, query_type, client_ip, status, latency_ms, upstream, rcode FROM queries WHERE 1=1",
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
                if !filter.client_ips.is_empty() {
                    let placeholders = filter.client_ips.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
                    sql.push_str(&format!(" AND client_ip IN ({})", placeholders));
                    for ip in &filter.client_ips {
                        params.push(Box::new(ip.clone()));
                    }
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
                    let status_str: String = row.get(5)?;
                    let latency_ms: i64 = row.get(6)?;
                    let upstream: Option<String> = row.get(7)?;
                    let rcode: i64 = row.get(8)?;

                    Ok((id, ts, domain, query_type, client_ip, status_str, latency_ms, upstream, rcode))
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
                    status_str,
                    latency_ms,
                    upstream,
                    rcode,
                )| {
                    let status = match status_str.as_str() {
                        "blocked" => QueryStatus::Blocked,
                        "cached" => QueryStatus::Cached,
                        "allowed" => QueryStatus::Allowed,
                        _ => QueryStatus::Upstream,
                    };
                    QueryEntry {
                        id: id as u64,
                        timestamp: chrono::DateTime::from_timestamp(ts, 0)
                            .unwrap_or_default()
                            .with_timezone(&chrono::Utc),
                        domain,
                        query_type: query_type as u16,
                        client_ip,
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
                    "SELECT client_ip,
                            SUM(total) as total,
                            SUM(blocked) as blocked,
                            MAX(last_seen) as last_seen
                     FROM client_buckets_10m
                     WHERE bucket >= ?1 AND bucket <= ?2
                     GROUP BY client_ip
                     ORDER BY total DESC LIMIT ?3",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![from_bucket, to_bucket, n as i64], |row| {
                        Ok(ClientStats {
                            client_ip: row.get(0)?,
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

    async fn client_stats(&self, client_ip: &str) -> Result<Option<ClientStats>> {
        let ip = client_ip.to_string();
        let result = self
            .conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT client_ip,
                            SUM(total) as total,
                            SUM(blocked) as blocked,
                            MAX(last_seen) as last_seen
                     FROM client_buckets_10m WHERE client_ip = ?1 GROUP BY client_ip",
                )?;
                let row = stmt
                    .query_row(rusqlite::params![ip], |row| {
                        Ok(ClientStats {
                            client_ip: row.get(0)?,
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
                     DELETE FROM client_buckets_10m;",
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn delete_queries_older_than(&self, cutoff_ts: i64) -> Result<u64> {
        self.conn
            .call(move |c| {
                let cutoff_bucket = align_bucket(cutoff_ts);
                let tx = c.unchecked_transaction()?;
                let n = tx.execute(
                    "DELETE FROM queries WHERE timestamp < ?1",
                    rusqlite::params![cutoff_ts],
                )?;
                tx.execute(
                    "DELETE FROM query_buckets_10m WHERE bucket < ?1",
                    rusqlite::params![cutoff_bucket],
                )?;
                tx.execute(
                    "DELETE FROM domain_buckets_10m WHERE bucket < ?1",
                    rusqlite::params![cutoff_bucket],
                )?;
                tx.execute(
                    "DELETE FROM client_buckets_10m WHERE bucket < ?1",
                    rusqlite::params![cutoff_bucket],
                )?;
                tx.commit()?;
                Ok(n as u64)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn add_custom_entry(&self, domain: &str, entry_type: &str) -> Result<()> {
        let domain = domain.to_string();
        let entry_type = entry_type.to_string();
        let now = chrono::Utc::now().timestamp();
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT INTO custom_entries (domain, entry_type, created_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(domain) DO UPDATE SET entry_type = excluded.entry_type",
                    rusqlite::params![domain, entry_type, now],
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn remove_custom_entry(&self, domain: &str) -> Result<()> {
        let domain = domain.to_string();
        self.conn
            .call(move |c| {
                c.execute(
                    "DELETE FROM custom_entries WHERE domain = ?1",
                    rusqlite::params![domain],
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn load_custom_entries(&self) -> Result<Vec<(String, String)>> {
        self.conn
            .call(|c| {
                let mut stmt = c.prepare(
                    "SELECT domain, entry_type FROM custom_entries ORDER BY created_at ASC",
                )?;
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

    async fn add_client_alias(&self, key: &str, key_type: &str, name: &str) -> Result<()> {
        let key = key.to_string();
        let key_type = key_type.to_string();
        let name = name.to_string();
        let now = chrono::Utc::now().timestamp();
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT INTO client_aliases (key, key_type, name, created_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(key, key_type) DO UPDATE SET name = excluded.name",
                    rusqlite::params![key, key_type, name, now],
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn remove_client_alias(&self, key: &str, key_type: &str) -> Result<()> {
        let key = key.to_string();
        let key_type = key_type.to_string();
        self.conn
            .call(move |c| {
                c.execute(
                    "DELETE FROM client_aliases WHERE key = ?1 AND key_type = ?2",
                    rusqlite::params![key, key_type],
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn load_client_aliases(&self) -> Result<Vec<(String, String, String)>> {
        self.conn
            .call(|c| {
                let mut stmt = c.prepare(
                    "SELECT key, key_type, name FROM client_aliases ORDER BY created_at ASC",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn upsert_custom_record(
        &self,
        domain: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) -> Result<()> {
        let domain = domain.to_string();
        let record_type = record_type.to_string();
        let value = value.to_string();
        let now = chrono::Utc::now().timestamp();
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT INTO custom_dns_records (domain, record_type, value, ttl, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(domain, record_type) DO UPDATE
                         SET value = excluded.value, ttl = excluded.ttl",
                    rusqlite::params![domain, record_type, value, ttl as i64, now],
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn delete_custom_record(&self, domain: &str) -> Result<()> {
        let domain = domain.to_string();
        self.conn
            .call(move |c| {
                c.execute(
                    "DELETE FROM custom_dns_records WHERE domain = ?1",
                    rusqlite::params![domain],
                )?;
                Ok(())
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }

    async fn load_custom_records(&self) -> Result<Vec<crate::config::CustomRecordConfig>> {
        self.conn
            .call(|c| {
                let mut stmt = c.prepare(
                    "SELECT domain, record_type, value, ttl FROM custom_dns_records
                     ORDER BY created_at ASC",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(crate::config::CustomRecordConfig {
                            domain: row.get(0)?,
                            record_type: row.get(1)?,
                            value: row.get(2)?,
                            ttl: row.get::<_, i64>(3)? as u32,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .map_err(FeriteError::TokioDatabase)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn collect_rollup_aggregates(
    entry: &QueryEntry,
    query_buckets: &mut HashMap<i64, QueryBucketAgg>,
    domain_buckets: &mut HashMap<(i64, String), DomainBucketAgg>,
    client_buckets: &mut HashMap<(i64, String), ClientBucketAgg>,
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
        QueryStatus::Allowed => {}
    }

    let domain_agg = domain_buckets
        .entry((bucket, entry.domain.clone()))
        .or_default();
    domain_agg.total += 1;
    if is_blocked {
        domain_agg.blocked += 1;
    }

    let client_agg = client_buckets
        .entry((bucket, entry.client_ip.clone()))
        .or_default();
    client_agg.total += 1;
    if is_blocked {
        client_agg.blocked += 1;
    }
    client_agg.last_seen = client_agg.last_seen.max(ts);
}

fn align_bucket(ts: i64) -> i64 {
    (ts / ROLLUP_BUCKET_SECS) * ROLLUP_BUCKET_SECS
}

fn backfill_rollups_if_needed(c: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let query_count: i64 = c.query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))?;
    if query_count == 0 {
        return Ok(());
    }

    let rollup_count: i64 = c.query_row("SELECT COUNT(*) FROM query_buckets_10m", [], |row| {
        row.get(0)
    })?;
    if rollup_count > 0 {
        return Ok(());
    }

    tracing::info!(
        "backfilling SQLite query rollups from {} existing query rows",
        query_count
    );
    let tx = c.unchecked_transaction()?;
    let sql = format!(
        r#"
        DELETE FROM query_buckets_10m;
        DELETE FROM domain_buckets_10m;
        DELETE FROM client_buckets_10m;

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

        INSERT INTO client_buckets_10m (bucket, client_ip, total, blocked, last_seen)
        SELECT (timestamp / {bucket_secs}) * {bucket_secs} as bucket,
               client_ip,
               COUNT(*) as total,
               SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) as blocked,
               MAX(timestamp) as last_seen
        FROM queries
        GROUP BY bucket, client_ip;
        "#,
        bucket_secs = ROLLUP_BUCKET_SECS
    );
    tx.execute_batch(&sql)?;
    tx.commit()?;
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
        "SELECT domain, SUM({value_col}) as cnt FROM domain_buckets_10m
         WHERE bucket >= ?1 AND bucket <= ?2
         GROUP BY domain HAVING cnt > 0
         ORDER BY cnt DESC LIMIT ?3",
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
        QueryEntry {
            id: 0,
            timestamp: chrono::DateTime::from_timestamp(ts, 0).unwrap(),
            domain: domain.to_string(),
            query_type: 1,
            client_ip: client_ip.to_string(),
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

        storage.write_batch(&entries).await.unwrap();

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

        let clients = storage.top_clients(bucket, bucket + 599, 10).await.unwrap();
        assert_eq!(clients[0].client_ip, "192.168.1.11");
        assert_eq!(clients[0].total, 2);
        assert_eq!(clients[0].blocked, 2);

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

        storage.write_batch(&entries).await.unwrap();

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

    #[tokio::test]
    async fn custom_entries_round_trip_and_can_be_removed() {
        let storage = SqliteStorage::open(&temp_db_path("ferrite-custom-entries"))
            .await
            .unwrap();

        storage
            .add_custom_entry("ads.test", "blacklist")
            .await
            .unwrap();
        storage
            .add_custom_entry("safe.test", "whitelist")
            .await
            .unwrap();
        storage
            .add_custom_entry("ads.test", "whitelist")
            .await
            .unwrap();

        let mut entries = storage.load_custom_entries().await.unwrap();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                ("ads.test".to_string(), "whitelist".to_string()),
                ("safe.test".to_string(), "whitelist".to_string()),
            ]
        );

        storage.remove_custom_entry("safe.test").await.unwrap();
        assert_eq!(
            storage.load_custom_entries().await.unwrap(),
            vec![("ads.test".to_string(), "whitelist".to_string())]
        );
    }

    #[tokio::test]
    async fn client_aliases_round_trip_ip_and_mac_keys() {
        let storage = SqliteStorage::open(&temp_db_path("ferrite-client-aliases"))
            .await
            .unwrap();

        storage
            .add_client_alias("192.168.1.10", "ip", "Laptop")
            .await
            .unwrap();
        storage
            .add_client_alias("aa:bb:cc:dd:ee:ff", "mac", "Phone")
            .await
            .unwrap();
        storage
            .add_client_alias("192.168.1.10", "ip", "Workstation")
            .await
            .unwrap();

        let mut aliases = storage.load_client_aliases().await.unwrap();
        aliases.sort();
        assert_eq!(
            aliases,
            vec![
                (
                    "192.168.1.10".to_string(),
                    "ip".to_string(),
                    "Workstation".to_string()
                ),
                (
                    "aa:bb:cc:dd:ee:ff".to_string(),
                    "mac".to_string(),
                    "Phone".to_string()
                ),
            ]
        );

        storage
            .remove_client_alias("aa:bb:cc:dd:ee:ff", "mac")
            .await
            .unwrap();
        assert_eq!(
            storage.load_client_aliases().await.unwrap(),
            vec![(
                "192.168.1.10".to_string(),
                "ip".to_string(),
                "Workstation".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn custom_dns_records_round_trip_update_and_delete_by_domain() {
        let storage = SqliteStorage::open(&temp_db_path("ferrite-custom-records"))
            .await
            .unwrap();

        storage
            .upsert_custom_record("router.lan", "A", "192.168.1.1", 60)
            .await
            .unwrap();
        storage
            .upsert_custom_record("router.lan", "A", "192.168.1.2", 120)
            .await
            .unwrap();
        storage
            .upsert_custom_record("nas.lan", "CNAME", "router.lan.", 300)
            .await
            .unwrap();

        let mut records = storage.load_custom_records().await.unwrap();
        records.sort_by(|a, b| {
            a.domain
                .cmp(&b.domain)
                .then(a.record_type.cmp(&b.record_type))
        });
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].domain, "nas.lan");
        assert_eq!(records[0].record_type, "CNAME");
        assert_eq!(records[1].domain, "router.lan");
        assert_eq!(records[1].value, "192.168.1.2");
        assert_eq!(records[1].ttl, 120);

        storage.delete_custom_record("router.lan").await.unwrap();
        let records = storage.load_custom_records().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].domain, "nas.lan");
    }

    #[tokio::test]
    async fn delete_all_queries_clears_history_and_rollups() {
        let storage = SqliteStorage::open(&temp_db_path("ferrite-delete-all"))
            .await
            .unwrap();
        let bucket = align_bucket(chrono::Utc::now().timestamp());
        storage
            .write_batch(&[
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

        assert!(storage
            .query_range(&QueryFilter::default())
            .await
            .unwrap()
            .is_empty());
        assert_eq!(storage.summary(3600).await.unwrap(), (0, 0));
        assert!(storage
            .top_domains(bucket, bucket + 599, 10)
            .await
            .unwrap()
            .is_empty());
        assert!(storage
            .top_clients(bucket, bucket + 599, 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn retention_delete_removes_old_queries_and_rollups_only() {
        let storage = SqliteStorage::open(&temp_db_path("ferrite-retention"))
            .await
            .unwrap();
        let now_bucket = align_bucket(chrono::Utc::now().timestamp());
        let old_bucket = now_bucket - 10 * 86400;
        storage
            .write_batch(&[
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
        assert!(storage
            .top_blocked_domains(old_bucket, old_bucket + 599, 10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            storage
                .top_domains(now_bucket, now_bucket + 599, 10)
                .await
                .unwrap(),
            vec![("new.test".to_string(), 1)]
        );
    }
}
