use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use fred::prelude::*;

use crate::config::CustomRecordConfig;
use crate::dns::types::{QueryEntry, QueryStatus};
use crate::error::{FeriteError, Result};
use crate::stats::timeseries::TimeseriesBucket;
use crate::storage::{ClientStats, QueryFilter, Storage, SummaryStats};

// ── Error helper ─────────────────────────────────────────────────────────────

fn re(e: fred::error::Error) -> FeriteError {
    FeriteError::Storage(e.to_string())
}

fn alias_field(key: &str, key_type: &str) -> String {
    format!("{}:{}", key, key_type)
}

fn parse_alias_field(field: &str) -> Option<(String, String)> {
    let (key, key_type) = field.rsplit_once(':')?;
    Some((key.to_string(), key_type.to_string()))
}

// ── Key schema ────────────────────────────────────────────────────────────────
//
//  {prefix}:log                  LIST  — JSON query entries, newest first (LPUSH)
//  {prefix}:top:{day}            ZSET  — domain  → total query count
//  {prefix}:blocked:{day}        ZSET  — domain  → blocked query count
//  {prefix}:clients:{day}        ZSET  — client_ip → total query count
//  {prefix}:clients_bl:{day}     ZSET  — client_ip → blocked query count
//  {prefix}:client_meta:{ip}     HASH  — last_seen (unix ts)
//  {prefix}:ts:{bucket}          HASH  — total, blocked, cached, upstream (10-min buckets)
//  {prefix}:custom_entries       HASH  — domain → "whitelist"|"blacklist"
//  {prefix}:custom_records       HASH  — domain → JSON {type,value,ttl}
//  {prefix}:aliases              HASH  — "{key}:{key_type}" → name

const LOG_MAXLEN: i64 = 50_000;
const DAY_TTL: i64 = 3 * 86_400; // keep 3 days of ZSET data
const TS_TTL: i64 = 26 * 3_600; // keep 26 h of timeseries keys

// write_batch always bins into 10-min buckets; timeseries(bucket_secs) reads
// whatever granularity is in Redis (it just won't find keys at other strides).
const WRITE_BUCKET_SECS: u64 = 600;

// ── Storage struct ────────────────────────────────────────────────────────────

pub struct RedisStorage {
    pool: Pool,
    prefix: String,
}

impl RedisStorage {
    pub async fn connect(url: &str, prefix: &str) -> Result<Arc<Self>> {
        let config = Config::from_url(url).map_err(re)?;
        let pool = Builder::from_config(config).build_pool(4).map_err(re)?;
        pool.init().await.map_err(re)?;
        tracing::info!("Redis storage connected (prefix: {})", prefix);
        Ok(Arc::new(Self {
            pool,
            prefix: prefix.to_string(),
        }))
    }

    fn k(&self, s: &str) -> String {
        format!("{}:{}", self.prefix, s)
    }

    fn day_range(from_ts: i64, to_ts: i64) -> Vec<i64> {
        if from_ts > to_ts {
            return Vec::new();
        }
        let from_ts = from_ts.max(to_ts.saturating_sub(DAY_TTL));
        let mut days = vec![];
        let mut day = (from_ts / 86_400) * 86_400;
        let end = (to_ts / 86_400) * 86_400;
        while day <= end {
            days.push(day);
            day += 86_400;
        }
        days
    }

    /// Merge multiple ZSETs (member→score) in memory and return top `n` descending.
    async fn merge_zsets_top(&self, keys: &[String], n: usize) -> Result<Vec<(String, u64)>> {
        let mut counts: HashMap<String, u64> = HashMap::new();
        for key in keys {
            let pairs: Vec<(String, f64)> = self
                .pool
                .zrangebyscore(key.as_str(), "-inf", "+inf", true, None)
                .await
                .map_err(re)?;
            for (member, score) in pairs {
                *counts.entry(member).or_default() += score as u64;
            }
        }
        let mut sorted: Vec<(String, u64)> = counts.into_iter().collect();
        sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        sorted.truncate(n);
        Ok(sorted)
    }
}

// ── Storage impl ──────────────────────────────────────────────────────────────

#[async_trait]
impl Storage for RedisStorage {
    async fn write_batch(&self, entries: &[QueryEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let log_key = self.k("log");
        // One connection, one pipeline — all commands sent in a single round-trip.
        let pipeline = self.pool.next().pipeline();

        for entry in entries {
            let ts = entry.timestamp.timestamp();
            let day = (ts / 86_400) * 86_400;
            let bucket = (ts as u64 / WRITE_BUCKET_SECS) * WRITE_BUCKET_SECS;
            let is_blocked = entry.status == QueryStatus::Blocked;
            let json = serde_json::to_string(entry).map_err(FeriteError::Json)?;

            // Append to log (ltrim happens once after the loop).
            let _: () = pipeline.lpush(&log_key, json).await.map_err(re)?;

            // Daily domain ZSET.
            let top_key = self.k(&format!("top:{}", day));
            let _: () = pipeline
                .zincrby(&top_key, 1.0_f64, entry.domain.as_str())
                .await
                .map_err(re)?;
            let _: () = pipeline.expire(&top_key, DAY_TTL, None).await.map_err(re)?;

            // Daily client ZSET.
            let clients_key = self.k(&format!("clients:{}", day));
            let _: () = pipeline
                .zincrby(&clients_key, 1.0_f64, entry.client_ip.as_str())
                .await
                .map_err(re)?;
            let _: () = pipeline
                .expire(&clients_key, DAY_TTL, None)
                .await
                .map_err(re)?;

            // Per-client last-seen.
            let meta_key = self.k(&format!("client_meta:{}", entry.client_ip));
            let _: () = pipeline
                .hset(&meta_key, vec![("last_seen", ts.to_string())])
                .await
                .map_err(re)?;

            // Timeseries bucket (10-min granularity).
            let ts_key = self.k(&format!("ts:{}", bucket));
            let _: () = pipeline.hincrby(&ts_key, "total", 1i64).await.map_err(re)?;
            let _: () = pipeline.expire(&ts_key, TS_TTL, None).await.map_err(re)?;
            match entry.status {
                QueryStatus::Cached => {
                    let _: () = pipeline
                        .hincrby(&ts_key, "cached", 1i64)
                        .await
                        .map_err(re)?;
                }
                QueryStatus::Upstream => {
                    let _: () = pipeline
                        .hincrby(&ts_key, "upstream", 1i64)
                        .await
                        .map_err(re)?;
                }
                _ => {}
            }

            if is_blocked {
                let blocked_key = self.k(&format!("blocked:{}", day));
                let _: () = pipeline
                    .zincrby(&blocked_key, 1.0_f64, entry.domain.as_str())
                    .await
                    .map_err(re)?;
                let _: () = pipeline
                    .expire(&blocked_key, DAY_TTL, None)
                    .await
                    .map_err(re)?;

                let cb_key = self.k(&format!("clients_bl:{}", day));
                let _: () = pipeline
                    .zincrby(&cb_key, 1.0_f64, entry.client_ip.as_str())
                    .await
                    .map_err(re)?;
                let _: () = pipeline.expire(&cb_key, DAY_TTL, None).await.map_err(re)?;

                let _: () = pipeline
                    .hincrby(&ts_key, "blocked", 1i64)
                    .await
                    .map_err(re)?;
            }
        }

        // Trim the log once after all pushes.
        let _: () = pipeline
            .ltrim(&log_key, 0, LOG_MAXLEN - 1)
            .await
            .map_err(re)?;

        // Flush the entire pipeline in one round-trip.
        pipeline.last::<()>().await.map_err(re)?;
        Ok(())
    }

    async fn query_range(&self, filter: &QueryFilter) -> Result<Vec<QueryEntry>> {
        let raw: Vec<String> = self
            .pool
            .lrange(self.k("log"), 0, LOG_MAXLEN - 1)
            .await
            .map_err(re)?;

        let mut entries: Vec<QueryEntry> = raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();

        if let Some(from) = filter.from_ts {
            entries.retain(|e| e.timestamp.timestamp() >= from);
        }
        if let Some(to) = filter.to_ts {
            entries.retain(|e| e.timestamp.timestamp() <= to);
        }
        if let Some(ref domain) = filter.domain {
            let d = domain.to_lowercase();
            entries.retain(|e| e.domain.contains(&d));
        }
        if !filter.client_ips.is_empty() {
            entries.retain(|e| filter.client_ips.contains(&e.client_ip));
        }
        if let Some(ref status) = filter.status {
            entries.retain(|e| e.status.as_str() == status.as_str());
        }

        let cursor = filter.before_ts.zip(filter.before_id);
        if let Some((before_ts, before_id)) = cursor {
            entries.retain(|e| {
                let ts = e.timestamp.timestamp();
                ts < before_ts || (ts == before_ts && e.id < before_id)
            });
        }

        let offset = if cursor.is_some() {
            0
        } else {
            filter.offset.unwrap_or(0)
        };
        let limit = filter.limit.unwrap_or(100);
        Ok(entries.into_iter().skip(offset).take(limit).collect())
    }

    async fn top_domains(&self, from_ts: i64, to_ts: i64, n: usize) -> Result<Vec<(String, u64)>> {
        let keys: Vec<String> = Self::day_range(from_ts, to_ts)
            .into_iter()
            .map(|d| self.k(&format!("top:{}", d)))
            .collect();
        self.merge_zsets_top(&keys, n).await
    }

    async fn top_blocked_domains(
        &self,
        from_ts: i64,
        to_ts: i64,
        n: usize,
    ) -> Result<Vec<(String, u64)>> {
        let keys: Vec<String> = Self::day_range(from_ts, to_ts)
            .into_iter()
            .map(|d| self.k(&format!("blocked:{}", d)))
            .collect();
        self.merge_zsets_top(&keys, n).await
    }

    async fn top_clients(&self, from_ts: i64, to_ts: i64, n: usize) -> Result<Vec<ClientStats>> {
        let days = Self::day_range(from_ts, to_ts);

        let total_keys: Vec<String> = days
            .iter()
            .map(|d| self.k(&format!("clients:{}", d)))
            .collect();
        let top = self.merge_zsets_top(&total_keys, n).await?;

        let mut result = Vec::with_capacity(top.len());
        for (ip, total) in top {
            let mut blocked = 0u64;
            for day in &days {
                let score: Option<f64> = self
                    .pool
                    .zscore(self.k(&format!("clients_bl:{}", day)), ip.as_str())
                    .await
                    .map_err(re)?;
                blocked += score.unwrap_or(0.0) as u64;
            }
            let last_seen: Option<String> = self
                .pool
                .hget(self.k(&format!("client_meta:{}", ip)), "last_seen")
                .await
                .map_err(re)?;
            let last_seen = last_seen.and_then(|s| s.parse().ok()).unwrap_or(0i64);
            result.push(ClientStats {
                client_ip: ip,
                total,
                blocked,
                last_seen,
            });
        }
        Ok(result)
    }

    async fn timeseries(&self, bucket_secs: u64) -> Result<Vec<TimeseriesBucket>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let start = ((now.saturating_sub(86_400)) / bucket_secs) * bucket_secs;
        let end = (now / bucket_secs) * bucket_secs;

        let mut result = vec![];
        let mut b = start;
        while b <= end {
            let vals: HashMap<String, String> = self
                .pool
                .hgetall(self.k(&format!("ts:{}", b)))
                .await
                .map_err(re)?;
            if !vals.is_empty() {
                let total = vals.get("total").and_then(|s| s.parse().ok()).unwrap_or(0);
                let blocked = vals
                    .get("blocked")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                result.push(TimeseriesBucket {
                    bucket: b,
                    total,
                    blocked,
                    cached: vals.get("cached").and_then(|s| s.parse().ok()).unwrap_or(0),
                    upstream: vals
                        .get("upstream")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                });
            }
            b += bucket_secs;
        }
        Ok(result)
    }

    async fn client_stats(&self, client_ip: &str) -> Result<Option<ClientStats>> {
        let now_ts = chrono::Utc::now().timestamp();
        let days = Self::day_range(now_ts - 30 * 86_400, now_ts);

        let total_keys: Vec<String> = days
            .iter()
            .map(|d| self.k(&format!("clients:{}", d)))
            .collect();
        let all = self.merge_zsets_top(&total_keys, 100_000).await?;

        let total = match all.into_iter().find(|(ip, _)| ip == client_ip) {
            Some((_, t)) => t,
            None => return Ok(None),
        };

        let mut blocked = 0u64;
        for day in &days {
            let score: Option<f64> = self
                .pool
                .zscore(self.k(&format!("clients_bl:{}", day)), client_ip)
                .await
                .map_err(re)?;
            blocked += score.unwrap_or(0.0) as u64;
        }

        let last_seen: Option<String> = self
            .pool
            .hget(self.k(&format!("client_meta:{}", client_ip)), "last_seen")
            .await
            .map_err(re)?;
        let last_seen = last_seen.and_then(|s| s.parse().ok()).unwrap_or(0i64);

        Ok(Some(ClientStats {
            client_ip: client_ip.to_string(),
            total,
            blocked,
            last_seen,
        }))
    }

    async fn summary(&self, secs: u64) -> Result<(u64, u64)> {
        let from = (chrono::Utc::now().timestamp() as u64).saturating_sub(secs) as i64;
        let counts = self
            .summary_counts(from, chrono::Utc::now().timestamp())
            .await?;
        Ok((counts.total, counts.blocked))
    }

    async fn summary_counts(&self, from_ts: i64, to_ts: i64) -> Result<SummaryStats> {
        let raw: Vec<String> = self
            .pool
            .lrange(self.k("log"), 0, LOG_MAXLEN - 1)
            .await
            .map_err(re)?;

        let mut counts = SummaryStats::default();
        for json in raw {
            if let Ok(entry) = serde_json::from_str::<QueryEntry>(&json) {
                let ts = entry.timestamp.timestamp();
                if ts >= from_ts && ts <= to_ts {
                    counts.total += 1;
                    match entry.status {
                        QueryStatus::Blocked => counts.blocked += 1,
                        QueryStatus::Cached => counts.cached += 1,
                        QueryStatus::Upstream => counts.upstream += 1,
                        QueryStatus::Allowed => {}
                    }
                }
            }
        }
        Ok(counts)
    }

    async fn delete_all_queries(&self) -> Result<()> {
        let _: i64 = self.pool.del::<i64, _>(self.k("log")).await.map_err(re)?;
        Ok(())
    }

    async fn delete_queries_older_than(&self, cutoff_ts: i64) -> Result<u64> {
        // The Redis log LIST is already bounded by LOG_MAXLEN (LTRIM on every write),
        // and per-day ZSETs expire automatically via TTL. Time-based filtering would
        // require an O(n) scan of the JSON entries; for the home-server use case
        // the existing caps are sufficient, so we skip explicit retention here.
        let _ = cutoff_ts;
        Ok(0)
    }

    // ── Custom whitelist / blacklist ─────────────────────────────────────────

    async fn add_custom_entry(&self, domain: &str, entry_type: &str) -> Result<()> {
        let _: i64 = self
            .pool
            .hset(
                self.k("custom_entries"),
                vec![(domain.to_string(), entry_type.to_string())],
            )
            .await
            .map_err(re)?;
        Ok(())
    }

    async fn remove_custom_entry(&self, domain: &str) -> Result<()> {
        let _: i64 = self
            .pool
            .hdel(self.k("custom_entries"), domain)
            .await
            .map_err(re)?;
        Ok(())
    }

    async fn load_custom_entries(&self) -> Result<Vec<(String, String)>> {
        let map: HashMap<String, String> = self
            .pool
            .hgetall(self.k("custom_entries"))
            .await
            .map_err(re)?;
        Ok(map.into_iter().collect())
    }

    // ── Client aliases ────────────────────────────────────────────────────────

    async fn add_client_alias(&self, key: &str, key_type: &str, name: &str) -> Result<()> {
        let field = alias_field(key, key_type);
        let _: i64 = self
            .pool
            .hset(self.k("aliases"), vec![(field, name.to_string())])
            .await
            .map_err(re)?;
        Ok(())
    }

    async fn remove_client_alias(&self, key: &str, key_type: &str) -> Result<()> {
        let field = alias_field(key, key_type);
        let _: i64 = self.pool.hdel(self.k("aliases"), field).await.map_err(re)?;
        Ok(())
    }

    async fn load_client_aliases(&self) -> Result<Vec<(String, String, String)>> {
        let map: HashMap<String, String> =
            self.pool.hgetall(self.k("aliases")).await.map_err(re)?;
        Ok(map
            .into_iter()
            .filter_map(|(field, name)| {
                let (key, key_type) = parse_alias_field(&field)?;
                Some((key, key_type, name))
            })
            .collect())
    }

    // ── Custom DNS records ────────────────────────────────────────────────────

    async fn upsert_custom_record(
        &self,
        domain: &str,
        record_type: &str,
        value: &str,
        ttl: u32,
    ) -> Result<()> {
        let json = serde_json::to_string(&serde_json::json!({
            "type": record_type,
            "value": value,
            "ttl": ttl,
        }))
        .map_err(FeriteError::Json)?;
        let _: i64 = self
            .pool
            .hset(self.k("custom_records"), vec![(domain.to_string(), json)])
            .await
            .map_err(re)?;
        Ok(())
    }

    async fn delete_custom_record(&self, domain: &str) -> Result<()> {
        let _: i64 = self
            .pool
            .hdel(self.k("custom_records"), domain)
            .await
            .map_err(re)?;
        Ok(())
    }

    async fn load_custom_records(&self) -> Result<Vec<CustomRecordConfig>> {
        let map: HashMap<String, String> = self
            .pool
            .hgetall(self.k("custom_records"))
            .await
            .map_err(re)?;
        Ok(map
            .into_iter()
            .filter_map(|(domain, json)| {
                let v: serde_json::Value = serde_json::from_str(&json).ok()?;
                Some(CustomRecordConfig {
                    domain,
                    record_type: v["type"].as_str().unwrap_or("A").to_string(),
                    value: v["value"].as_str().unwrap_or("").to_string(),
                    ttl: v["ttl"].as_u64().unwrap_or(300) as u32,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_fields_round_trip_ipv4_ipv6_and_mac_keys() {
        for (key, key_type) in [
            ("192.168.1.10", "ip"),
            ("fe80::a0ce:c8ff:fe12:3456", "ip"),
            ("aa:bb:cc:dd:ee:ff", "mac"),
        ] {
            let field = alias_field(key, key_type);
            assert_eq!(
                parse_alias_field(&field),
                Some((key.to_string(), key_type.to_string()))
            );
        }
    }
}
