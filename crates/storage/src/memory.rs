//! In-RAM query log — the `memory` storage backend.
//!
//! Same contract as [`crate::SqliteStorage`], with no file behind it: no
//! database, no write-ahead log, and no write per query. Everything it holds
//! is lost on restart, which is the deal someone makes when they pick it. It
//! exists for boxes whose storage you don't want to spend — an SD card, or a
//! read-only root — and for anyone who wants the Queries page to work without
//! what was looked up ever reaching a disk.
//!
//! It bounds *this* store, not the whole process: the compiled blocklist cache
//! still lands in the data directory. That is built from downloaded lists, not
//! from traffic, so it is written on a refresh rather than per query — and it
//! says nothing about who asked for what.
//!
//! It mirrors SQLite's rollup model rather than inventing its own: the same
//! 10-minute buckets keyed the same way, so the dashboard reads identically on
//! either backend and the two can't drift on what a "top domain" means.
//!
//! **Bounded by construction.** RAM is the resource being protected, so the
//! log is a ring with a hard entry cap; the oldest entry is dropped to make
//! room rather than growing without limit. `storage.log_max_mb` narrows that
//! cap further, and `storage.log_retention_days` trims by age as usual.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use ferrite_core::error::Result;
use ferrite_core::recording::RecordScope;
use ferrite_core::types::{QueryEntry, QueryStatus, TimeseriesBucket};

use crate::{ClientStats, LegacyConfigRows, QueryFilter, SizeTrim, Storage, SummaryStats};

/// Rollup bucket width, matching the SQLite backend exactly.
const ROLLUP_BUCKET_SECS: i64 = 600;

/// Rough live size of one retained entry: the struct, plus its heap strings
/// (domain, client IP, device token, upstream) and the allocator's share.
///
/// An estimate, deliberately. The alternative is walking every string on every
/// size check, which would cost more than the accuracy is worth — this only
/// has to be close enough to turn a megabyte budget into an entry count.
const APPROX_BYTES_PER_ENTRY: u64 = 256;

/// Entries kept when no size cap is configured.
///
/// Unlike a file, this cannot be allowed to grow until someone notices, so
/// there is always a ceiling. At roughly [`APPROX_BYTES_PER_ENTRY`] this is
/// about 32 MB — a few days for a household, and an amount a router-class box
/// can hold without the resolver feeling it.
pub const DEFAULT_MAX_ENTRIES: usize = 128_000;

#[derive(Default)]
struct QueryBucket {
    total: u64,
    blocked: u64,
    cached: u64,
    upstream: u64,
}

#[derive(Default)]
struct DomainBucket {
    total: u64,
    blocked: u64,
}

#[derive(Default)]
struct DeviceBucket {
    total: u64,
    blocked: u64,
    last_seen: i64,
}

struct Binding {
    mac: String,
    last_seen: i64,
}

#[derive(Default)]
struct Inner {
    /// Oldest first, so trimming by age or size pops from the front.
    queries: VecDeque<QueryEntry>,
    /// Rollups. `BTreeMap` rather than `HashMap`: every read is a bucket range
    /// scan, which an ordered map answers without touching the whole table.
    query_buckets: BTreeMap<i64, QueryBucket>,
    domain_buckets: BTreeMap<(i64, String), DomainBucket>,
    device_buckets: BTreeMap<(i64, String), DeviceBucket>,
    /// Learned device inventory: MAC → last known hostname.
    devices: BTreeMap<String, Option<String>>,
    /// Last-known IP → MAC binding.
    ip_bindings: BTreeMap<String, Binding>,
    /// Highest id ever stored, kept across trims so ids stay monotonic.
    max_id: u64,
    max_entries: usize,
}

impl Inner {
    /// Drop oldest entries until the ring fits its cap. Rollups are left
    /// alone: they are the aggregate history the dashboard reads, they cost a
    /// fraction of what the entries do, and age-based retention prunes them.
    fn enforce_ring_cap(&mut self) {
        while self.queries.len() > self.max_entries {
            self.queries.pop_front();
        }
    }

    fn drop_before(&mut self, cutoff_ts: i64) -> u64 {
        let before = self.queries.len();
        while let Some(front) = self.queries.front() {
            if front.timestamp.timestamp() < cutoff_ts {
                self.queries.pop_front();
            } else {
                break;
            }
        }
        let cutoff_bucket = align_bucket(cutoff_ts);
        self.query_buckets.retain(|b, _| *b >= cutoff_bucket);
        self.domain_buckets.retain(|(b, _), _| *b >= cutoff_bucket);
        self.device_buckets.retain(|(b, _), _| *b >= cutoff_bucket);
        (before - self.queries.len()) as u64
    }

    /// What this store is holding, in the same currency as the SQLite
    /// backend's `database_bytes`, so one size cap can drive both.
    fn approx_bytes(&self) -> u64 {
        self.queries.len() as u64 * APPROX_BYTES_PER_ENTRY
    }
}

/// The in-RAM storage backend. See the module docs.
pub struct MemoryStorage {
    inner: RwLock<Inner>,
}

impl MemoryStorage {
    /// Open the backend with a byte budget — `storage.log_max_mb` in bytes, or
    /// zero for [`DEFAULT_MAX_ENTRIES`]. Never actually unbounded: RAM is the
    /// resource this backend exists to protect.
    pub fn open(max_bytes: u64) -> Arc<Self> {
        let max_entries = if max_bytes == 0 {
            DEFAULT_MAX_ENTRIES
        } else {
            Self::entries_for_bytes(max_bytes)
        };
        tracing::info!(
            "in-memory storage opened — the query log never reaches disk, up to {} entries (~{} MB)",
            max_entries,
            (max_entries as u64 * APPROX_BYTES_PER_ENTRY) / 1_000_000
        );
        Arc::new(Self {
            inner: RwLock::new(Inner {
                max_entries,
                ..Default::default()
            }),
        })
    }

    /// Turn a byte budget into an entry count, never below one entry so a tiny
    /// cap degrades to "keep almost nothing" rather than "keep nothing".
    fn entries_for_bytes(max_bytes: u64) -> usize {
        ((max_bytes / APPROX_BYTES_PER_ENTRY).max(1) as usize).min(DEFAULT_MAX_ENTRIES)
    }
}

fn align_bucket(ts: i64) -> i64 {
    ts.div_euclid(ROLLUP_BUCKET_SECS) * ROLLUP_BUCKET_SECS
}

/// The device identity token an entry is filed under: its tagged `device`,
/// falling back to the client IP when untagged. Mirrors the SQLite backend.
fn device_token(entry: &QueryEntry) -> &str {
    if entry.device.is_empty() {
        &entry.client_ip
    } else {
        &entry.device
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn write_batch(&self, entries: Vec<QueryEntry>, scope: RecordScope) -> Result<()> {
        if entries.is_empty() || !scope.records_anything() {
            return Ok(());
        }
        let mut inner = self.inner.write();

        for entry in entries {
            inner.max_id = inner.max_id.max(entry.id);

            if scope.stats {
                let ts = entry.timestamp.timestamp();
                let bucket = align_bucket(ts);
                let blocked = entry.status == QueryStatus::Blocked;

                let q = inner.query_buckets.entry(bucket).or_default();
                q.total += 1;
                match entry.status {
                    QueryStatus::Blocked => q.blocked += 1,
                    QueryStatus::Cached => q.cached += 1,
                    QueryStatus::Upstream => q.upstream += 1,
                    QueryStatus::Allowed | QueryStatus::Routed => {}
                }

                let d = inner
                    .domain_buckets
                    .entry((bucket, entry.domain.clone()))
                    .or_default();
                d.total += 1;
                if blocked {
                    d.blocked += 1;
                }

                let device = device_token(&entry).to_string();
                let c = inner.device_buckets.entry((bucket, device)).or_default();
                c.total += 1;
                if blocked {
                    c.blocked += 1;
                }
                c.last_seen = c.last_seen.max(ts);
            }

            if scope.queries {
                // Tag before storing, so a read never has to re-derive it.
                let mut entry = entry;
                if entry.device.is_empty() {
                    entry.device = entry.client_ip.clone();
                }
                inner.queries.push_back(entry);
            }
        }

        inner.enforce_ring_cap();
        Ok(())
    }

    async fn max_query_id(&self) -> Result<u64> {
        Ok(self.inner.read().max_id)
    }

    async fn query_range(&self, filter: &QueryFilter) -> Result<Vec<QueryEntry>> {
        let inner = self.inner.read();

        // Lower-cased once, not per entry: SQLite's LIKE is case-insensitive
        // for ASCII, and the UI's domain box relies on that.
        let needle = filter.domain.as_ref().map(|d| d.to_lowercase());

        let mut matched: Vec<&QueryEntry> = inner
            .queries
            .iter()
            .filter(|e| {
                let ts = e.timestamp.timestamp();
                if filter.from_ts.is_some_and(|from| ts < from) {
                    return false;
                }
                if filter.to_ts.is_some_and(|to| ts > to) {
                    return false;
                }
                if let Some(needle) = &needle
                    && !e.domain.to_lowercase().contains(needle)
                {
                    return false;
                }
                // Identity filter: IP and device token are OR-combined, so
                // "everything from device X" spans every IP it ever held.
                if !filter.client_ips.is_empty() || !filter.devices.is_empty() {
                    let by_ip = filter.client_ips.contains(&e.client_ip);
                    let by_device = filter.devices.contains(&e.device);
                    if !by_ip && !by_device {
                        return false;
                    }
                }
                if let Some(status) = &filter.status
                    && e.status.as_str() != status
                {
                    return false;
                }
                // Keyset cursor: strictly older than (ts, id).
                if let (Some(before_ts), Some(before_id)) = (filter.before_ts, filter.before_id)
                    && !(ts < before_ts || (ts == before_ts && e.id < before_id))
                {
                    return false;
                }
                true
            })
            .collect();

        // Newest first, ids breaking ties — the order the UI paginates in.
        matched.sort_unstable_by(|a, b| {
            b.timestamp
                .timestamp()
                .cmp(&a.timestamp.timestamp())
                .then(b.id.cmp(&a.id))
        });

        // A cursor replaces the offset rather than stacking with it, exactly
        // as the SQL builder does.
        let offset = if filter.before_id.is_some() && filter.before_ts.is_some() {
            0
        } else {
            filter.offset.unwrap_or(0)
        };
        let limit = filter.limit.unwrap_or(100);

        Ok(matched
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn top_domains(&self, from_ts: i64, to_ts: i64, n: usize) -> Result<Vec<(String, u64)>> {
        Ok(self.top_domains_in(from_ts, to_ts, n, false))
    }

    async fn top_blocked_domains(
        &self,
        from_ts: i64,
        to_ts: i64,
        n: usize,
    ) -> Result<Vec<(String, u64)>> {
        Ok(self.top_domains_in(from_ts, to_ts, n, true))
    }

    async fn top_clients(&self, from_ts: i64, to_ts: i64, n: usize) -> Result<Vec<ClientStats>> {
        let inner = self.inner.read();
        let (from, to) = (align_bucket(from_ts), align_bucket(to_ts));

        let mut totals: HashMap<&str, ClientStats> = HashMap::new();
        for ((bucket, device), agg) in &inner.device_buckets {
            if *bucket < from || *bucket > to {
                continue;
            }
            let e = totals.entry(device).or_insert_with(|| ClientStats {
                device: device.clone(),
                total: 0,
                blocked: 0,
                last_seen: 0,
            });
            e.total += agg.total;
            e.blocked += agg.blocked;
            e.last_seen = e.last_seen.max(agg.last_seen);
        }

        let mut rows: Vec<ClientStats> = totals.into_values().collect();
        rows.sort_unstable_by(|a, b| b.total.cmp(&a.total).then(a.device.cmp(&b.device)));
        rows.truncate(n);
        Ok(rows)
    }

    async fn timeseries(&self, bucket_secs: u64) -> Result<Vec<TimeseriesBucket>> {
        let inner = self.inner.read();
        let width = (bucket_secs as i64).max(1);
        let since = chrono::Utc::now().timestamp() - 86_400;
        let floor = since.div_euclid(width) * width;

        let mut out: BTreeMap<i64, TimeseriesBucket> = BTreeMap::new();
        for (bucket, agg) in &inner.query_buckets {
            if *bucket < floor {
                continue;
            }
            let key = bucket.div_euclid(width) * width;
            let e = out.entry(key).or_insert_with(|| TimeseriesBucket {
                bucket: key as u64,
                total: 0,
                blocked: 0,
                cached: 0,
                upstream: 0,
            });
            e.total += agg.total;
            e.blocked += agg.blocked;
            e.cached += agg.cached;
            e.upstream += agg.upstream;
        }
        Ok(out.into_values().collect())
    }

    async fn client_stats(&self, device: &str) -> Result<Option<ClientStats>> {
        let inner = self.inner.read();
        let mut found = false;
        let mut stats = ClientStats {
            device: device.to_string(),
            total: 0,
            blocked: 0,
            last_seen: 0,
        };
        for ((_, key), agg) in &inner.device_buckets {
            if key != device {
                continue;
            }
            found = true;
            stats.total += agg.total;
            stats.blocked += agg.blocked;
            stats.last_seen = stats.last_seen.max(agg.last_seen);
        }
        Ok(found.then_some(stats))
    }

    async fn summary(&self, secs: u64) -> Result<(u64, u64)> {
        let now = chrono::Utc::now().timestamp();
        let counts = self
            .summary_counts(align_bucket(now - secs as i64), now)
            .await?;
        Ok((counts.total, counts.blocked))
    }

    async fn summary_counts(&self, from_ts: i64, to_ts: i64) -> Result<SummaryStats> {
        let inner = self.inner.read();
        let (from, to) = (align_bucket(from_ts), align_bucket(to_ts));
        let mut out = SummaryStats::default();
        for (bucket, agg) in inner.query_buckets.range(from..=to) {
            let _ = bucket;
            out.total += agg.total;
            out.blocked += agg.blocked;
            out.cached += agg.cached;
            out.upstream += agg.upstream;
        }
        Ok(out)
    }

    async fn delete_all_queries(&self) -> Result<()> {
        let mut inner = self.inner.write();
        inner.queries.clear();
        inner.query_buckets.clear();
        inner.domain_buckets.clear();
        inner.device_buckets.clear();
        Ok(())
    }

    async fn vacuum(&self) -> Result<()> {
        // Give the ring's spare capacity back after a clear; there is no file
        // to rebuild, so this is the whole of it.
        let mut inner = self.inner.write();
        inner.queries.shrink_to_fit();
        Ok(())
    }

    async fn delete_queries_older_than(&self, cutoff_ts: i64) -> Result<u64> {
        Ok(self.inner.write().drop_before(cutoff_ts))
    }

    async fn prepare_size_cap(&self) -> Result<bool> {
        // Dropping an entry frees it outright — nothing to convert, and no
        // one-time cost to warn about.
        Ok(false)
    }

    async fn enforce_size_cap(&self, max_bytes: u64) -> Result<SizeTrim> {
        let mut inner = self.inner.write();
        let bytes_before = inner.approx_bytes();
        let before = inner.queries.len();

        // A byte budget narrows the ring; it never widens it past the ceiling
        // the backend was opened with.
        inner.max_entries = Self::entries_for_bytes(max_bytes).min(inner.max_entries);
        inner.enforce_ring_cap();

        Ok(SizeTrim {
            rows_deleted: (before - inner.queries.len()) as u64,
            bytes_before,
            bytes_after: inner.approx_bytes(),
        })
    }

    async fn upsert_device(&self, mac: &str, hostname: Option<&str>) -> Result<()> {
        self.inner
            .write()
            .devices
            .insert(mac.to_string(), hostname.map(str::to_string));
        Ok(())
    }

    async fn upsert_ip_binding(&self, ip: &str, mac: &str) -> Result<()> {
        self.inner.write().ip_bindings.insert(
            ip.to_string(),
            Binding {
                mac: mac.to_string(),
                last_seen: chrono::Utc::now().timestamp(),
            },
        );
        Ok(())
    }

    async fn load_devices(&self) -> Result<Vec<(String, Option<String>)>> {
        Ok(self
            .inner
            .read()
            .devices
            .iter()
            .map(|(mac, host)| (mac.clone(), host.clone()))
            .collect())
    }

    async fn load_ip_bindings(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .inner
            .read()
            .ip_bindings
            .iter()
            .map(|(ip, b)| (ip.clone(), b.mac.clone()))
            .collect())
    }

    async fn delete_all_ip_bindings(&self) -> Result<()> {
        self.inner.write().ip_bindings.clear();
        Ok(())
    }

    async fn delete_all_devices(&self) -> Result<()> {
        self.inner.write().devices.clear();
        Ok(())
    }

    async fn touch_ip_bindings(&self, ips: &[String]) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp();
        let mut inner = self.inner.write();
        for ip in ips {
            if let Some(binding) = inner.ip_bindings.get_mut(ip) {
                binding.last_seen = now;
            }
        }
        Ok(())
    }

    async fn delete_ip_bindings_older_than(&self, cutoff_ts: i64) -> Result<Vec<String>> {
        let mut inner = self.inner.write();
        let stale: Vec<String> = inner
            .ip_bindings
            .iter()
            .filter(|(_, b)| b.last_seen < cutoff_ts)
            .map(|(ip, _)| ip.clone())
            .collect();
        for ip in &stale {
            inner.ip_bindings.remove(ip);
        }
        Ok(stale)
    }

    async fn database_bytes(&self) -> Result<u64> {
        Ok(self.inner.read().approx_bytes())
    }

    async fn load_legacy_config_rows(&self) -> Result<LegacyConfigRows> {
        // This backend never had the pre-v9 tables — it never had a file.
        Ok(LegacyConfigRows::default())
    }

    async fn drop_legacy_config_tables(&self) -> Result<()> {
        Ok(())
    }
}

impl MemoryStorage {
    fn top_domains_in(
        &self,
        from_ts: i64,
        to_ts: i64,
        n: usize,
        blocked_only: bool,
    ) -> Vec<(String, u64)> {
        let inner = self.inner.read();
        let (from, to) = (align_bucket(from_ts), align_bucket(to_ts));

        let mut totals: HashMap<&str, u64> = HashMap::new();
        for ((bucket, domain), agg) in &inner.domain_buckets {
            if *bucket < from || *bucket > to {
                continue;
            }
            let value = if blocked_only { agg.blocked } else { agg.total };
            *totals.entry(domain).or_default() += value;
        }

        // `HAVING cnt > 0`: a domain seen but never blocked is not a top
        // *blocked* domain, however many times it was resolved.
        let mut rows: Vec<(String, u64)> = totals
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .map(|(domain, count)| (domain.to_string(), count))
            .collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        rows.truncate(n);
        rows
    }
}
