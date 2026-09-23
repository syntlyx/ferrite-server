/// SQL schema applied on first startup (or after a migration).
///
/// Everything here is data ferrite *observed*: the query log, its rollups, and
/// the device inventory learned from PTR/mDNS and the neighbour tables. What an
/// operator *authored* — settings, subscriptions, manual block/allow entries,
/// custom DNS records, client aliases — lives in `config.toml` and only there,
/// so backing up one file backs up the configuration and the database stays
/// disposable. Five tables here used to hold authored state; they are handed
/// over to the config file once and then dropped — see
/// `Storage::load_legacy_config_rows` / `drop_legacy_config_tables`.
pub const SCHEMA: &str = r#"
-- Must come before the first table: on an existing database this is a no-op,
-- and switching it on later costs a full VACUUM (which `prepare_size_cap`
-- does, once, only for a database that opts into `storage.log_max_mb`).
-- Without it a delete only moves pages to the freelist and the file never
-- shrinks, so a size cap could not be met.
PRAGMA auto_vacuum=INCREMENTAL;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
-- Truncate the write-ahead log back down after each checkpoint instead of
-- leaving it at its high-water mark. It sits next to the database and is not
-- counted in its size, which matters most when the pair lives in RAM.
PRAGMA journal_size_limit=8388608;

-- ---------------------------------------------------------------
-- DNS query log
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,   -- Unix epoch seconds (UTC)
    domain      TEXT    NOT NULL,
    query_type  INTEGER NOT NULL,   -- u16, full RFC DNS QTYPE (A=1, AAAA=28, CAA=257, …)
    client_ip   TEXT    NOT NULL,
    status      TEXT    NOT NULL,   -- 'upstream' | 'cached' | 'blocked' | 'allowed' | 'routed'
    latency_ms  INTEGER NOT NULL DEFAULT 0,
    upstream    TEXT,               -- NULL if not forwarded
    rcode       INTEGER NOT NULL DEFAULT 0
);

-- Every row here is one DNS query, so each index is maintained on the hot
-- write path, and only the ones a read actually uses are worth that.
--
-- There is deliberately no single-column index on `timestamp`, `client_ip` or
-- `status`: each is the leading column of one of the composites below, and
-- SQLite uses a leftmost prefix (in either scan direction), so they cost three
-- extra b-tree writes per query and bought nothing.
--
-- And none on `domain`: the query log is searched with `domain LIKE '%…%'`,
-- which no b-tree can serve — SQLite scans the timestamp index instead, with or
-- without it. It was the most expensive index of the lot (a string key in
-- random order, so page splits on nearly every insert): removing it took ~45%
-- off the cost of logging a query and ~9% off the file.
CREATE INDEX IF NOT EXISTS idx_queries_time_id_desc
    ON queries (timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_status_time_id_desc
    ON queries (status, timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_client_time_id_desc
    ON queries (client_ip, timestamp DESC, id DESC);

-- ---------------------------------------------------------------
-- Query rollups
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS query_buckets_10m (
    bucket    INTEGER PRIMARY KEY, -- Unix epoch seconds, aligned to 600s
    total     INTEGER NOT NULL DEFAULT 0,
    blocked   INTEGER NOT NULL DEFAULT 0,
    cached    INTEGER NOT NULL DEFAULT 0,
    upstream  INTEGER NOT NULL DEFAULT 0
);

-- One upsert per distinct domain per flush, so the same rule as the query log
-- applies: only indexes a read uses. The primary key serves every read there
-- is (`WHERE bucket BETWEEN ? AND ? GROUP BY domain`); nothing looks a single
-- domain up, so there is no `(domain, bucket)` index — it doubled the cost of
-- an upsert and the size of the table for nobody. `device_buckets_10m` below
-- does have one, because per-device stats really are read that way.
CREATE TABLE IF NOT EXISTS domain_buckets_10m (
    bucket   INTEGER NOT NULL,
    domain   TEXT    NOT NULL,
    total    INTEGER NOT NULL DEFAULT 0,
    blocked  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, domain)
);

-- Per-device rollups (`device_buckets_10m`) are created by migration v4 rather
-- than here — they replaced an IP-keyed table, and the migration is what moves
-- an existing database across.

-- ---------------------------------------------------------------
-- Learned device identities (one row per physical device, keyed by MAC).
-- Persists the last hostname resolved via PTR/mDNS so it survives both an
-- IP change (DHCP) and a process restart — identity is the device, not the IP.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT    PRIMARY KEY,            -- 'aa:bb:cc:dd:ee:ff'
    hostname    TEXT,                           -- last learned PTR/mDNS name (nullable)
    last_seen   INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------
-- Last-known IP → MAC binding. Lets a historical IP (one a device no longer
-- holds, hence absent from the live neighbour table) still resolve to its
-- device. "Last binding wins": a reassigned IP is overwritten on next learn.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_bindings (
    ip          TEXT    PRIMARY KEY,            -- normalized IP (IPv4-mapped v6 unmapped)
    mac         TEXT    NOT NULL,
    last_seen   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ip_bindings_mac ON ip_bindings (mac);
"#;
