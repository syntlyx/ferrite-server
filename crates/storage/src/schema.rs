/// SQL schema applied on first startup (or after a migration).
pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

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

CREATE TABLE IF NOT EXISTS client_buckets_10m (
    bucket     INTEGER NOT NULL,
    client_ip  TEXT    NOT NULL,
    total      INTEGER NOT NULL DEFAULT 0,
    blocked    INTEGER NOT NULL DEFAULT 0,
    last_seen  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, client_ip)
);
CREATE INDEX IF NOT EXISTS idx_client_buckets_client_bucket
    ON client_buckets_10m (client_ip, bucket);

-- ---------------------------------------------------------------
-- Per-client aggregated statistics (refreshed periodically)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS client_stats (
    client_ip   TEXT    PRIMARY KEY,
    total       INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    last_seen   INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------
-- Blocklist metadata (which lists are configured)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocklists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    url         TEXT    NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_update INTEGER,            -- Unix epoch of last successful fetch
    domain_count INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------
-- Custom per-user whitelist / blacklist entries
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS custom_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT    NOT NULL UNIQUE,
    entry_type  TEXT    NOT NULL,   -- 'whitelist' | 'blacklist'
    comment     TEXT,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_custom_domain ON custom_entries (domain);
CREATE INDEX IF NOT EXISTS idx_custom_type   ON custom_entries (entry_type);

-- ---------------------------------------------------------------
-- Custom DNS records (managed at runtime via API)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS custom_dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT    NOT NULL,
    record_type TEXT    NOT NULL,   -- 'A' | 'AAAA' | 'CNAME'
    value       TEXT    NOT NULL,
    ttl         INTEGER NOT NULL DEFAULT 300,
    created_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_custom_dns_domain_type
    ON custom_dns_records (domain, record_type);

-- ---------------------------------------------------------------
-- Key-value settings store
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    key     TEXT    PRIMARY KEY,
    value   TEXT    NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- ---------------------------------------------------------------
-- Manual client name aliases  (key + key_type → friendly name)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS client_aliases (
    key         TEXT    NOT NULL,
    key_type    TEXT    NOT NULL DEFAULT 'ip',  -- 'ip' | 'mac'
    name        TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (key, key_type)
);

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
