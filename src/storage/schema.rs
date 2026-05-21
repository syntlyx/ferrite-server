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
    status      TEXT    NOT NULL,   -- 'upstream' | 'cached' | 'blocked' | 'allowed'
    latency_ms  INTEGER NOT NULL DEFAULT 0,
    upstream    TEXT,               -- NULL if not forwarded
    rcode       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_queries_timestamp  ON queries (timestamp);
CREATE INDEX IF NOT EXISTS idx_queries_domain     ON queries (domain);
CREATE INDEX IF NOT EXISTS idx_queries_client_ip  ON queries (client_ip);
CREATE INDEX IF NOT EXISTS idx_queries_status     ON queries (status);
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

CREATE TABLE IF NOT EXISTS domain_buckets_10m (
    bucket   INTEGER NOT NULL,
    domain   TEXT    NOT NULL,
    total    INTEGER NOT NULL DEFAULT 0,
    blocked  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, domain)
);
CREATE INDEX IF NOT EXISTS idx_domain_buckets_domain_bucket
    ON domain_buckets_10m (domain, bucket);

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
"#;
