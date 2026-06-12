# Ferrite API Reference

Base URL: `http://localhost:8080` (default; configured via `api.bind_addr` in `config.toml`)

All responses are `application/json`. Error responses have the shape `{ "error": "<message>" }`.

---

## Authentication

Ferrite has two optional, independent auth mechanisms. If **neither** is configured, every endpoint is open.

### API Key (static)

Set `api_key` via `PATCH /api/settings`. Send on every request:

```
X-Api-Key: your-api-key
```

or

```
Authorization: Bearer your-api-key
```

### Session Token (password-based)

If a password is set (via `PATCH /api/settings` → `password` field, or `ferrite passwd` CLI), log in to get a session token valid for 24 h:

```
POST /api/auth
{ "password": "..." }
→ { "token": "...", "expires_in": 86400 }
```

Send the token on subsequent requests:

```
X-Session-Token: <token>
```

or

```
Authorization: Bearer <token>
```

> **Note:** `GET /api/auth`, `POST /api/auth`, and `DELETE /api/auth` are always public — no auth required.

---

## Auth Endpoints

### `GET /api/auth` — check auth status

No auth required.

```json
{ "authenticated": true, "password_set": true }
```

Returns `401` if a password is set and the caller has no valid session.

### `POST /api/auth` — log in

```json
{ "password": "plaintext-password" }
```

```json
{ "token": "abcdef123...", "expires_in": 86400 }
```

Returns `500` if no password is configured.

### `DELETE /api/auth` — log out

Invalidates the current session token. Token read from `X-Session-Token` or `Authorization: Bearer`.

```json
{ "status": "ok" }
```

---

## Stats

### `GET /api/stats/summary` — live summary from retained history

Served entirely from memory — **zero storage reads**. Safe to poll every 1–2 seconds. Includes timeseries, so a separate `GET /api/stats/timeseries` call is only needed for standalone chart use.

Counters and top-N lists are seeded from retained storage on startup, then updated in memory as new DNS queries arrive. The 24h timeseries and recent-query lists remain rolling/live windows. A same-day warm-restart snapshot can only increase seeded counters, so an old snapshot cannot shrink all-time totals after startup.

```json
{
  "total_queries": 14523,
  "blocked_queries": 3210,
  "cached_queries": 6700,
  "upstream_queries": 4613,
  "block_percentage": 22.1,
  "total_domains_blocked": 180423,
  "top_domains": [
    ["google.com", 842],
    ["api.example.com", 310]
  ],
  "top_blocked": [
    ["ads.doubleclick.net", 120],
    ["tracker.example.com", 88]
  ],
  "top_clients": [
    { "name": "macbook", "total": 5100, "ips": ["192.168.1.42", "fe80::1"], "macs": ["aa:bb:cc:dd:ee:ff"] },
    { "name": "192.168.1.99", "total": 210, "ips": ["192.168.1.99"], "macs": [] }
  ],
  "recent_domains": [
    {
      "id": 4821,
      "timestamp": "2025-04-24T10:01:02Z",
      "domain": "github.com",
      "query_type": 1,
      "client_ip": "192.168.1.42",
      "client_name": "macbook",
      "status": "upstream",
      "latency_ms": 12,
      "upstream": "1.1.1.1:53",
      "rcode": 0
    }
  ],
  "recent_blocked": [
    {
      "id": 4819,
      "timestamp": "2025-04-24T10:00:58Z",
      "domain": "ads.doubleclick.net",
      "query_type": 1,
      "client_ip": "192.168.1.99",
      "client_name": null,
      "status": "blocked",
      "latency_ms": 0,
      "upstream": null,
      "rcode": 3
    }
  ],
  "timeseries": [
    { "bucket": 1745491800, "total": 312, "blocked": 47, "cached": 180, "upstream": 85 },
    { "bucket": 1745492400, "total": 289, "blocked": 38, "cached": 171, "upstream": 80 }
  ]
}
```

- `top_domains`, `top_blocked` — top 10 from retained history plus live updates, sorted descending. Each item is `[name, count]`.
- `top_clients` — top 10 objects. `ips` lists every raw IP that resolved to this name; pass them as a comma-separated `client_ip` filter to `GET /api/queries`.
- Multiple IPs resolving to the same PTR hostname or alias are merged into one entry.
- `recent_domains` — last 10 queries (all statuses), newest first. Same format as `GET /api/queries`. `client_name` omitted if unknown.
- `recent_blocked` — last 10 blocked queries, newest first. Scans up to 500 recent entries to find them.
- `timeseries` — same data as `GET /api/stats/timeseries`: 24h rolling window, 10-min buckets, sorted ascending. Empty buckets omitted. Each bucket includes `total`, `blocked`, `cached`, and `upstream` counts.
- For rolling top-N with a specific time window, use `GET /api/stats/top-domains?hours=X` etc. (served from storage rollups). Use `all_time=true` or `hours=0` for all retained history.

### `GET /api/stats/timeseries` — 24-hour history

144 buckets × 10 minutes = 24 hours. Served from in-memory rolling window — no storage reads. On startup the window is seeded from storage so the chart is never blank after a restart. Buckets with zero traffic are omitted.

> The same data is included in `GET /api/stats/summary` under the `timeseries` key — prefer that endpoint when polling the dashboard to avoid a second request.

```json
[
  { "bucket": 1745000400, "total": 120, "blocked": 18, "cached": 70, "upstream": 32 },
  { "bucket": 1745001000, "total": 95, "blocked": 12, "cached": 55, "upstream": 28 }
]
```

`bucket` — Unix timestamp (UTC) of the start of the 10-minute window.

### `GET /api/stats/system` — system resource usage

CPU and network are measured over the same ~200 ms sample window, so this endpoint always takes ~200 ms. Poll no more than once every 2–5 seconds.

```json
{
  "cpu_usage_percent": 12.5,
  "cpu_temp_celsius": 42.0,
  "memory": {
    "total_bytes": 8589934592,
    "used_bytes": 4831838208,
    "used_percent": 56.3,
    "available_bytes": 3758096384,
    "free_bytes": 2684354560,
    "allocated_bytes": 5905580032,
    "reclaimable_bytes": 1073741824
  },
  "swap": {
    "total_bytes": 2147483648,
    "used_bytes": 524288000,
    "used_percent": 24.4
  },
  "network": {
    "interfaces": ["enP2p33s0"],
    "rx_bytes_per_sec": 1245000,
    "tx_bytes_per_sec": 320000,
    "link_speed_mbps": 1000,
    "rx_utilization_percent": 0.99,
    "tx_utilization_percent": 0.26
  },
  "process": {
    "memory_bytes": 104857600,
    "memory_percent": 1.2,
    "cpu_percent": 0.5
  },
  "disk": {
    "mount": "/",
    "total_bytes": 32000000000,
    "used_bytes": 8500000000,
    "used_percent": 26.6
  },
  "load_avg": {
    "one": 1.2,
    "five": 0.9,
    "fifteen": 0.7
  },
  "uptime_seconds": 86400
}
```

- `cpu_temp_celsius` — `null` if hardware sensors are unavailable (common on macOS and some VMs).
- `memory.used_bytes` — RAM pressure value: `total_bytes - available_bytes`. On Linux this follows `MemAvailable`, so reclaimable filesystem cache does not make the machine look fully loaded.
- `memory.allocated_bytes` — raw allocated RAM: `total_bytes - free_bytes`. This includes kernel/page-cache allocations and can be much higher than real pressure.
- `memory.reclaimable_bytes` — estimated immediately reusable memory: `available_bytes - free_bytes`.
- `network.interfaces` — list of active interface names used for the measurement. Interfaces with `operstate == down` (e.g. unplugged secondary NICs) are excluded. Loopback is always excluded.
- `network.link_speed_mbps` — read from `/sys/class/net/<iface>/speed` of the first active interface (Linux only); `null` on macOS and most VMs.
- `network.rx_utilization_percent`, `tx_utilization_percent` — `null` if `link_speed_mbps` is unknown. When available, use these for 0–100 % bars; otherwise display raw bytes/sec.
- `process` — ferrite's own resource usage. `memory_bytes` is RSS (resident set size). `memory_percent` = process RSS / total RAM × 100. `cpu_percent` is measured over the same 200 ms sample window. `null` if PID lookup fails.
- `disk` — root filesystem `/`; falls back to the first detected disk. `null` if no disks are found.
- `load_avg` — 1 / 5 / 15-minute load averages; always `0` on Windows.

### `GET /api/stats/top-blocked` — top blocked domains

| Param   | Type | Description                                |
| ------- | ---- | ------------------------------------------ |
| `limit` | int  | Max results (default 20, max 200)          |
| `hours` | int  | How far back to look (default 24, max 168); `0` means all retained history |
| `all_time` | bool | When true, ignore `hours` and use all retained history |

```
GET /api/stats/top-blocked?limit=10&hours=48
```

```json
{
  "domains": [
    { "domain": "ads.doubleclick.net", "count": 842 },
    { "domain": "tracker.example.com", "count": 310 }
  ],
  "from_ts": 1744922400,
  "to_ts": 1745008800
}
```

### `GET /api/stats/top-domains` — top queried domains

Same parameters as `top-blocked`, but counts all queries regardless of status.

| Param   | Type | Description                                |
| ------- | ---- | ------------------------------------------ |
| `limit` | int  | Max results (default 20, max 200)          |
| `hours` | int  | How far back to look (default 24, max 168); `0` means all retained history |
| `all_time` | bool | When true, ignore `hours` and use all retained history |

```
GET /api/stats/top-domains?limit=10&hours=24
```

```json
{
  "domains": [
    { "domain": "google.com", "count": 1420 },
    { "domain": "example.com", "count": 380 }
  ],
  "from_ts": 1744922400,
  "to_ts": 1745008800
}
```

### `GET /api/stats/top-clients` — top clients by query count

Groups IPs by resolved PTR hostname or alias, same as `summary.top_clients` but with configurable time range and limit.

| Param   | Type | Description                                |
| ------- | ---- | ------------------------------------------ |
| `limit` | int  | Max results (default 20, max 200)          |
| `hours` | int  | How far back to look (default 24, max 168); `0` means all retained history |
| `all_time` | bool | When true, ignore `hours` and use all retained history |

```
GET /api/stats/top-clients?limit=10&hours=12
GET /api/stats/top-clients?limit=10&all_time=true
```

```json
{
  "clients": [
    { "name": "macbook", "total": 5100, "ips": ["192.168.1.42", "fe80::1"], "macs": ["aa:bb:cc:dd:ee:ff"] },
    { "name": "router", "total": 1830, "ips": ["192.168.1.1"], "macs": [] }
  ],
  "from_ts": 1744965600,
  "to_ts": 1745008800
}
```

---

## Query Log

### `GET /api/queries` — DNS query log

All params are optional.

| Param       | Type   | Description                                      |
| ----------- | ------ | ------------------------------------------------ |
| `from_ts`   | int    | Unix timestamp lower bound                       |
| `to_ts`     | int    | Unix timestamp upper bound                       |
| `domain`    | string | Substring filter on domain name                  |
| `client_ip` | string | One IP or comma-separated list of IPs (OR logic) |
| `status`    | string | `upstream` \| `cached` \| `blocked` \| `allowed` |
| `limit`     | int    | Max results (default 100, max 1000)              |
| `before_ts` | int    | Cursor timestamp for the next page               |
| `before_id` | int    | Cursor row id for the next page                  |
| `offset`    | int    | Legacy pagination offset; slower on large logs   |

**Without any filters and without pagination params** — served from the in-memory ring buffer (last 2 000 entries). Always live, no SQLite read. Results are returned newest-first.

**With any filter, `before_ts`/`before_id`, or `offset > 0`** — queries storage. Use this path for search, filtering by status/domain/client, or paginating beyond the ring buffer.

For fast pagination, pass both cursor params from the last row of the current page:

```
GET /api/queries?limit=100&before_ts=1745323392&before_id=4821
```

`timestamp` in the JSON response is ISO-8601; frontends can derive `before_ts` with `Math.floor(new Date(last.timestamp).getTime() / 1000)`. Prefer cursor pagination over `offset` once the log grows beyond a few thousand rows.

```
GET /api/queries                               → live ring buffer, newest first
GET /api/queries?limit=50                      → live ring buffer, up to 50
GET /api/queries?status=blocked&limit=50       → SQLite (filter present)
GET /api/queries?client_ip=192.168.1.42        → SQLite (filter present)
GET /api/queries?limit=100&before_ts=1745323392&before_id=4821
                                                → SQLite (fast cursor pagination)
GET /api/queries?limit=100&offset=100          → SQLite (offset present)
```

```json
[
  {
    "id": 4821,
    "timestamp": "2025-04-22T14:03:12Z",
    "domain": "ads.doubleclick.net",
    "query_type": 1,
    "client_ip": "192.168.1.42",
    "client_name": "macbook",
    "status": "blocked",
    "latency_ms": 0,
    "upstream": null,
    "rcode": 3
  }
]
```

- `client_name` — resolved PTR hostname or manual alias; omitted if unknown.
- `query_type` — DNS record type number (1=A, 28=AAAA, 5=CNAME, 15=MX, 16=TXT, 12=PTR, 33=SRV, 65=HTTPS).
- `rcode` — DNS response code (0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN).
- `upstream` — resolver used, e.g. `"8.8.8.8:53"`; `null` if served from cache or blocklist. For CNAME-blocked queries the value is `"cname:<blocked-target>"` (see below).

**CNAME inspection:** When a domain resolves upstream to a CNAME chain that includes a blocked target, ferrite returns NXDOMAIN and logs the query as `status: "blocked"` with `upstream: "cname:<target>"`. Example: a query for `tracker.example.com` that CNAMEs to a blocked CDN would log `"upstream": "cname:cdn.blocked.net"`. This catches blocklist bypasses via CDN aliasing.

### `DELETE /api/queries` — purge the query log

Deletes all entries from SQLite **and** resets all in-memory stats: ring buffer, top-N counters, timeseries, and atomic counters (`total_queries`, `blocked_queries`, etc.). The next `/api/stats/summary` response will show zeroes until new traffic arrives.

```json
{ "status": "cleared" }
```

---

## Clients

### `GET /api/clients` — client list grouped by hostname

IPv4 and IPv6 addresses resolving to the same PTR hostname are merged into one entry. By default this returns all retained client history. Pass `hours` for a rolling window.

| Param      | Type | Description                                                |
| ---------- | ---- | ---------------------------------------------------------- |
| `limit`    | int  | Max results (default 50, max 500)                          |
| `hours`    | int  | Rolling window in hours, max 168; `0` means all retained history |
| `all_time` | bool | When true, ignore `hours` and use all retained history      |

```json
{
  "from_ts": 0,
  "to_ts": 1745008800,
  "clients": [
    {
      "name": "macbook",
      "ips": ["192.168.1.42", "fe80::a0ce:c8ff:fe12:3456"],
      "macs": ["a2:ce:c8:12:34:56"],
      "total": 4812,
      "blocked": 932,
      "last_seen": 1745008923,
      "is_alias": false,
      "blocking_bypassed": false
    }
  ]
}
```

- `name` — PTR hostname (local suffixes stripped), manual alias, or raw IP if unresolved.
- `macs` — MAC addresses learned from ARP/NDP/EUI-64; use one as a MAC alias key when available.
- `is_alias` — `true` if the name was set manually via `POST /api/clients/aliases`.
- `blocking_bypassed` — `true` if this client is exempt from blocklist filtering.
- `last_seen` — Unix timestamp of the most recent query from any of this client's IPs.

> PTR lookups run in the background on first sight. A new IP shows `name == ip` immediately and gets a resolved name within seconds.

### `GET /api/clients/:ip/stats` — per-client stats

```
GET /api/clients/192.168.1.42/stats
```

```json
{
  "client_ip": "192.168.1.42",
  "name": "macbook",
  "mac": "aa:bb:cc:dd:ee:ff",
  "total": 4812,
  "blocked": 932,
  "last_seen": 1745008923
}
```

- `name` — resolved PTR or alias; `null` if unknown.
- `mac` — learned MAC address for this IP, or `null` if not available yet.
- Returns `404` if no queries have been seen from this IP.

### `GET /api/clients/aliases` — list manual aliases

```json
{
  "aliases": [
    { "ip": "192.168.1.42", "name": "My MacBook", "type": "ip" },
    { "mac": "aa:bb:cc:dd:ee:ff", "name": "NAS", "type": "mac" }
  ]
}
```

### `POST /api/clients/aliases` — add or update alias

Manual aliases take priority over PTR lookups. Persisted across restarts. Provide exactly one of `ip` or `mac`.

```json
{ "ip": "192.168.1.42", "name": "My MacBook" }
```

```json
{ "mac": "aa:bb:cc:dd:ee:ff", "name": "NAS" }
```

`201` on success:

```json
{ "ip": "192.168.1.42", "name": "My MacBook", "type": "ip" }
```

### `DELETE /api/clients/aliases/:key` — remove alias

Accepts either an IP address or a MAC address as `:key`.

```
DELETE /api/clients/aliases/192.168.1.42
DELETE /api/clients/aliases/aa:bb:cc:dd:ee:ff
```

```json
{ "ip": "192.168.1.42", "status": "removed" }
```

---

## Blocklist

### `GET /api/blocklist/whitelist`

```json
{ "whitelist": ["safe.example.com", "*.internal.corp"] }
```

### `POST /api/blocklist/whitelist`

```json
{ "domain": "safe.example.com" }
```

```json
{ "domain": "safe.example.com", "status": "whitelisted" }
```

Persisted to SQLite. Takes effect immediately. Wildcard patterns (`*.example.com`) match all direct subdomains but not the apex itself.

### `DELETE /api/blocklist/whitelist/:domain`

```
DELETE /api/blocklist/whitelist/safe.example.com
```

```json
{ "domain": "safe.example.com", "status": "removed" }
```

### `GET /api/blocklist/blacklist`

```json
{ "blacklist": ["evil.com", "*.ads.net"] }
```

### `POST /api/blocklist/blacklist`

```json
{ "domain": "evil.com" }
```

```json
{ "domain": "evil.com", "status": "blacklisted" }
```

### `DELETE /api/blocklist/blacklist/:domain`

```
DELETE /api/blocklist/blacklist/evil.com
```

```json
{ "domain": "evil.com", "status": "removed" }
```

### `GET /api/blocklist/check/:domain` — check if a domain is blocked

```
GET /api/blocklist/check/ads.example.com
```

```json
{ "domain": "ads.example.com", "blocked": true, "whitelisted": false }
```

---

## Subscription Lists

Remote blocklists that ferrite downloads and compiles into an FST. Per-list downloads are cached on disk for 12 hours; only expired or new lists hit the network on refresh.

### `GET /api/lists`

```json
{
  "lists": [
    {
      "name": "StevenBlack",
      "url": "https://...",
      "enabled": true,
      "domains_loaded": 182443
    }
  ]
}
```

### `POST /api/lists` — add a new list

```json
{
  "name": "EasyList",
  "url": "https://easylist.to/easylist/easylist.txt",
  "enabled": true
}
```

`201` on success. Triggers a background FST rebuild (only the new list is downloaded; existing cached lists are reused).

```json
{
  "list": {
    "name": "EasyList",
    "url": "...",
    "enabled": true,
    "domains_loaded": null
  }
}
```

### `PATCH /api/lists/:name` — enable or disable a list

```json
{ "enabled": false }
```

```json
{
  "list": {
    "name": "EasyList",
    "url": "...",
    "enabled": false,
    "domains_loaded": 0
  }
}
```

Triggers a background FST rebuild. Returns `404` if the name is not found.

### `DELETE /api/lists/:name` — remove a list

```
DELETE /api/lists/EasyList
```

```json
{ "name": "EasyList", "status": "removed" }
```

Triggers a background FST rebuild without the removed list.

### `POST /api/lists/refresh` — force re-fetch all lists

Ignores disk cache and re-downloads every list from the network. Waits for the rebuild to complete before responding.

```
POST /api/lists/refresh
```

```json
{
  "lists": [
    {
      "name": "StevenBlack",
      "url": "https://...",
      "enabled": true,
      "domains_loaded": 182443
    },
    {
      "name": "EasyList",
      "url": "https://...",
      "enabled": true,
      "domains_loaded": 74210
    }
  ]
}
```

### `POST /api/lists/:name/refresh` — force re-fetch a single list

Ignores disk cache and re-downloads from the network. Waits for the rebuild to complete.

```
POST /api/lists/StevenBlack/refresh
```

```json
{ "name": "StevenBlack", "domains_loaded": 182443 }
```

---

## Custom DNS Records

Local A / AAAA / CNAME overrides. Take priority over blocklist and upstream. Wildcards (`*.home.lan`) are supported. Persisted to SQLite.

Ferrite also has a hidden built-in panel record: `fe.te` resolves to `panel.ipv4` when configured, or to the detected local IPv4 address of the ferrite server. It is not returned by `GET /api/custom-records`; adding a manual `fe.te` custom record overrides the built-in answer. In Docker bridge mode, set `panel.ipv4` or `FERRITE_PANEL_IP` to the host/LAN IP because container interface auto-detection sees the container IP.

### `GET /api/custom-records`

```json
{
  "records": [
    { "domain": "router.lan", "type": "A", "value": "192.168.1.1", "ttl": 300 },
    { "domain": "nas.lan", "type": "AAAA", "value": "fd00::1", "ttl": 300 },
    { "domain": "*.home.lan", "type": "CNAME", "value": "nas.lan", "ttl": 300 }
  ]
}
```

### `POST /api/custom-records` — add or update a record

```json
{
  "domain": "printer.lan",
  "type": "A",
  "value": "192.168.1.20",
  "ttl": 300
}
```

`type` must be `"A"`, `"AAAA"`, or `"CNAME"`. `ttl` is optional (default 300 s).

`201` on success:

```json
{
  "record": {
    "domain": "printer.lan",
    "type": "A",
    "value": "192.168.1.20",
    "ttl": 300
  }
}
```

### `DELETE /api/custom-records/:domain`

```
DELETE /api/custom-records/printer.lan
```

```json
{ "domain": "printer.lan", "status": "removed" }
```

---

## Settings

### `GET /api/settings` — current configuration

Returns the full parsed config. Non-empty `api_key` and `password_hash` values are redacted to `"***"`; unset or blank values are returned as `null`.

```json
{
  "dns": {
    "bind_addr": "0.0.0.0:53",
    "cache_size": 10000,
    "min_ttl": 60,
    "max_ttl": 3600,
    "log_ignore": ["fe.te", "*.arpa", "*.local", "*.localdomain"]
  },
  "upstream": [
    { "type": "plain", "address": "1.1.1.1", "port": 53 },
    { "type": "plain", "address": "1.0.0.1", "port": 53 }
  ],
  "zones": [{ "name": "1.168.192.in-addr.arpa", "upstream": "192.168.1.1:53" }],
  "storage": {
    "backend": "sqlite",
    "path": "/path/to/ferrite.db",
    "log_retention_days": 30
  },
  "api": {
    "bind_addr": "127.0.0.1:8080",
    "api_key": "***",
    "password_hash": null
  },
  "panel": {
    "enabled": true,
    "domain": "fe.te",
    "ipv4": "192.168.1.5",
    "url": "http://fe.te:8031"
  },
  "blocklist": {
    "enabled": true,
    "decision_cache_size": 50000,
    "lists": [],
    "wildcard_block": [],
    "whitelist": [],
    "client_bypass": ["192.168.1.50", "aa:bb:cc:dd:ee:ff"]
  },
  "custom_records": []
}
```

### `PATCH /api/settings` — update settings

All fields are optional. Fields not provided are left unchanged.

#### Hot-patchable — take effect immediately, no restart needed

| Field                | Type             | Description                                                                                                                                                                                                     |
| -------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api_key`            | `string \| null` | API key for Bearer/X-Api-Key auth; blank values are rejected; `null` disables key auth                                                                                                                          |
| `password`           | `string \| null` | Web UI password (hashed server-side, Argon2id); empty values are rejected; `null` disables password auth                                                                                                        |
| `dns_min_ttl`        | int              | Minimum TTL clamp for cached DNS responses, 60–3600 seconds                                                                                                                                                     |
| `dns_max_ttl`        | int              | Maximum TTL clamp for cached DNS responses, 60–3600 seconds                                                                                                                                                     |
| `dns_log_ignore`     | `string[]`       | Domain patterns to suppress from the query log entirely. Replaces the full list. Supports exact names (`fe.te`) and wildcard suffixes (`*.local`). Queries matching these patterns are still resolved normally. |
| `web_dir`            | `string \| null` | Override static web UI directory; `null` resets to `~/.local/share/ferrite/web`                                                                                                                                 |
| `log_retention_days` | int              | Automatically delete query log entries older than N days; `0` disables retention. Applied once ~30 s after startup and every 24 h thereafter.                                                                   |
| `blocklist_enabled`  | bool             | Master switch for DNS blocklist filtering. DNS resolution, custom records, caching, and logging continue to work while filtering is disabled.                                                                    |
| `blocklist_client_bypass` | `string[]` | Full replacement list of client IP/MAC keys that bypass blocklist filtering. IPs are normalized; MACs use `aa:bb:cc:dd:ee:ff`. No groups yet.                                                                   |

#### Restart-required — saved to disk, server exits so supervisor can restart it

| Field                           | Type   | Description                                                      |
| ------------------------------- | ------ | ---------------------------------------------------------------- |
| `dns_bind_addr`                 | string | DNS listener address, e.g. `"0.0.0.0:53"`                        |
| `dns_cache_size`                | int    | DNS response cache capacity (number of entries)                  |
| `blocklist_decision_cache_size` | int    | Block/allow decision cache capacity (number of domains, min `1`) |
| `api_bind_addr`                 | string | HTTP API / web UI bind address, e.g. `"127.0.0.1:8080"`          |
| `upstream`                      | array  | Replace the entire upstream resolver list (see format below)     |
| `zones`                         | array  | Replace the entire zone routing table (see format below)         |
| `panel_enabled`                 | bool   | Enable or disable the built-in panel DNS shortcut record          |
| `panel_domain`                  | string | Domain for the built-in panel shortcut, e.g. `"fe.te"`           |
| `panel_ipv4`                    | string \| null | IPv4 address returned by the panel shortcut; `null` restores auto-detection |
| `panel_url`                     | string \| null | Display URL shown in startup logs; `null` clears the override |

**Upstream resolver format** (`upstream` array items):

```json
{ "type": "plain", "address": "1.1.1.1", "port": 53 }
{ "type": "tls",   "address": "1.1.1.1", "port": 853, "tls_name": "cloudflare-dns.com" }
{ "type": "https", "url": "https://cloudflare-dns.com/dns-query", "bootstrap_ip": "1.1.1.1" }
{ "type": "quic",  "address": "94.140.14.14", "port": 853, "tls_name": "dns.adguard-dns.com" }
```

**Zone routing format** (`zones` array items):

```json
{ "name": "1.168.192.in-addr.arpa", "upstream": "192.168.1.1:53" }
{ "name": "localdomain",            "upstream": "192.168.1.1:53" }
```

In Docker bridge mode, automatic zone detection sees the Docker bridge network,
not the LAN. Configure the LAN reverse-DNS zone manually if router-provided PTR
hostnames should appear for clients.

**Panel shortcut fields:** `panel_ipv4` controls the A record returned for the
built-in panel domain. In Docker bridge mode, set it to the host/LAN IP because
the container usually auto-detects its bridge IP. `panel_url` is only a display
URL; DNS A records cannot encode a non-80 web UI port.

**Examples:**

```json
{ "api_key": "new-secret-key" }
```

```json
{ "password": null }
```

```json
{ "dns_min_ttl": 120, "dns_max_ttl": 2400 }
```

```json
{ "dns_log_ignore": ["fe.te", "*.arpa", "*.local", "*.localdomain", "*.wlan0"] }
```

```json
{
  "dns_bind_addr": "0.0.0.0:53",
  "upstream": [
    {
      "type": "https",
      "url": "https://cloudflare-dns.com/dns-query",
      "bootstrap_ip": "1.1.1.1"
    }
  ]
}
```

```json
{
  "panel_enabled": true,
  "panel_domain": "fe.te",
  "panel_ipv4": "192.168.1.5",
  "panel_url": "http://fe.te:8031"
}
```

```json
{
  "zones": [{ "name": "1.168.192.in-addr.arpa", "upstream": "192.168.1.1:53" }]
}
```

**Response (no restart):**

```json
{
  "status": "ok",
  "changed": ["api_key", "dns_min_ttl"],
  "hot_changed": ["api_key", "dns_min_ttl"],
  "restart_changed": [],
  "restart_required": false,
  "persisted": true,
  "saved_to": "/home/user/.config/ferrite/config.toml"
}
```

**Response (restart triggered):**

```json
{
  "status": "ok",
  "changed": ["dns_bind_addr", "upstream"],
  "hot_changed": [],
  "restart_changed": ["dns_bind_addr", "upstream"],
  "restart_required": true,
  "persisted": true,
  "saved_to": "/home/user/.config/ferrite/config.toml"
}
```

> When `restart_required` is `true`, the server exits ~300 ms after sending the response. A process supervisor (`systemd` with `Restart=always`, OpenRC `supervise-daemon`, etc.) is expected to restart it automatically.

---

## Updates

### `GET /api/update/check` — check for new versions

Queries GitHub releases for both the server binary (`syntlyx/ferrite-server`) and the web UI package (`syntlyx/ferrite-web`). Version labels are kept for display, but update availability also considers the GitHub release asset digest (`sha256:<hex>`). The release workflow publishes package archives and `.sha256` sidecars so checks can still verify artifacts when GitHub's release API digest is unavailable.

Web UI releases also publish `dist.manifest.json` with a `server_compat` range.
Ferrite only offers the newest web release compatible with the running server.
By convention, `0.1.x` web releases are compatible with `>=0.1.0 <0.2.0`
servers, `0.2.x` web releases with `>=0.2.0 <0.3.0`, and so on. The manifest
can override that range for exceptional releases.

By default, this endpoint returns the server's cached update state and does not
contact GitHub on every request. The background updater refreshes the cache once
per hour. Use `GET /api/update/check?force=true` for an explicit live refresh,
for example from a "Check updates" button.

If GitHub's REST API rate-limits unauthenticated requests, ferrite falls back to
public release download URLs and `.sha256` sidecar assets. Set
`FERRITE_RELEASE_TOKEN` or `GITHUB_TOKEN` in the service environment for private
repos or higher API limits.

```json
{
  "current_server_version": "0.1.1",
  "current_server_sha256": "6a9f4dca6f9f3b8e2d5b5d5e7a6f8c9b5b3f9a6d7e8c9b0a1d2e3f4a5b6c7d8e",
  "current_web_version": "0.1.1",
  "current_web_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "server_update": {
    "version": "0.2.0",
    "download_url": "https://github.com/syntlyx/ferrite-server/releases/download/v0.2.0/ferrite-v0.2.0-x86_64-unknown-linux-musl.tar.gz",
    "release_notes": "...",
    "sha256": "6a9f..."
  },
  "web_update": null,
  "incompatible_web_update": {
    "version": "0.3.0",
    "required_server": ">=0.3.0 <0.4.0",
    "reason": "web UI v0.3.0 requires server >=0.3.0 <0.4.0; running server is v0.2.4"
  },
  "checked_at": 1780000000,
  "cache_ttl_seconds": 3600,
  "stale": false,
  "check_pending": false,
  "last_error": null
}
```

`server_update` and `web_update` are `null` when that component is already up to date. If the release tag is recreated with the same semantic version but a different asset digest, the matching update object is returned so the same-version artifact can still be applied; older releases are ignored even when their digest differs. `web_update.server_compat` is included when a compatible web release is available. `incompatible_web_update` is present when a newer web release exists but requires a different server version range. `check_pending` is `true` before the first background check completes; `stale` is `true` when the cached result is older than the TTL or the latest refresh failed.

### `POST /api/update/server` — apply server update

Downloads and replaces the running binary. After a successful update, ferrite
saves a warm-restart snapshot, exits after the response is sent, and expects the
process supervisor to start the new binary.

On systemd and OpenRC installs, `install.sh` uses
`/usr/local/lib/ferrite/bin/ferrite` as the service binary and
`/usr/local/bin/ferrite` as a CLI link. The service binary directory is writable
by the `ferrite` service user, so web UI server updates can apply in place.
Systemd lists the directory in the unit `ReadWritePaths`; OpenRC uses
`supervise-daemon` with ambient `cap_net_bind_service` so the updated binary does
not depend on file `setcap`. Other install layouts must make the current
executable directory writable by the running service user, or update the server
by rerunning the installer with sudo/root.

Container images run the server from the mounted
`/var/lib/ferrite/bin/ferrite` path. The Alpine entrypoint installs or refreshes
that binary from GitHub releases on startup, so application releases do not
require rebuilding the image. `POST /api/update/server` can also replace the
mounted binary in place, then ferrite exits so the container runtime can restart
it on the updated binary.

```json
{
  "status": "updated",
  "version": "0.2.0",
  "sha256": "6a9f...",
  "restart_required": true,
  "note": "server is restarting to apply the update"
}
```

### `POST /api/update/web` — apply web UI update

Downloads and extracts the new web bundle to `~/.local/share/ferrite/web/`.
Only a web bundle compatible with the running server is applied. If the newest
available web bundle requires a newer server and no compatible web update is
available, the endpoint returns `409 Conflict` with the compatibility reason.

```json
{ "status": "updated", "version": "0.2.0", "sha256": "f12b..." }
```

---

## Error Responses

All errors follow the same shape:

```json
{
  "error": "human-readable description",
  "code": "stable_error_code",
  "kind": "config",
  "details": "raw server detail"
}
```

`error` remains for compatibility with older clients. New clients should prefer
`code` for localized UI copy and keep `details` only as a fallback/debug hint.

| HTTP status | Meaning                                           |
| ----------- | ------------------------------------------------- |
| `400`       | Bad request (invalid input or config)             |
| `401`       | Unauthorized (missing or invalid auth)            |
| `404`       | Resource not found                                |
| `409`       | Conflict (for example incompatible update bundle) |
| `500`       | Internal server error                             |

---

## Notes for Frontend Developers

**Polling summary:** `GET /api/stats/summary` is served from memory with no storage reads — safe to poll every 1–2 seconds.

**Live query log:** `GET /api/queries` without filters returns from the in-memory ring buffer (last 2 000 entries, newest-first). This is always live. For search or pagination beyond 2 000 entries, add any filter or use `before_ts` + `before_id` cursor pagination to use SQLite efficiently. `offset` remains supported for compatibility but gets slower on deep pages.

**Timeseries chart:** Buckets missing from `GET /api/stats/timeseries` had zero traffic. Fill gaps with zero when rendering a full 24-hour chart.

**Stats persistence after restart:** Atomic counters and Top-N counters (`top_domains`, `top_blocked`, `top_clients` in `/summary`) are seeded from retained storage on startup, then updated in memory. A same-day warm-restart snapshot can only increase seeded counters. The timeseries window and query ring buffer are seeded from storage on startup for the rolling 24h/recent views. For rolling Top-N with a specific time window, use `GET /api/stats/top-domains?hours=X` etc. Use `all_time=true` or `hours=0` for all retained history.

**`DELETE /api/queries`** clears both SQLite and all in-memory stats: ring buffer, top-N counters, timeseries, and atomic counters (`total_queries`, etc.). The next `/summary` response will show zeroes until new traffic arrives.

**Multi-IP client filter:** `GET /api/stats/top-clients` and `GET /api/stats/summary` return `ips[]` per client entry. Pass the whole array as a comma-separated `client_ip` value to `GET /api/queries` to see all traffic for that client regardless of which IP was used.

**Client name latency:** PTR lookups are asynchronous. On first load some clients appear with an IP as their name. Re-polling `GET /api/clients` after a few seconds returns resolved names. The no-flicker guarantee means once a name is known, it stays visible even while being refreshed in the background.

**Log ignore:** Domains matching `dns.log_ignore` patterns are resolved normally but never appear in `/api/queries` or any top-N list. Defaults: `fe.te`, `*.arpa`, `*.local`, `*.localdomain`. Update via `PATCH /api/settings` → `dns_log_ignore`.

**Wildcard format:** `*.example.com` matches any subdomain of `example.com` but not `example.com` itself. To cover both, add separate entries for `example.com` and `*.example.com`.

**`query_type` values:** `1`=A, `28`=AAAA, `5`=CNAME, `15`=MX, `16`=TXT, `12`=PTR, `33`=SRV, `65`=HTTPS.

**Restart flow:** When `PATCH /api/settings` returns `restart_required: true`, the connection will drop ~300 ms later. The frontend should show a "restarting…" indicator and poll `GET /api/auth` (or any endpoint) until the server responds again.
