# ferrite

A Pi-hole alternative written in Rust. Blocks ads and trackers at the DNS level, supports encrypted upstream resolvers, stores query statistics, and is fully managed via a REST API.

## Features

- **DNS server** — UDP + TCP, automatic TCP fallback on TC bit
- **Encrypted upstreams** — DoT, DoH (RFC 8484), DoQ (RFC 9250) via hickory-resolver
- **Blocklist engine** — FST (Finite State Transducer) for fast lookup across 100k+ domains; auto-detects list format (hosts / adblock `||domain^` / plain); wildcard support for both whitelist and blacklist
- **Client tracking** — groups IPv4 and IPv6 addresses with PTR, MAC, and manual aliases
- **LRU DNS cache** — TTL clamping, survives restarts via binary snapshot
- **Custom DNS records** — A, AAAA, CNAME with wildcard domains (`*.home.lan`)
- **Statistics** — live atomic counters, 24h timeseries (144 × 10 min buckets), full query log in SQLite
- **REST API** — complete control without restarting; see [API.md](API.md)
- **Authentication** — session tokens (Argon2id, 24h TTL) or static API key
- **Hot reload** — blocklist lists, selected runtime settings, and web UI path update without restart
- **Panel shortcut** — built-in `fe.te` DNS record resolves to the ferrite server IP
- **Warm restart** — DNS cache and same-day stats counters snapshotted on shutdown, restored on startup

## Installation

From release artifacts:

```bash
curl -fsSL https://raw.githubusercontent.com/syntlyx/ferrite-server/main/install.sh | sudo sh
```

From source:

```bash
cargo build --release
cp target/release/ferrite /usr/local/bin/ferrite
```

Requires Rust 1.88+. Key dependencies: `tokio`, `axum`, `hickory-resolver`, `fst`, `rusqlite`, `argon2`.

## Testing

Fast local gate:

```bash
cargo fmt --all -- --check
cargo check --locked
cargo check --locked --features storage-redis
cargo test --all --locked
cargo test --all --all-features --locked
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo audit --deny warnings
sh -n install.sh
shellcheck install.sh
git diff --check
```

## Configuration

### File locations

| Scope       | Path                            |
| ----------- | ------------------------------- |
| User        | `~/.config/ferrite/config.toml` |
| System-wide | `/etc/ferrite/config.toml`      |

The user path is the same on macOS and Linux. If no config file is found, ferrite starts with defaults (plain UDP to 8.8.8.8 / 8.8.4.4 on port 53, API on 127.0.0.1:8080).

Copy the provided `config.toml.example` as a starting point. Only specify what differs from defaults.

### Minimal example

```toml
[dns]
bind_addr = "0.0.0.0:53"

[api]
bind_addr = "0.0.0.0:8080"
```

## Upstream resolvers

Multiple upstreams are used in round-robin with automatic failover.

### Plain UDP/TCP

```toml
[[upstream]]
type = "plain"
address = "8.8.8.8"
port = 53
```

### DNS-over-TLS (DoT)

```toml
[[upstream]]
type = "tls"
address = "1.1.1.1"
port = 853
tls_name = "cloudflare-dns.com"
```

### DNS-over-HTTPS (DoH)

```toml
[[upstream]]
type = "https"
url = "https://cloudflare-dns.com/dns-query"
bootstrap_ip = "1.1.1.1"   # required when ferrite is the system DNS resolver
```

> **Bootstrap problem:** when ferrite is the system resolver, it cannot resolve the DoH server hostname through itself. Set `bootstrap_ip` to the server's IP address to bypass DNS resolution.

| Provider   | URL                                     | bootstrap_ip   |
| ---------- | --------------------------------------- | -------------- |
| Cloudflare | `https://cloudflare-dns.com/dns-query`  | `1.1.1.1`      |
| Google     | `https://dns.google/dns-query`          | `8.8.8.8`      |
| AdGuard    | `https://dns.adguard-dns.com/dns-query` | `94.140.14.14` |

### DNS-over-QUIC (DoQ)

```toml
[[upstream]]
type = "quic"
address = "94.140.14.14"
port = 853
tls_name = "dns.adguard-dns.com"
```

> DoT and DoQ use a direct IP in `address` — no bootstrap needed.

## Blocklists

The default subscription is [StevenBlack/hosts](https://github.com/StevenBlack/hosts).

Supported list formats (auto-detected): hosts (`0.0.0.0 domain`), Adblock (`||domain^`), plain one-per-line. Comments (`#` and `!`) are supported in all formats.

The compiled FST is cached to disk after the first load; subsequent starts skip the network entirely. Each list's parsed domains are cached separately for 12 hours — adding a new list only re-fetches that list, not the others.
List refreshes are intentionally throttled so large subscriptions do not all parse/build in memory at the same time.

```toml
[[blocklist.lists]]
name = "StevenBlack"
url  = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
enabled = true
```

Lists can also be added, removed, enabled/disabled, and force-refreshed at runtime via the API. Changes are persisted to the config file automatically.

### Whitelist and blacklist

Both support exact domains and wildcard patterns. Wildcards use `*` as the only special character — `*.example.com` matches all direct subdomains but not `example.com` itself.

```toml
[blocklist]
decision_cache_size = 50000
whitelist = ["safe.example.com", "*.internal.corp"]
wildcard_block = ["*.doubleclick.net"]
```

Lower `decision_cache_size` on very small devices if you prefer a smaller RAM footprint over fewer FST lookups.

Runtime overrides are also available via `POST /api/blocklist/whitelist` and `POST /api/blocklist/blacklist`.

## Custom DNS records

Defined in config or added via the API. Take priority over the blocklist and upstream.

```toml
[[custom_records]]
domain = "router.lan"
type   = "A"
value  = "192.168.1.1"
ttl    = 300

[[custom_records]]
domain = "*.home.lan"
type   = "A"
value  = "192.168.1.100"
```

Supported types: `A`, `AAAA`, `CNAME`.

## Web UI

Static files are served from `~/.local/share/ferrite/web/` by default. Install or update them via:

```bash
curl -s -X POST http://localhost:8080/api/update/web
```

During frontend development, point ferrite at your local build output instead of redeploying:

```bash
curl -s -X PATCH http://localhost:8080/api/settings \
     -H 'Content-Type: application/json' \
     -d '{"web_dir": "/path/to/ferrite-ui/dist"}'
```

Ferrite also serves a built-in DNS shortcut for the panel: `fe.te` resolves to
the detected local IPv4 address of the ferrite server. A manual custom DNS
record for `fe.te` overrides the built-in one.

Or set it permanently in the config file:

```toml
# Top-level setting.
web_dir = "/path/to/ferrite-ui/dist"
```

## Updates

`POST /api/update/web` can update the web UI in place because the installed web
directory is writable by the `ferrite` service user.

On systemd and OpenRC installs, `install.sh` runs ferrite from
`/usr/local/lib/ferrite/bin/ferrite` and leaves `/usr/local/bin/ferrite` as a CLI
link. That service binary is writable by the `ferrite` service user, so
`POST /api/update/server` can replace it from the web UI. After a successful
server update, ferrite exits and the process supervisor restarts it on the new
binary. OpenRC uses `supervise-daemon` with ambient `cap_net_bind_service`
instead of file `setcap`, so the capability is not lost when the binary is
replaced.

If ferrite is installed from source, on macOS, or with a root-owned binary path,
server self-update needs the executable directory to be writable by the running
service user. Otherwise update the server by rerunning the installer with
sudo/root:

```bash
curl -fsSL https://raw.githubusercontent.com/syntlyx/ferrite-server/main/install.sh | sudo sh
```

## Authentication

### Set a password

```bash
ferrite passwd
```

This stores an Argon2id hash in the config file. If neither a password nor an API key is set, the API is open.

### Log in

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth \
        -H 'Content-Type: application/json' \
        -d '{"password":"your-password"}' | jq -r .token)
curl -s http://localhost:8080/api/stats/summary \
     -H "Authorization: Bearer $TOKEN"
```

### Static API key

Set `api_key` in config or via `PATCH /api/settings`. Pass it on every request:

```
Authorization: Bearer <api_key>
X-Api-Key: <api_key>
```

## API overview

Full documentation: [API.md](API.md)

Base URL: `http://127.0.0.1:8080`

```
GET    /api/auth                          session status
POST   /api/auth                          log in → session token
DELETE /api/auth                          log out

GET    /api/stats/summary                 live counters
GET    /api/stats/timeseries              24 h timeseries (144 × 10 min buckets)
GET    /api/stats/top-blocked             top blocked domains from the query log
GET    /api/stats/top-domains             top queried domains from the query log
GET    /api/stats/top-clients             top clients from the query log
GET    /api/stats/system                  host/process system metrics

GET    /api/queries                       query log (filterable, paginated)

GET    /api/clients                       top clients grouped by hostname
GET    /api/clients/aliases               manual name aliases
POST   /api/clients/aliases               add or update alias
DELETE /api/clients/aliases/{ip}          remove alias

GET    /api/blocklist/whitelist           list whitelist entries
POST   /api/blocklist/whitelist           add entry (exact or *.wildcard)
DELETE /api/blocklist/whitelist/{domain}
GET    /api/blocklist/blacklist           list blacklist entries
POST   /api/blocklist/blacklist           add entry (exact or *.wildcard)
DELETE /api/blocklist/blacklist/{domain}
GET    /api/blocklist/check/{domain}      check if a domain would be blocked

GET    /api/lists                         subscription lists
POST   /api/lists                         add subscription
PATCH  /api/lists/{name}                  enable or disable a list
DELETE /api/lists/{name}                  remove subscription
POST   /api/lists/{name}/refresh          force re-fetch
POST   /api/lists/refresh                 force re-fetch all enabled lists

GET    /api/custom-records                list custom DNS records
POST   /api/custom-records                add or update record
DELETE /api/custom-records/{domain}       remove record

GET    /api/settings                      current config (secrets redacted)
PATCH  /api/settings                      update runtime settings

GET    /api/update/check                  check for available updates
POST   /api/update/server                 update server binary
POST   /api/update/web                    update web UI assets
```

## Data files

All data lives under `~/.local/share/ferrite/` on both macOS and Linux.

| File                   | Contents                                                           |
| ---------------------- | ------------------------------------------------------------------ |
| `ferrite.db`           | SQLite: query log, statistics, whitelist/blacklist, custom records |
| `blocklist.fst`        | Compiled FST blocklist (disk cache, rebuilt on list changes)       |
| `lists/<name>.domains` | Per-list parsed domain cache (12 h TTL)                            |
| `state.bin`            | Warm restart snapshot (DNS cache + stats counters)                 |
| `web/`                 | Web UI static files                                                |

## License

MIT
