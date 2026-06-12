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
- **Panel shortcut** — built-in `fe.te` DNS record resolves to the configured or detected ferrite server IP
- **Warm restart** — DNS cache and same-day stats counters snapshotted on shutdown, restored on startup

## Installation

From release artifacts on Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/syntlyx/ferrite-server/main/install.sh | sudo sh
```

Release binaries are also published for macOS, but the service installer is
Linux-only until launchd, port 53 binding, and self-update semantics are handled
cleanly.

From source:

```bash
cargo build --release
cp target/release/ferrite /usr/local/bin/ferrite
```

Requires Rust 1.88+. Key dependencies: `tokio`, `axum`, `hickory-resolver`, `fst`, `rusqlite`, `argon2`.

### Container image

Container images are published to GitHub Container Registry, not Docker Hub:

```bash
docker pull ghcr.io/syntlyx/ferrite-server:latest
```

Run ferrite with persistent config/data volumes:

```bash
docker run -d --name ferrite \
  --restart unless-stopped \
  -p 53:53/tcp \
  -p 53:53/udp \
  -p 80:80/tcp \
  -v ferrite-data:/var/lib/ferrite \
  ghcr.io/syntlyx/ferrite-server:latest
```

Docker publishes TCP and UDP with separate rules, but Ferrite uses one DNS
listener address: keep both rules on the same host/container port (`53:53`).

The image is a small Alpine runtime. On startup, the entrypoint downloads the
latest Ferrite server and web release assets, verifies their `.sha256` sidecars
when available, installs them under `/var/lib/ferrite`, and then runs Ferrite as
the unprivileged `ferrite` user. The container default config listens for DNS on
`0.0.0.0:53`, API/web on `0.0.0.0:80`, stores SQLite data under
`/var/lib/ferrite`, runs the server binary from `/var/lib/ferrite/bin/ferrite`,
and serves web assets from `/var/lib/ferrite/web`. Mount `/var/lib/ferrite` to
persistent storage so config, data, server updates, and web updates survive
container restarts. If your runtime strips file capabilities and port 53 fails
to bind, add `--cap-add=NET_BIND_SERVICE`.
If host port 80 is already taken, keep Ferrite on container port 80 and map a
different host port, for example `-p 8080:80`.

Container system stats reflect the container/VM view of the host. CPU and memory
usually work, but CPU temperature is normally unavailable unless the Linux host
explicitly exposes hardware sensor files; ferrite reports it as `null` when the
runtime hides sensors.

For containers, application releases do not require rebuilding or pulling a new
image. Restarting the container after a release is enough: the entrypoint checks
GitHub releases and refreshes `/var/lib/ferrite/bin/ferrite` and
`/var/lib/ferrite/web` when a newer release, or a same-version checksum change,
is available. `POST /api/update/server` still works too: it updates the mounted
server binary in place, then exits so Docker can restart the container on the new
binary. Use a restart policy such as `--restart unless-stopped` if you want that
restart to be automatic.

Pin startup installs with `FERRITE_SERVER_VERSION=0.1.1`; `FERRITE_WEB_VERSION`
defaults to the same value unless set separately. Leave both unset to track the
latest releases. For private repos or higher API limits, pass
`FERRITE_RELEASE_TOKEN` or `GITHUB_TOKEN`.

In Docker bridge mode, the built-in `fe.te` panel shortcut cannot infer the LAN
IP of the host from inside the container. Set `FERRITE_PANEL_IP` to the host IP
for the `fe.te` A record, for example `FERRITE_PANEL_IP=192.168.1.5`. If the web
UI is published on a non-80 host port, open `http://fe.te:<port>` and optionally
set `FERRITE_PANEL_URL` to that URL so startup logs show the reachable address.
Bridge mode also prevents Ferrite from auto-detecting the LAN reverse-DNS zone,
so configure `zones` manually if you want router-provided client hostnames:

```json
{ "zones": [{ "name": "1.168.192.in-addr.arpa", "upstream": "192.168.1.1:53" }] }
```

Build locally:

```bash
docker build -t ferrite:local .
```

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
enabled = true
decision_cache_size = 50000
whitelist = ["safe.example.com", "*.internal.corp"]
wildcard_block = ["*.doubleclick.net"]
client_bypass = ["192.168.1.50", "aa:bb:cc:dd:ee:ff"]
```

Set `enabled = false` to turn off DNS blocking globally without disabling DNS
resolution, logging, custom records, or the web UI. `client_bypass` disables
blocking for specific IP/MAC clients without introducing groups.

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
the configured panel IPv4 address, or the detected local IPv4 address of the
ferrite server. A manual custom DNS record for `fe.te` overrides the built-in
one. In Docker bridge mode, set `FERRITE_PANEL_IP` to the host/LAN IP because
interface auto-detection only sees the container IP.

For router-provided client hostnames in Docker bridge mode, configure the LAN
reverse-DNS zone explicitly, for example `1.168.192.in-addr.arpa` to
`192.168.1.1:53` for a `192.168.1.0/24` network. Auto-detection inside the
container sees the Docker bridge network, not the LAN.

Or set it permanently in the config file:

```toml
# Top-level setting.
web_dir = "/path/to/ferrite-ui/dist"

[panel]
enabled = true
domain = "fe.te"
ipv4 = "192.168.1.5"
url = "http://fe.te:8031"
```

## Updates

`POST /api/update/web` can update the web UI in place because the installed web
directory is writable by the `ferrite` service user.

Update checks prefer GitHub's release API because it exposes asset SHA256
digests. If GitHub rate-limits unauthenticated API requests, ferrite falls back
to public release download URLs and `.sha256` sidecar assets. For private repos
or higher API limits, run the service with `FERRITE_RELEASE_TOKEN` or
`GITHUB_TOKEN`.

Web UI releases include a small compatibility manifest. Ferrite only offers the
newest web bundle compatible with the running server, so `0.1.x` web builds stay
on the `0.1.x` server line while `0.2.x` can require a `0.2.x` server.

The server refreshes update state in the background once per hour. Opening the
web UI reads the cached state; the manual "Check updates" action forces a live
refresh.

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

GET    /api/stats/summary                 live counters seeded from retained history
GET    /api/stats/timeseries              24 h timeseries (144 × 10 min buckets)
GET    /api/stats/top-blocked             top blocked domains from the query log
GET    /api/stats/top-domains             top queried domains from the query log
GET    /api/stats/top-clients             top clients from the query log (hours window or all-time)
GET    /api/stats/system                  host/process system metrics

GET    /api/queries                       query log (filterable, paginated)

GET    /api/clients                       clients grouped by hostname (all retained history by default)
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
