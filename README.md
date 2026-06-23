# ferrite

**Self-hosted DNS that blocks ads & trackers — and routes any device through a
tunnel.** It's a Pi-hole-style sinkhole that goes further: send chosen domains,
or whole devices, through **WireGuard, SOCKS5, or Tor** with DPI evasion and
encrypted upstreams. Filtering and a privacy tunnel in **one binary, no root**,
written in Rust.

> Pi-hole keeps your DNS clean. ferrite keeps it clean **and** lets you decide,
> per device, what leaves your network and how.

## Why ferrite

- **Filtering _and_ per-device routing in one box.** No glue between a DNS
  blocker and a VPN — it's the same server.
- **Anti-censorship built in.** Route blocked domains through Tor or a tunnel,
  with TLS-ClientHello (SNI) fragmentation to defeat DPI — per device, your choice.
- **No root, no TUN device.** WireGuard runs in userspace (boringtun + smoltcp),
  fully in-process.
- **Fast and small.** Rust, single binary, sub-2 ms cache/block decisions,
  tens-of-thousands of QPS on a home server.
- **Self-hosted and private.** No telemetry, no phone-home. Your queries stay on
  your box.

## Screenshots

> Images live in the [web UI repo](https://github.com/syntlyx/ferrite-web/tree/main/screenshots).

![Dashboard](https://raw.githubusercontent.com/syntlyx/ferrite-web/main/screenshots/dashboard.png)
![Tunnels](https://raw.githubusercontent.com/syntlyx/ferrite-web/main/screenshots/tunnels.png)

## Privacy

ferrite is a privacy tool first. What that means concretely:

- **No telemetry, no analytics, no phone-home.** The only outbound call ferrite
  makes on its own is an hourly GitHub check for updates (and blocklist fetches
  you configure). Nothing about your queries ever leaves the box.
- **Your DNS, encrypted upstream.** Plain, DoT, DoH, and DoQ upstreams in one
  pool. A resolver's queries can also ride a **tunnel** (DNS-over-TCP or DoT
  through an egress) — so your ISP sees only WireGuard, not your lookups.
- **No client-subnet leak.** EDNS Client Subnet is stripped from outgoing
  queries, so the upstream never learns the client's subnet.
- **DNSSEC requested.** The DO bit is set and signatures are forwarded; pair with
  a validating resolver over DoT/DoH for end-to-end integrity.
- **No TLS interception.** For routed domains ferrite peeks the SNI/Host but
  **never terminates TLS** — the client validates the real certificate end-to-end.
- **Local, optional logging.** The query log is SQLite on your disk. Retention is
  configurable, and verbose logging is a toggle.
- **No auth by default is loopback-only.** The panel binds `127.0.0.1` until you
  expose it; if you bind it to the LAN without a password, ferrite warns you.

## How it works

Every query runs the shortest useful path, stopping at the first stage that can
answer:

```
client ──▶ ferrite
            1. custom records   → local A/AAAA/CNAME answer
            2. selective routing→ matches a rule? answer with ferrite's own IP
            3. blocklist        → blocked? NXDOMAIN
            4. cache            → fresh? cached answer
            5. upstream         → DoT/DoH/DoQ/plain (round-robin + failover)
```

**Selective routing / tunnels.** When a domain matches a routing rule, ferrite
answers DNS with **its own LAN IP**, so the client connects to ferrite. The
listeners peek the **SNI** (`:443`) or **Host** (`:80`) — without terminating TLS
— re-match the rule on the real hostname, and splice the connection through the
chosen **egress**:

| Egress      | What it does                                                                                                                       |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `direct`    | Connect straight out (resolved via ferrite's upstream — no DNS leak).                                                              |
| `socks5`    | Forward through a SOCKS5 proxy (hostname sent as `ATYP=domain`). Point it at a local **Tor** (`127.0.0.1:9050`) to route over Tor. |
| `wireguard` | Built-in userspace WireGuard — paste a `.conf`. DNS for routed names resolves _through_ the tunnel.                                |
| `evasion`   | Like `direct`, but splits the TLS ClientHello at the SNI across TCP segments so DPI can't read the hostname.                       |

Rules can be scoped to **specific devices** (by name/MAC/IP) — route a kid's
tablet through a tunnel while everything else goes direct. Routing is independent
of blocking (a routed domain is never blocked). Rules, egresses, and listener
ports **hot-reload** — no restart.

## Install

```bash
# Linux — release install (systemd / OpenRC service)
curl -fsSL https://raw.githubusercontent.com/syntlyx/ferrite-server/main/install.sh | sudo sh
```

```bash
# Docker — image on GHCR (not Docker Hub)
docker run -d --name ferrite \
  --restart unless-stopped \
  -p 53:53/tcp -p 53:53/udp \
  -p 80:80/tcp \
  -v ferrite-data:/var/lib/ferrite \
  ghcr.io/syntlyx/ferrite-server:latest
```

```bash
# From source (Rust 1.88+)
cargo build --release
cp target/release/ferrite /usr/local/bin/ferrite
```

Then point your network's DNS (router DHCP, or per device) at the ferrite host,
open **`http://fe.te`** on the LAN, and set a password.

- The Docker image is a small Alpine runtime; mount `/var/lib/ferrite` so config,
  data, and updates survive restarts. If port 53 fails to bind, add
  `--cap-add=NET_BIND_SERVICE`. In bridge mode set `FERRITE_PANEL_IP=<host LAN IP>`
  so the `fe.te` shortcut resolves.
- `fe.te` is a built-in DNS record pointing at the detected (or configured) server
  IP, so the panel is easy to find.

## Configuration

Config lives at `~/.config/ferrite/config.toml` (user) or `/etc/ferrite/config.toml`
(system). The **web UI is the primary editor** — ferrite writes the file itself;
hand-editing is optional. With no config, ferrite starts with sane defaults (plain
UDP to `8.8.8.8`/`8.8.4.4`, API on `127.0.0.1:8080`).

```toml
[dns]
bind_addr = "0.0.0.0:53"
strip_ecs = true   # don't leak the client subnet upstream
dnssec    = true   # request DNSSEC (DO bit)

[api]
bind_addr = "0.0.0.0:8080"   # default 127.0.0.1 (loopback) — set a password before exposing
```

**Upstreams** (round-robin + failover). Each upstream may tunnel through an egress
via `egress = "<id>"` (plain/DoT only):

```toml
[[upstream]]
type = "plain"; address = "8.8.8.8"; port = 53

[[upstream]]
type = "tls"; address = "1.1.1.1"; port = 853; tls_name = "cloudflare-dns.com"

[[upstream]]
type = "https"; url = "https://cloudflare-dns.com/dns-query"; bootstrap_ip = "1.1.1.1"

[[upstream]]
type = "quic"; address = "94.140.14.14"; port = 853; tls_name = "dns.adguard-dns.com"
```

> `bootstrap_ip` is needed for DoH when ferrite is the system resolver (it can't
> resolve the DoH hostname through itself). DoT/DoQ use a literal IP — no bootstrap.

**Blocklists** — subscribe to any public list by URL (StevenBlack, OISD, AdGuard,
Hagezi…); formats (hosts / Adblock `||domain^` / plain) are auto-detected and
compiled into one fast FST. Manage them live in the UI.

```toml
[blocklist]
enabled = true
whitelist       = ["safe.example.com", "*.internal.corp"]
wildcard_block  = ["*.doubleclick.net"]
client_bypass   = ["192.168.1.50", "aa:bb:cc:dd:ee:ff"]   # these clients skip filtering

[[blocklist.lists]]
name = "StevenBlack"
url  = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
enabled = true
```

**Custom records** (take priority over blocklist + upstream):

```toml
[[custom_records]]
domain = "router.lan"; type = "A"; value = "192.168.1.1"; ttl = 300

[[custom_records]]
domain = "*.home.lan"; type = "A"; value = "192.168.1.100"
```

**Selective routing** — an egress + a rule. Paste a standard WireGuard `.conf`:

```toml
[proxy]
enabled = true
max_connections = 256
# advertise_ipv4 / advertise_ipv6 auto-detect when unset

[[proxy.egresses]]
id = "nl-proton"; name = "NL Proton"; enabled = true
kind = "wireguard"        # direct | socks5 | wireguard | evasion
buffer_kb = 512           # wireguard per-connection window (throughput vs RAM; 256–1024 KiB)
config = """
[Interface]
PrivateKey = <your key>
Address = 10.2.0.2/32
DNS = 10.2.0.1
[Peer]
PublicKey = <peer key>
Endpoint = 146.70.86.114:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

[[proxy.rules]]
pattern = "example.com"   # exact = domain + all subdomains; "*.example.com" = subdomains only
egress  = "nl-proton"
fail_closed = true        # if the egress is down, refuse rather than leak the connection directly
clients = []              # empty = all devices; or restrict by IP/MAC
```

The HTTP listener is shared with the panel on `:80` (demuxed by `Host`); TLS is
`:443`. Binding 80/443 needs privilege — ferrite already binds `:53`, so deploy
with `CAP_NET_BIND_SERVICE`.

## Authentication

```bash
ferrite passwd                 # set a web UI password (Argon2id hash, stored in config)
```

If neither a password nor an `api_key` is set, the API/panel is open — fine on
loopback, **set a password before binding to the LAN** (ferrite warns you if you
don't). For scripts, set `api_key` and send `Authorization: Bearer <key>` or
`X-Api-Key: <key>`. Password login returns a 24 h session token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth \
        -H 'Content-Type: application/json' -d '{"password":"…"}' | jq -r .token)
curl -s http://localhost:8080/api/stats/summary -H "Authorization: Bearer $TOKEN"
```

## API

Everything in the web UI is this REST API — anything you do by hand, a script can
too. Base URL `http://127.0.0.1:8080`, all under `/api`, behind auth when configured.

```
GET/POST/DELETE  /api/auth                     session status · log in · log out

GET    /api/stats/summary                      live counters
GET    /api/stats/timeseries                   24 h, 144 × 10 min buckets
GET    /api/stats/top-blocked|top-domains|top-clients
GET    /api/stats/system                       host/process metrics
GET    /api/queries        DELETE /api/queries query log (filterable) · clear
GET    /api/logs                               recent in-memory server logs

GET    /api/clients                            clients grouped by name (IPs + MACs)
GET/POST/DELETE  /api/clients/aliases[/{ip}]   manual client aliases

GET/POST  /api/blocklist/whitelist|blacklist   list · add (exact or *.wildcard)
DELETE    /api/blocklist/whitelist|blacklist/{domain}
GET    /api/blocklist/check/{domain}           why-blocked: which list/rule matched

GET/POST  /api/lists      PATCH/DELETE /api/lists/{name}    subscriptions
POST   /api/lists/refresh · /api/lists/{name}/refresh

GET/POST  /api/custom-records   DELETE /api/custom-records/{domain}

GET    /api/proxy   PUT /api/proxy             selective-routing config (secrets redacted)

GET    /api/tools/resolve?name=&type=          DNS lookup (any record type)
GET    /api/tools/whois?query=                 WHOIS

GET    /api/settings   PATCH /api/settings      config (secrets redacted; restart-fields flagged)
GET    /api/update/check   POST /api/update/server|web
```

## More

- **Deployment & Docker, updates, service install** → [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- **Build from source, the CI gate, contributing** → [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- **Full guide & API reference** → [ferrite.me/docs](https://ferrite.me/docs.html) · [ferrite.me/api](https://ferrite.me/api.html)
- **Web UI** → [ferrite-web](https://github.com/syntlyx/ferrite-web)

## Data files

All under `~/.local/share/ferrite/`:

| File             | Contents                                                       |
| ---------------- | -------------------------------------------------------------- |
| `ferrite.db`     | SQLite — query log, stats, whitelist/blacklist, custom records |
| `blocklist.fst`  | Compiled blocklist (rebuilt on list changes)                   |
| `lists/<name>.*` | Per-list parsed-domain cache                                   |
| `state.bin`      | Warm-restart snapshot (DNS cache + counters)                   |
| `web/`           | Web UI static files                                            |

## License

MIT
