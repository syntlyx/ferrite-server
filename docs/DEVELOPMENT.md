# Development

For contributors and people building from source.

## Build

```bash
cargo build --release
cp target/release/ferrite /usr/local/bin/ferrite
```

Requires **Rust 1.97+**. Key dependencies: `tokio`, `axum`, `hickory-resolver`
(DoT/DoH/DoQ), `boringtun` + `smoltcp` (userspace WireGuard), `tokio-rustls`
(tunneled DoT), `fst` (blocklist), `rusqlite` (storage), `argon2` (password
hashing).

The single binary contains the DNS server, blocklist engine, selective-routing /
tunnel egresses, REST API, and the static web UI.

## Workspace layout

The code is a Cargo workspace under `crates/`. `cargo build` at the root builds
the binary (`default-members = ["crates/ferrite"]`); `cargo test --all` covers
every crate. Dependencies point strictly downward — a crate may only use the
ones above it in this list:

```
ferrite            bin: main.rs + setup.rs; wires everything together
├── ferrite-api    axum REST API + static web-UI handler
└── ferrite-app    AppState, init(), per-subsystem ctx builders, warm-restart snapshot
    ├── ferrite-proxy     egress backends (direct/evasion/socks5/wireguard), SNI/Host
    │                     splice, routing rules, breakers, alerts, probes
    ├── ferrite-dns       cache, custom records, query pipeline, UDP/TCP servers
    ├── ferrite-updater   GitHub release checks + self-update
    ├── ferrite-stats     live counters, timeseries, top-lists, stats writer
    ├── ferrite-clients   IP↔MAC registry, PTR/mDNS resolution, aliases
    ├── ferrite-blocklist FST engine, adblock parser, list refresh, decision cache
    ├── ferrite-upstream  resolver pool, DoT/DoH/DoQ, tunneled resolver
    ├── ferrite-storage   SQLite query log + rollups
    └── ferrite-core      errors, config, shared record types, IP/MAC utils, log ring
```

Two former in-crate cycles are now trait seams: `ferrite-proxy` implements
`ferrite-upstream`'s `EgressConnector` (so upstream DNS can ride a tunnel without
depending on the proxy) and `ferrite-dns`'s `DnsInterceptor` (so the DNS pipeline
can route without depending on the proxy). Each subsystem takes a small context
struct (`DnsCtx`, `ProxyCtx`, `WriterCtx`, `UpdaterCtx`) built by `ferrite-app`,
rather than the whole `AppState`.

Third-party version and feature choices live once in `[workspace.dependencies]`
in the root `Cargo.toml`; member crates opt in with `<name>.workspace = true`.

## Local gate (run before pushing)

CI enforces all of these — `cargo build`/`clippy`/`test` do **not** catch
formatting, so run `fmt` too:

```bash
cargo fmt --all -- --check
cargo check --locked
cargo test --all --locked
cargo clippy --all-targets --locked -- -D warnings
cargo audit --deny warnings
sh -n install.sh
shellcheck install.sh
git diff --check
```

## Web UI

The web UI lives in a separate repo, [ferrite-web](https://github.com/syntlyx/ferrite-web)
(React + Vite + Tailwind). During frontend work, point a running ferrite at your
local build output instead of redeploying:

```bash
curl -s -X PATCH http://localhost:8080/api/settings \
     -H 'Content-Type: application/json' \
     -d '{"web_dir": "/path/to/ferrite-web/dist"}'
```

`POST /api/update/web` installs/updates the bundled web assets at runtime.

## Principles

- **No telemetry, ever.** ferrite makes no outbound calls of its own except the
  optional hourly GitHub update check and the blocklist fetches the user
  configures. Keep it that way.
- **No `.await` while holding a lock.** The hot paths (DNS, proxy) must never hold
  a `parking_lot`/`DashMap` guard across an `await` — that has frozen the runtime
  before. Copy the value out and drop the guard first.
- **Single binary, no root.** Userspace WireGuard, no TUN device. Don't add
  features that require root or a kernel interface to the core.
