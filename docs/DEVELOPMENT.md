# Development

For contributors and people building from source.

## Build

```bash
cargo build --release
cp target/release/ferrite /usr/local/bin/ferrite
```

Requires **Rust 1.88+**. Key dependencies: `tokio`, `axum`, `hickory-resolver`
(DoT/DoH/DoQ), `boringtun` + `smoltcp` (userspace WireGuard), `tokio-rustls`
(tunneled DoT), `fst` (blocklist), `rusqlite` (storage), `argon2` (password
hashing).

The single binary contains the DNS server, blocklist engine, selective-routing /
tunnel egresses, REST API, and the static web UI.

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
