# Deployment & operations

Operator-level detail that the [README](../README.md) keeps out of the way.

## Docker (GHCR)

Images are published to GitHub Container Registry, not Docker Hub:

```bash
docker pull ghcr.io/syntlyx/ferrite-server:latest

docker run -d --name ferrite \
  --restart unless-stopped \
  -p 53:53/tcp -p 53:53/udp \
  -p 80:80/tcp \
  -v ferrite-data:/var/lib/ferrite \
  ghcr.io/syntlyx/ferrite-server:latest
```

- Docker publishes TCP and UDP with separate rules — keep both DNS rules on the
  same host/container port (`53:53`).
- If host port 80 is taken, keep the container on 80 and remap, e.g. `-p 8080:80`.
- If the runtime strips capabilities and port 53 won't bind, add
  `--cap-add=NET_BIND_SERVICE`.

**What the image does.** A small Alpine runtime. On startup the entrypoint
downloads the latest server + web release assets, verifies their `.sha256`
sidecars when available, installs them under `/var/lib/ferrite`, and runs ferrite
as the unprivileged `ferrite` user. Default container config: DNS on `0.0.0.0:53`,
API/web on `0.0.0.0:80`, data + binary + web under `/var/lib/ferrite`. **Mount
`/var/lib/ferrite`** so config, data, and updates survive restarts.

**Application updates without a new image.** Restarting the container after a
release is enough — the entrypoint refreshes `/var/lib/ferrite/bin/ferrite` and
`/var/lib/ferrite/web` when a newer release (or a same-version checksum change)
is available. `POST /api/update/server` also works: it replaces the mounted
binary and exits so Docker restarts on the new one (use `--restart unless-stopped`).

**Environment variables.**

| Var                                      | Purpose                                                            |
| ---------------------------------------- | ------------------------------------------------------------------ |
| `FERRITE_SERVER_VERSION`                 | Pin the server release at startup (e.g. `0.1.4`).                  |
| `FERRITE_WEB_VERSION`                    | Pin the web release; defaults to the server version.               |
| `FERRITE_RELEASE_TOKEN` / `GITHUB_TOKEN` | Private repos / higher GitHub API limits.                          |
| `FERRITE_PANEL_IP`                       | Host LAN IP for the `fe.te` A record (bridge mode can't infer it). |
| `FERRITE_PANEL_URL`                      | Display URL in startup logs when the UI is on a non-80 host port.  |

Leave the version vars unset to track latest.

**Bridge mode caveats.** Inside a bridge network ferrite sees the container IP,
not the LAN, so:

- Set `FERRITE_PANEL_IP=<host LAN IP>` for the `fe.te` shortcut.
- Configure the reverse-DNS zone manually for router-provided client hostnames:

```json
{
  "zones": [{ "name": "1.168.192.in-addr.arpa", "upstream": "192.168.1.1:53" }]
}
```

Container system stats reflect the container/VM view: CPU/memory work; CPU
temperature is usually `null` unless the host exposes sensor files.

Build the image locally:

```bash
docker build -t ferrite:local .
```

## Service install (systemd / OpenRC)

`install.sh` fetches the server + web release assets, installs them under
`/var/lib/ferrite`, and registers a service. It runs ferrite from
`/usr/local/lib/ferrite/bin/ferrite` and leaves `/usr/local/bin/ferrite` as a CLI
symlink. That service binary is writable by the `ferrite` service user, so
`POST /api/update/server` can replace it from the UI; ferrite then exits and the
supervisor restarts it on the new binary. OpenRC uses `supervise-daemon` with
ambient `cap_net_bind_service`, so the bind capability survives a binary replace.

Re-run the installer to update a source/macOS/root-owned install:

```bash
curl -fsSL https://raw.githubusercontent.com/syntlyx/ferrite-server/main/install.sh | sudo sh
```

## Updates

- `POST /api/update/web` updates the web UI in place (the web dir is writable by
  the service user).
- Update checks prefer GitHub's release API (it exposes asset SHA256 digests); on
  rate-limit, ferrite falls back to public release URLs + `.sha256` sidecars. Set
  `FERRITE_RELEASE_TOKEN` / `GITHUB_TOKEN` for private repos or higher limits.
- Web releases carry a compatibility manifest — ferrite only offers the newest web
  bundle compatible with the running server (so `0.1.x` web stays on `0.1.x`
  server).
- The server refreshes update state hourly in the background; the UI reads the
  cache, and "Check updates" forces a live refresh.

## Privileged ports

Binding `:53` (and `:80`/`:443` for the panel + selective routing) needs
privilege. Deploy with `CAP_NET_BIND_SERVICE` rather than running as root. The
WireGuard egress is userspace (boringtun + smoltcp) and needs **no** extra
network capability or TUN device.
