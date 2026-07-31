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
ambient `cap_net_bind_service` + `cap_net_admin`, so the capabilities survive a
binary replace.

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

## Privileged ports & capabilities

Binding `:53` (and `:80`/`:443` for the panel + selective routing) needs
privilege. Deploy with `CAP_NET_BIND_SERVICE` rather than running as root.

WireGuard egresses have two backends, chosen automatically per host:

- **kernel** (preferred; Linux): ferrite creates a real `wireguard` netdev over
  netlink plus fwmark policy routing — the main routing table is never touched.
  The kernel does the crypto (multicore, GSO/GRO) and TCP autotuning, so tunnel
  throughput scales to the hardware. Requires `CAP_NET_ADMIN` (the
  installer's service units grant it; in Docker pass `--cap-add=NET_ADMIN`) and
  the `wireguard` kernel module — in Docker the module must be present on the
  **host** kernel. The startup log states which backend was picked and why.
- **userspace** (fallback; everywhere): boringtun + smoltcp, fully in-process,
  no extra capability or TUN device. Single-core crypto and a static
  per-connection window (`buffer_kb`) cap its throughput — fine for browsing,
  not for line-rate media.

An egress can pin a backend with `backend = "kernel" | "userspace"` (default
`auto`); a pinned `kernel` fails loudly instead of degrading when the host
can't provide it.

## Tunnel throughput on a low-power box

WireGuard encrypts with ChaCha20-Poly1305, which no consumer SoC accelerates in
hardware — it is CPU work, and on small ARM cores it, not ferrite, is what
limits tunnel throughput. Measured on a NanoPi R5C (Rockchip RK3568, 4× Cortex-A55
@ 2 GHz, 2.5 GbE): a saturated tunnel sits at roughly 60 % across all four cores
while ferrite itself accounts for ~2 % of the machine. Expect a few hundred Mbit/s
through a tunnel on this class of hardware regardless of the port speed — 2.5 GbE
ports route unencrypted traffic at line rate, but cannot carry it encrypted.

**Find out whose CPU it is** before tuning anything. During the load, run
`top -bn1 | head -12` and read the summary line:

- `0 % usr` means no userspace computation — ferrite is not the consumer. The
  relay uses `splice(2)`, so proxied bytes never enter userspace.
- `sy` + `sirq` with `[kworker/N:x-wg-]` and `ksoftirqd` at the top of the
  process list is kernel tunnel crypto and the network stack. That is the
  hardware's cost; no ferrite setting reduces it.

Two host-level checks are worth making, in this order:

1. **Accelerated crypto.** `grep -i chacha /proc/crypto` must list a `-neon`
   (arm64) or `-avx`/`-simd` (x86) driver. Generic C ChaCha20 costs several
   times more CPU; if only `chacha20-generic` appears, load the accelerated
   module (`modprobe chacha-neon`).
2. **Receive processing spread across cores.** `grep -iE 'eth|r816' /proc/interrupts`
   — if the NIC's interrupt counts sit in the CPU0 column only, one core does
   all packet reception and becomes the ceiling while the others idle. Enable
   RPS (mask below excludes CPU0, which still takes the hard interrupt):

   ```sh
   for q in /sys/class/net/eth0/queues/rx-*/rps_cpus; do echo e > "$q"; done
   ```

   Verify with `grep NET_RX /proc/softirqs` — counters on the other CPUs should
   start rising. The setting is not persistent; on Alpine put the loop in an
   executable `/etc/local.d/rps.start` (`rc-update add local default`), on
   systemd hosts in a `tmpfiles.d` entry or a small unit.

The CPU frequency governor is worth a glance but is usually not the problem:
read `/sys/devices/system/cpu/cpufreq/policy*/scaling_cur_freq` *while traffic
flows*, not at idle. A low value at idle is normal — even the slow-ramping
`conservative` governor reached the full 1.99 GHz under load on the box above.
