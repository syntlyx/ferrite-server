#!/usr/bin/env sh
# ferrite — install script
# Downloads pre-built Linux binaries from GitHub Releases and sets up the system service.
#
# Usage (Linux, run as root):
#   curl -fsSL https://raw.githubusercontent.com/syntlyx/ferrite-server/main/install.sh | sudo sh
#
# Or download and inspect first:
#   curl -fsSL https://raw.githubusercontent.com/syntlyx/ferrite-server/main/install.sh -o install.sh
#   sudo sh install.sh

set -eu

# ── Config ────────────────────────────────────────────────────────────────────

GITHUB_BASE_URL="${GITHUB_BASE_URL:-https://github.com}"
GITHUB_API_BASE="${GITHUB_API_BASE:-https://api.github.com}"
GITHUB_OWNER="${GITHUB_OWNER:-syntlyx}"
GITHUB_REPO_SERVER="${GITHUB_REPO_SERVER:-ferrite-server}"
GITHUB_REPO_WEB="${GITHUB_REPO_WEB:-ferrite-web}"

BIN_DIR="/usr/local/bin"
SERVICE_UPDATE_BIN_DIR="/usr/local/lib/ferrite/bin"
CONFIG_DIR="/etc/ferrite"
DATA_DIR="/var/lib/ferrite"
WEB_PARENT="/usr/share/ferrite"
WEB_DIR="${WEB_PARENT}/web"
SERVICE_USER="ferrite"
SERVICE_GROUP="ferrite"
SYSTEMD_SERVICE="/etc/systemd/system/ferrite.service"
OPENRC_SERVICE="/etc/init.d/ferrite"

# ── Colors ────────────────────────────────────────────────────────────────────

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

info()  { printf "${BLUE}→${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}✓${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}!${NC} %s\n" "$*"; }
die()   { printf "${RED}✗${NC} %s\n" "$*" >&2; exit 1; }
bold()  { printf "${BOLD}%s${NC}\n" "$*"; }

# ── Checks ────────────────────────────────────────────────────────────────────

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo sh install.sh"

for cmd in curl tar; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required tool not found: $cmd"
done

# ── Platform detection ────────────────────────────────────────────────────────

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Asset names use Rust target triples — must match current_platform_target() in updater/server.rs.
detect_asset_pattern() {
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)           printf "x86_64-unknown-linux-musl"  ;;
        Linux-aarch64)          printf "aarch64-unknown-linux-musl" ;;
        *) die "Unsupported platform: $(uname -s) $(uname -m). The installer currently supports Linux x86_64/arm64 only." ;;
    esac
}
ASSET_PATTERN=$(detect_asset_pattern)

# Human-friendly name for display only.
detect_platform_display() {
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)           printf "linux-x86_64"  ;;
        Linux-aarch64)          printf "linux-arm64"   ;;
        *)                      printf "unknown"        ;;
    esac
}
PLATFORM=$(detect_platform_display)

# Detect Alpine Linux.
IS_ALPINE=false
[ -f /etc/alpine-release ] && IS_ALPINE=true

# Detect init system.
detect_init_system() {
    if [ -d /run/systemd/system ] || (command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1); then
        printf "systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        printf "openrc"
    else
        printf "none"
    fi
}
INIT_SYSTEM=$(detect_init_system)

if [ "$OS" = "linux" ] && { [ "$INIT_SYSTEM" = "systemd" ] || [ "$INIT_SYSTEM" = "openrc" ]; }; then
    SERVICE_BIN_DIR="$SERVICE_UPDATE_BIN_DIR"
else
    SERVICE_BIN_DIR="$BIN_DIR"
fi
SERVICE_BIN="${SERVICE_BIN_DIR}/ferrite"
PUBLIC_BIN="${BIN_DIR}/ferrite"

# ── Release helpers ───────────────────────────────────────────────────────────

release_token() {
    if [ -n "${FERRITE_RELEASE_TOKEN:-}" ]; then
        printf '%s' "$FERRITE_RELEASE_TOKEN"
    elif [ -n "${GITHUB_TOKEN:-}" ]; then
        printf '%s' "$GITHUB_TOKEN"
    elif [ -n "${GITEA_TOKEN:-}" ]; then
        printf '%s' "$GITEA_TOKEN"
    fi
}

release_latest() {
    token=$(release_token)
    if [ -n "$token" ]; then
        curl -fsSL \
            -H "Accept: application/json" \
            -H "Authorization: Bearer ${token}" \
            "${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/$1/releases/latest"
    else
        curl -fsSL \
            -H "Accept: application/json" \
            "${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/$1/releases/latest"
    fi
}

release_asset_url() {
    release_asset_field "$1" "$2" url
}

release_asset_digest() {
    release_asset_field "$1" "$2" digest
}

release_asset_field() {
    # Use awk over GitHub's release JSON to avoid a jq dependency.
    printf '%s\n' "$1" | tr "," "\n" | awk -v pattern="$2" -v want="$3" '
        function json_value(line) {
            sub(/^[^:]*:[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)
            return line
        }

        function maybe_emit() {
            target = name " " url
            if (url != "" && target ~ pattern && name !~ /\.sha256$/ && url !~ /\.sha256$/) {
                if (want == "url") {
                    print url
                    exit
                }
                if (want == "digest" && digest != "") {
                    print digest
                    exit
                }
            }
        }

        /"name"[[:space:]]*:/ {
            name = json_value($0)
            url = ""
            digest = ""
        }

        /"browser_download_url"[[:space:]]*:/ {
            url = json_value($0)
            maybe_emit()
        }

        /"digest"[[:space:]]*:/ {
            digest = json_value($0)
            maybe_emit()
        }
    '
}

release_tag() {
    printf '%s' "$1" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -1
}

release_version() {
    printf '%s' "$1" | sed 's/^v//'
}

download_asset() {
    token=$(release_token)
    if [ -n "$token" ]; then
        curl -fL --progress-bar -H "Authorization: Bearer ${token}" "$1" -o "$2"
    else
        curl -fL --progress-bar "$1" -o "$2"
    fi
}

normalize_sha256() {
    printf '%s\n' "$1" | grep -Eo '[A-Fa-f0-9]{64}' | head -1 | tr '[:upper:]' '[:lower:]'
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        return 1
    fi
}

verify_download_sha256() {
    file="$1"
    expected="$2"
    label="$3"
    [ -n "$expected" ] || return 0

    actual=$(sha256_file "$file") || {
        warn "No SHA256 tool found; skipping checksum verification for ${label}."
        return 0
    }

    [ "$actual" = "$expected" ] || die "${label} checksum mismatch: expected ${expected}, got ${actual}"
}

# ── Install server binary ─────────────────────────────────────────────────────

install_server() {
    bold "Installing ferrite server..."

    mkdir -p "$SERVICE_BIN_DIR" "$BIN_DIR"

    json=$(release_latest "$GITHUB_REPO_SERVER") \
        || die "Failed to fetch release info from GitHub. Check your network and release assets."

    version=$(release_tag "$json")
    [ -n "$version" ] || die "Could not determine release version."
    info "Latest version: ${version}"

    # Try tar.gz first (matches release.yml packaging), fall back to bare binary.
    is_archive=false
    asset_pattern="${ASSET_PATTERN}.*\\.tar\\.gz"
    url=$(release_asset_url "$json" "$asset_pattern")
    if [ -n "$url" ]; then
        is_archive=true
    else
        asset_pattern="${ASSET_PATTERN}"
        url=$(release_asset_url "$json" "$asset_pattern")
    fi

    [ -n "$url" ] || die "No release asset found for '${ASSET_PATTERN}'. The platform may not have a build yet."
    expected_sha=$(normalize_sha256 "$(release_asset_digest "$json" "$asset_pattern")")

    info "Downloading from: ${url}"
    tmp=$(mktemp)
    download_asset "$url" "$tmp"

    if [ -n "$expected_sha" ]; then
        verify_download_sha256 "$tmp" "$expected_sha" "Server archive"
    else
        warn "GitHub release did not expose a SHA256 digest for the server asset; skipping checksum verification."
    fi

    if $is_archive; then
        # Extract ferrite binary from the archive. Uses a temp dir for BusyBox tar
        # compatibility (Alpine) — avoids GNU tar-only flags like --wildcards and -O.
        tmp_dir=$(mktemp -d)
        tar -xzf "$tmp" -C "$tmp_dir"
        bin_path=$(find "$tmp_dir" -name 'ferrite' -type f | head -1)
        [ -n "$bin_path" ] || die "Could not find 'ferrite' binary in the release archive."
        install -m 755 "$bin_path" "$SERVICE_BIN"
        rm -rf "$tmp_dir" "$tmp"
    else
        install -m 755 "$tmp" "$SERVICE_BIN"
        rm -f "$tmp"
    fi

    if [ "$SERVICE_BIN" != "$PUBLIC_BIN" ]; then
        ln -sfn "$SERVICE_BIN" "$PUBLIC_BIN"
    fi

    if [ -n "$expected_sha" ]; then
        printf '%s\n' "$expected_sha" > "${SERVICE_BIN}.sha256"
        if [ "$SERVICE_BIN" != "$PUBLIC_BIN" ]; then
            ln -sfn "${SERVICE_BIN}.sha256" "${PUBLIC_BIN}.sha256"
        fi
    else
        rm -f "${SERVICE_BIN}.sha256" "${PUBLIC_BIN}.sha256"
    fi

    ok "Installed ferrite ${version} → ${SERVICE_BIN}"
    if [ "$SERVICE_BIN" != "$PUBLIC_BIN" ]; then
        ok "CLI link: ${PUBLIC_BIN} → ${SERVICE_BIN}"
    fi
}

# ── Install web UI ────────────────────────────────────────────────────────────

install_web() {
    bold "Installing ferrite web UI..."

    json=$(release_latest "$GITHUB_REPO_WEB" 2>/dev/null) || {
        warn "Could not fetch web UI release (repo may not have releases yet). Skipping."
        return 0
    }

    version=$(release_tag "$json")
    [ -n "$version" ] || { warn "No web UI release found. Skipping."; return 0; }
    info "Latest web UI version: ${version}"
    installed_version=$(release_version "$version")

    asset_pattern="\\.tar\\.gz"
    url=$(release_asset_url "$json" "$asset_pattern")
    if [ -z "$url" ]; then
        asset_pattern="\\.zip"
        url=$(release_asset_url "$json" "$asset_pattern")
    fi
    [ -n "$url" ] || { warn "No web UI asset found in release. Skipping."; return 0; }
    expected_sha=$(normalize_sha256 "$(release_asset_digest "$json" "$asset_pattern")")

    info "Downloading from: ${url}"
    tmp=$(mktemp)
    download_asset "$url" "$tmp"

    if [ -n "$expected_sha" ]; then
        verify_download_sha256 "$tmp" "$expected_sha" "Web UI archive"
    else
        warn "GitHub release did not expose a SHA256 digest for the web UI asset; skipping checksum verification."
    fi

    rm -rf "$WEB_DIR"
    mkdir -p "$WEB_DIR"

    if tar -tzf "$tmp" | head -1 | grep -q '/'; then
        tar -xzf "$tmp" -C "$WEB_DIR" --strip-components=1
    else
        tar -xzf "$tmp" -C "$WEB_DIR"
    fi
    rm -f "$tmp"

    printf '%s\n' "$installed_version" > "${WEB_DIR}.version"
    if [ -n "$expected_sha" ]; then
        printf '%s\n' "$expected_sha" > "${WEB_DIR}.sha256"
    else
        rm -f "${WEB_DIR}.sha256"
    fi

    ok "Installed web UI ${version} → ${WEB_DIR}"
}

# ── Create system user ────────────────────────────────────────────────────────

group_exists() {
    getent group "$1" >/dev/null 2>&1 || grep -q "^$1:" /etc/group 2>/dev/null
}

ensure_linux_group() {
    group_exists "$SERVICE_GROUP" && return 0

    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system "$SERVICE_GROUP"
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup -S "$SERVICE_GROUP" 2>/dev/null || addgroup "$SERVICE_GROUP"
    else
        die "Could not create group '${SERVICE_GROUP}': groupadd/addgroup not found."
    fi
    ok "Created system group: ${SERVICE_GROUP}"
}

ensure_linux_user_group() {
    if command -v usermod >/dev/null 2>&1; then
        usermod -g "$SERVICE_GROUP" "$SERVICE_USER" 2>/dev/null || true
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup "$SERVICE_USER" "$SERVICE_GROUP" 2>/dev/null || true
    fi
}

service_owner() {
    if [ "$OS" = "linux" ]; then
        printf "%s:%s" "$SERVICE_USER" "$SERVICE_GROUP"
    else
        printf "%s" "$SERVICE_USER"
    fi
}

configured_api_port() {
    awk '
        /^\[api\]/ { in_api = 1; next }
        /^\[/ { in_api = 0 }
        in_api && /^[[:space:]]*bind_addr[[:space:]]*=/ {
            value = $0
            sub(/^[^"]*"/, "", value)
            sub(/".*$/, "", value)
            sub(/^.*:/, "", value)
            if (value ~ /^[0-9]+$/) {
                print value
                exit
            }
        }
    ' "${CONFIG_DIR}/config.toml"
}

create_user() {
    if [ "$OS" = "linux" ]; then
        ensure_linux_group

        if id "$SERVICE_USER" >/dev/null 2>&1; then
            ensure_linux_user_group
            ok "System user '${SERVICE_USER}' already exists"
            return 0
        fi
        if $IS_ALPINE; then
            # Alpine uses BusyBox adduser (no useradd).
            adduser -S -D -H -s /sbin/nologin -h "$DATA_DIR" -G "$SERVICE_GROUP" "$SERVICE_USER"
        else
            useradd --system --gid "$SERVICE_GROUP" --no-create-home --shell /usr/sbin/nologin \
                --home-dir "$DATA_DIR" "$SERVICE_USER"
        fi
        ok "Created system user: ${SERVICE_USER}"
    fi
}

# ── Directories and config ────────────────────────────────────────────────────

install_dirs_and_config() {
    bold "Setting up directories and config..."

    mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$WEB_PARENT" "$WEB_DIR" "$SERVICE_BIN_DIR"

    if [ -f "${CONFIG_DIR}/config.toml" ]; then
        ok "Config already exists at ${CONFIG_DIR}/config.toml — skipping (not overwritten)"
    else
        cat > "${CONFIG_DIR}/config.toml" << EOF
# ferrite configuration
# Edit to your needs, then restart the ferrite service.

web_dir = "${WEB_DIR}"
custom_records = []

[dns]
bind_addr = "[::]:53"
cache_size = 10000
min_ttl = 360
max_ttl = 3600
log_ignore = [
    "fe.te",
    "*.arpa",
    "*.local",
    "*.localdomain",
]

[[upstream]]
type = "https"
url = "https://cloudflare-dns.com/dns-query"
bootstrap_ip = "1.1.1.1"

[storage]
backend            = "sqlite"
path               = "${DATA_DIR}/ferrite.db"
log_retention_days = 30

[api]
bind_addr = "0.0.0.0:80"

[panel]
enabled = true
domain = "fe.te"

[blocklist]
whitelist      = []
wildcard_block = []

[[blocklist.lists]]
name    = "StevenBlack"
url     = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
enabled = true
EOF
        ok "Config written to ${CONFIG_DIR}/config.toml"
    fi

    chown -R "$(service_owner)" "$CONFIG_DIR" "$DATA_DIR" "$WEB_PARENT" 2>/dev/null || true
    chmod 750 "$CONFIG_DIR" "$DATA_DIR" "$WEB_PARENT" "$WEB_DIR"
    chmod 640 "${CONFIG_DIR}/config.toml"

    if [ "$SERVICE_BIN_DIR" != "$BIN_DIR" ]; then
        chown -R "$(service_owner)" "$SERVICE_BIN_DIR" 2>/dev/null || true
        chmod 755 "$SERVICE_BIN_DIR"
    fi
}

# ── systemd-resolved conflict (Debian/Ubuntu) ────────────────────────────────

fix_resolved() {
    [ "$OS" = "linux" ] || return 0
    [ "$INIT_SYSTEM" = "systemd" ] || return 0
    systemctl is-active --quiet systemd-resolved 2>/dev/null || return 0

    if ss -ulnp 2>/dev/null | grep -q ':53 ' \
        || ss -tlnp 2>/dev/null | grep -q ':53 '; then
        info "Disabling systemd-resolved stub listener (it occupies port 53)..."
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/ferrite.conf << 'EOF'
[Resolve]
DNSStubListener=no
EOF
        systemctl restart systemd-resolved
        ok "systemd-resolved stub listener disabled"
    fi
}

# ── Systemd service ───────────────────────────────────────────────────────────

install_systemd() {
    [ "$OS" = "linux" ] || return 0
    [ "$INIT_SYSTEM" = "systemd" ] || return 0

    bold "Installing systemd service..."

    cat > "$SYSTEMD_SERVICE" << EOF
[Unit]
Description=Ferrite DNS ad-blocker
Documentation=${GITHUB_BASE_URL}/${GITHUB_OWNER}/${GITHUB_REPO_SERVER}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}

ExecStart=${SERVICE_BIN}
Restart=always
RestartSec=5
TimeoutStopSec=30

# Allow binding to port 53 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${CONFIG_DIR} ${WEB_PARENT} ${SERVICE_BIN_DIR}
RuntimeDirectory=ferrite

StandardOutput=journal
StandardError=journal
SyslogIdentifier=ferrite

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ferrite
    ok "systemd service installed and enabled"
}

# ── OpenRC service (Alpine) ───────────────────────────────────────────────────

install_openrc() {
    [ "$OS" = "linux" ] || return 0
    [ "$INIT_SYSTEM" = "openrc" ] || return 0

    bold "Installing OpenRC service..."

    cat > "$OPENRC_SERVICE" << EOF
#!/sbin/openrc-run

name="ferrite"
description="Ferrite DNS ad-blocker"
supervisor=supervise-daemon
command="${SERVICE_BIN}"
command_user="${SERVICE_USER}:${SERVICE_GROUP}"
capabilities="^cap_net_bind_service"
respawn_delay=5
respawn_max=3
respawn_period=60
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="/var/log/ferrite.log"
error_log="/var/log/ferrite.log"

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$OPENRC_SERVICE"

    rc-update add ferrite default
    ok "OpenRC service installed and enabled (default runlevel, supervise-daemon)"
}

# ── Firewall: open port 53 ────────────────────────────────────────────────────

open_port_53() {
    [ "$OS" = "linux" ] || return 0

    bold "Opening port 53 in firewall..."

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow 53/udp comment "ferrite DNS" >/dev/null
        ufw allow 53/tcp comment "ferrite DNS" >/dev/null
        ok "UFW: port 53/udp and 53/tcp allowed"

    elif command -v firewall-cmd >/dev/null 2>&1 \
        && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --add-port=53/udp >/dev/null
        firewall-cmd --permanent --add-port=53/tcp >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: port 53/udp and 53/tcp allowed"

    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null \
            || iptables -I INPUT -p udp --dport 53 -j ACCEPT
        iptables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null \
            || iptables -I INPUT -p tcp --dport 53 -j ACCEPT
        warn "iptables: port 53 opened (not persistent). To persist:"
        if $IS_ALPINE; then
            warn "  apk add iptables && rc-update add iptables boot && rc-service iptables save"
        else
            warn "  Debian/Ubuntu: apt install iptables-persistent && netfilter-persistent save"
            warn "  RHEL/Rocky:    service iptables save"
        fi

    else
        warn "No active firewall detected. Make sure port 53 is accessible on your network interface."
    fi
}

# ── Start / restart service ───────────────────────────────────────────────────

start_service() {
    if [ "$OS" = "linux" ]; then
        bold "Starting ferrite service..."

        case "$INIT_SYSTEM" in
            systemd)
                if systemctl is-active --quiet ferrite 2>/dev/null; then
                    systemctl restart ferrite
                else
                    systemctl start ferrite
                fi
                sleep 1
                if systemctl is-active --quiet ferrite; then
                    ok "Service is running"
                else
                    warn "Service may have failed to start. Check: journalctl -u ferrite -n 30"
                fi
                ;;
            openrc)
                rc-service ferrite start
                sleep 1
                if rc-service ferrite status 2>/dev/null | grep -q "started"; then
                    ok "Service is running"
                else
                    warn "Service may have failed to start. Check: cat /var/log/ferrite.log"
                fi
                ;;
            *)
                warn "Unknown init system. Start manually: ${SERVICE_BIN}"
                ;;
        esac
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    echo
    bold "  Ferrite DNS ad-blocker — installer"
    printf "  ════════════════════════════════════\n"
    echo
    info "Platform: ${PLATFORM} (${INIT_SYSTEM})"
    echo

    install_server
    echo
    install_web
    echo
    create_user
    install_dirs_and_config
    echo
    fix_resolved
    case "$OS" in
        linux)
            case "$INIT_SYSTEM" in
                systemd) install_systemd ;;
                openrc)  install_openrc  ;;
                *)       warn "Unknown init system — skipping service setup. Start manually: ${SERVICE_BIN}" ;;
            esac
            ;;
    esac
    echo
    open_port_53
    echo
    start_service

    # Determine LAN IP for display.
    if [ "$OS" = "linux" ]; then
        lan_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')
    else
        lan_ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || printf "localhost")
    fi
    lan_ip="${lan_ip:-localhost}"
    api_port=$(configured_api_port)
    api_port="${api_port:-80}"

    echo
    bold "  ✓ Installation complete!"
    echo
    printf "  Config:    %s/config.toml\n" "$CONFIG_DIR"
    printf "  Database:  %s/ferrite.db\n"  "$DATA_DIR"
    printf "  Web UI:    http://%s:%s\n" "$lan_ip" "$api_port"
    echo
    printf "  Next steps:\n"
    printf "    1. Point your router's DNS to %s\n" "$lan_ip"
    printf "    2. Run 'ferrite setup' to auto-detect your local network zones\n"
    printf "    3. Run 'ferrite passwd' to set a web UI password\n"
    echo
    case "$INIT_SYSTEM" in
        systemd)
            printf "  Service commands:\n"
            printf "    systemctl status ferrite\n"
            printf "    journalctl -u ferrite -f\n"
            printf "    systemctl restart ferrite\n"
            ;;
        openrc)
            printf "  Service commands:\n"
            printf "    rc-service ferrite status\n"
            printf "    tail -f /var/log/ferrite.log\n"
            printf "    rc-service ferrite restart\n"
            ;;
    esac
    echo
}

main "$@"
