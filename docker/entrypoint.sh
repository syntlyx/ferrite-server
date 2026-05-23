#!/usr/bin/env sh
set -eu

GITHUB_BASE_URL="${GITHUB_BASE_URL:-https://github.com}"
GITHUB_API_BASE="${GITHUB_API_BASE:-https://api.github.com}"
GITHUB_OWNER="${GITHUB_OWNER:-syntlyx}"
GITHUB_REPO_SERVER="${GITHUB_REPO_SERVER:-ferrite-server}"
GITHUB_REPO_WEB="${GITHUB_REPO_WEB:-ferrite-web}"
FERRITE_SERVER_VERSION="${FERRITE_SERVER_VERSION:-latest}"
FERRITE_WEB_VERSION="${FERRITE_WEB_VERSION:-${FERRITE_SERVER_VERSION}}"

FERRITE_HOME="${HOME:-/var/lib/ferrite}"
CONFIG_FILE="${FERRITE_HOME}/.config/ferrite/config.toml"
SERVER_BIN="${FERRITE_HOME}/bin/ferrite"
SERVER_VERSION="${SERVER_BIN}.version"
SERVER_SHA256="${SERVER_BIN}.sha256"
WEB_DIR="${FERRITE_HOME}/web"
WEB_VERSION="${FERRITE_HOME}/web.version"
WEB_SHA256="${FERRITE_HOME}/web.sha256"

info() { printf 'ferrite: %s\n' "$*"; }
warn() { printf 'ferrite: warning: %s\n' "$*" >&2; }
die() { printf 'ferrite: error: %s\n' "$*" >&2; exit 1; }

normalize_version() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^v//'
}

normalize_sha256() {
    printf '%s\n' "$1" | grep -Eo '[A-Fa-f0-9]{64}' | head -n 1 | tr '[:upper:]' '[:lower:]'
}

version_cmp() {
    awk -v a="$(normalize_version "$1")" -v b="$(normalize_version "$2")" '
        BEGIN {
            split(a, av, ".")
            split(b, bv, ".")
            for (i = 1; i <= 3; i++) {
                left = av[i] + 0
                right = bv[i] + 0
                if (left > right) { print 1; exit }
                if (left < right) { print -1; exit }
            }
            print 0
        }
    '
}

auth_header() {
    token="${FERRITE_RELEASE_TOKEN:-${GITHUB_TOKEN:-${GITEA_TOKEN:-}}}"
    [ -n "${token}" ] && printf 'Authorization: Bearer %s' "${token}"
}

curl_json() {
    header="$(auth_header)"
    if [ -n "${header}" ]; then
        curl -fsSL -H "Accept: application/json" -H "${header}" "$1"
    else
        curl -fsSL -H "Accept: application/json" "$1"
    fi
}

curl_file() {
    header="$(auth_header)"
    if [ -n "${header}" ]; then
        curl -fL --progress-bar -H "${header}" "$1" -o "$2"
    else
        curl -fL --progress-bar "$1" -o "$2"
    fi
}

release_tag() {
    repo="$1"
    requested="$2"

    case "${requested}" in
        "" | "latest")
            curl_json "${GITHUB_API_BASE%/}/repos/${GITHUB_OWNER}/${repo}/releases/latest" \
                | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                | head -n 1
            ;;
        v*) printf '%s' "${requested}" ;;
        *) printf 'v%s' "${requested}" ;;
    esac
}

target_triple() {
    case "$(uname -m)" in
        x86_64) printf 'x86_64-unknown-linux-musl' ;;
        aarch64 | arm64) printf 'aarch64-unknown-linux-musl' ;;
        *) die "unsupported container architecture: $(uname -m)" ;;
    esac
}

download_sha256() {
    tmp_sha="$(mktemp)"
    if curl_file "$1.sha256" "${tmp_sha}" >/dev/null 2>&1; then
        normalize_sha256 "$(cat "${tmp_sha}")"
    fi
    rm -f "${tmp_sha}"
}

verify_sha256() {
    file="$1"
    expected="$2"
    [ -n "${expected}" ] || return 0
    actual="$(sha256sum "${file}" | awk '{print $1}')"
    [ "${actual}" = "${expected}" ] || die "checksum mismatch for ${file}: expected ${expected}, got ${actual}"
}

needs_install() {
    marker="$1"
    version_file="$2"
    sha_file="$3"
    wanted_tag="$4"
    wanted_sha="$5"
    requested="$6"

    [ -e "${marker}" ] || return 0
    [ -f "${version_file}" ] || return 0

    current_version="$(cat "${version_file}")"
    wanted_version="$(normalize_version "${wanted_tag}")"
    cmp="$(version_cmp "${wanted_version}" "${current_version}")"

    case "${requested}" in
        "" | "latest")
            [ "${cmp}" -gt 0 ] && return 0
            [ "${cmp}" -lt 0 ] && return 1
            ;;
        *)
            [ "${wanted_version}" != "$(normalize_version "${current_version}")" ] && return 0
            ;;
    esac

    current_sha=""
    [ -f "${sha_file}" ] && current_sha="$(normalize_sha256 "$(cat "${sha_file}")")"
    [ -n "${wanted_sha}" ] && [ "${wanted_sha}" != "${current_sha}" ] && return 0

    return 1
}

install_server() {
    tag="$(release_tag "${GITHUB_REPO_SERVER}" "${FERRITE_SERVER_VERSION}")"
    if [ -z "${tag}" ]; then
        [ -x "${SERVER_BIN}" ] && { warn "server release check failed; using existing binary"; return 0; }
        die "could not resolve ferrite server release"
    fi

    target="$(target_triple)"
    asset="ferrite-${tag}-${target}.tar.gz"
    url="${GITHUB_BASE_URL%/}/${GITHUB_OWNER}/${GITHUB_REPO_SERVER}/releases/download/${tag}/${asset}"
    expected_sha="$(download_sha256 "${url}")"

    needs_install "${SERVER_BIN}" "${SERVER_VERSION}" "${SERVER_SHA256}" "${tag}" "${expected_sha}" "${FERRITE_SERVER_VERSION}" || return 0

    info "installing server ${tag}"
    tmp="$(mktemp)"
    tmp_dir="$(mktemp -d)"
    if ! curl_file "${url}" "${tmp}"; then
        rm -rf "${tmp}" "${tmp_dir}"
        [ -x "${SERVER_BIN}" ] && { warn "server download failed; using existing binary"; return 0; }
        die "could not download ferrite server ${tag}"
    fi
    verify_sha256 "${tmp}" "${expected_sha}"
    tar -xzf "${tmp}" -C "${tmp_dir}"
    [ -f "${tmp_dir}/ferrite" ] || die "server archive did not contain ferrite"

    cp "${tmp_dir}/ferrite" "${SERVER_BIN}.new"
    chmod 0755 "${SERVER_BIN}.new"
    mv "${SERVER_BIN}.new" "${SERVER_BIN}"
    printf '%s\n' "$(normalize_version "${tag}")" > "${SERVER_VERSION}"
    if [ -n "${expected_sha}" ]; then
        printf '%s\n' "${expected_sha}" > "${SERVER_SHA256}"
    else
        rm -f "${SERVER_SHA256}"
    fi
    rm -rf "${tmp}" "${tmp_dir}"
}

install_web() {
    tag="$(release_tag "${GITHUB_REPO_WEB}" "${FERRITE_WEB_VERSION}")"
    if [ -z "${tag}" ]; then
        [ -f "${WEB_DIR}/index.html" ] && { warn "web release check failed; using existing web UI"; return 0; }
        warn "could not resolve ferrite web release; starting without web UI"
        return 0
    fi

    url="${GITHUB_BASE_URL%/}/${GITHUB_OWNER}/${GITHUB_REPO_WEB}/releases/download/${tag}/dist.tar.gz"
    expected_sha="$(download_sha256 "${url}")"
    needs_install "${WEB_DIR}/index.html" "${WEB_VERSION}" "${WEB_SHA256}" "${tag}" "${expected_sha}" "${FERRITE_WEB_VERSION}" || return 0

    info "installing web ${tag}"
    tmp="$(mktemp)"
    tmp_dir="$(mktemp -d)"
    next_dir="${WEB_DIR}.new"
    if ! curl_file "${url}" "${tmp}"; then
        rm -rf "${tmp}" "${tmp_dir}" "${next_dir}"
        [ -f "${WEB_DIR}/index.html" ] && { warn "web download failed; using existing web UI"; return 0; }
        warn "could not download ferrite web ${tag}; starting without web UI"
        return 0
    fi
    verify_sha256 "${tmp}" "${expected_sha}"
    tar -xzf "${tmp}" -C "${tmp_dir}"

    rm -rf "${next_dir}"
    mkdir -p "${next_dir}"
    if [ -d "${tmp_dir}/dist" ]; then
        cp -a "${tmp_dir}/dist/." "${next_dir}/"
    else
        cp -a "${tmp_dir}/." "${next_dir}/"
    fi
    [ -f "${next_dir}/index.html" ] || { rm -rf "${next_dir}"; die "web archive did not contain index.html"; }

    rm -rf "${WEB_DIR}"
    mv "${next_dir}" "${WEB_DIR}"
    printf '%s\n' "$(normalize_version "${tag}")" > "${WEB_VERSION}"
    if [ -n "${expected_sha}" ]; then
        printf '%s\n' "${expected_sha}" > "${WEB_SHA256}"
    else
        rm -f "${WEB_SHA256}"
    fi
    rm -rf "${tmp}" "${tmp_dir}"
}

mkdir -p "$(dirname "${CONFIG_FILE}")" "$(dirname "${SERVER_BIN}")" "${FERRITE_HOME}/.local/share/ferrite"

if [ ! -f "${CONFIG_FILE}" ]; then
    cp /etc/ferrite/config.toml "${CONFIG_FILE}"
fi

install_server
install_web

if [ "$(id -u)" -eq 0 ]; then
    chown -R ferrite:ferrite "${FERRITE_HOME}"
    setcap cap_net_bind_service=+ep "${SERVER_BIN}" 2>/dev/null || \
        warn "could not set cap_net_bind_service on ${SERVER_BIN}; port 53 may require --cap-add=NET_BIND_SERVICE"
    exec su-exec ferrite:ferrite "${SERVER_BIN}" "$@"
fi

exec "${SERVER_BIN}" "$@"
