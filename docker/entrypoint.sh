#!/usr/bin/env sh
set -eu

FERRITE_HOME="${HOME:-/var/lib/ferrite}"
CONFIG_DIR="${FERRITE_HOME}/.config/ferrite"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
DEFAULT_CONFIG="/etc/ferrite/config.toml"

mkdir -p "${CONFIG_DIR}" "${FERRITE_HOME}/.local/share/ferrite"

if [ ! -f "${CONFIG_FILE}" ]; then
    cp "${DEFAULT_CONFIG}" "${CONFIG_FILE}"
fi

if [ "$(id -u)" -eq 0 ]; then
    chown -R ferrite:ferrite "${FERRITE_HOME}"
    exec gosu ferrite:ferrite /usr/bin/tini -- /usr/local/bin/ferrite "$@"
fi

exec /usr/bin/tini -- /usr/local/bin/ferrite "$@"
