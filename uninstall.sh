#!/usr/bin/env bash
set -euo pipefail

# M.A.R.K. Sentinel Agent — Linux/macOS Uninstaller

INSTALL_PREFIX="/opt/sentinel"
CONFIG_DIR="/etc/sentinel"
SERVICE_NAME="sentinel-agent"
PLIST_PATH="/Library/LaunchDaemons/io.hash.sentinel-agent.plist"
SYSTEMD_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: this uninstaller must be run as root (use sudo)." >&2
    exit 1
fi

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        *)       echo "unknown" ;;
    esac
}

OS="$(detect_os)"

echo "This will remove:"
echo "  ${INSTALL_PREFIX}"
echo "  ${CONFIG_DIR}"
if [[ "$OS" == "linux" ]]; then
    echo "  ${SYSTEMD_UNIT}"
elif [[ "$OS" == "macos" ]]; then
    echo "  ${PLIST_PATH}"
fi
echo ""
read -r -p "Are you sure? [y/N] " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Aborted."
    exit 0
fi

# ── Stop and remove service ───────────────────────────────────────────────────

if [[ "$OS" == "linux" ]]; then
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
            echo "Stopping ${SERVICE_NAME} ..."
            systemctl stop "${SERVICE_NAME}"
        fi
        if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
            echo "Disabling ${SERVICE_NAME} ..."
            systemctl disable "${SERVICE_NAME}"
        fi
        if [[ -f "${SYSTEMD_UNIT}" ]]; then
            rm -f "${SYSTEMD_UNIT}"
            systemctl daemon-reload
            echo "Removed ${SYSTEMD_UNIT}"
        fi
    fi
elif [[ "$OS" == "macos" ]]; then
    if launchctl list | grep -q "io.hash.sentinel-agent" 2>/dev/null; then
        echo "Unloading launch daemon ..."
        launchctl unload "${PLIST_PATH}" 2>/dev/null || true
    fi
    if [[ -f "${PLIST_PATH}" ]]; then
        rm -f "${PLIST_PATH}"
        echo "Removed ${PLIST_PATH}"
    fi
fi

# ── Remove files ──────────────────────────────────────────────────────────────

if [[ -d "${INSTALL_PREFIX}" ]]; then
    rm -rf "${INSTALL_PREFIX}"
    echo "Removed ${INSTALL_PREFIX}"
fi

if [[ -d "${CONFIG_DIR}" ]]; then
    rm -rf "${CONFIG_DIR}"
    echo "Removed ${CONFIG_DIR}"
fi

# ── Remove system user (Linux) ────────────────────────────────────────────────

if [[ "$OS" == "linux" ]]; then
    if id -u sentinel &>/dev/null; then
        userdel sentinel 2>/dev/null && echo "Removed system user: sentinel" || true
    fi
fi

echo ""
echo "M.A.R.K. Sentinel Agent has been uninstalled."
