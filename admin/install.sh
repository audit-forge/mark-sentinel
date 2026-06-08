#!/usr/bin/env bash
set -euo pipefail

# M.A.R.K. Sentinel Agent — Linux/macOS Installer
# Usage: sudo bash install.sh [--server URL] [--token TOKEN] [--no-service]

INSTALL_PREFIX="/opt/sentinel"
CONFIG_DIR="/etc/sentinel"
CONFIG_FILE="${CONFIG_DIR}/agent_config.json"
SERVICE_NAME="sentinel-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OPT_SERVER=""
OPT_TOKEN=""
OPT_NO_SERVICE=0

usage() {
    echo "Usage: sudo bash install.sh [--server URL] [--token TOKEN] [--no-service]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)   OPT_SERVER="$2"; shift 2 ;;
        --token)    OPT_TOKEN="$2";  shift 2 ;;
        --no-service) OPT_NO_SERVICE=1; shift ;;
        -h|--help)  usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: this installer must be run as root (use sudo)." >&2
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
if [[ "$OS" == "unknown" ]]; then
    echo "Error: unsupported operating system '$(uname -s)'." >&2
    exit 1
fi

# ── Python version check ─────────────────────────────────────────────────────

find_python() {
    for candidate in python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" &>/dev/null; then
            local ver
            ver="$("$candidate" -c 'import sys; print("%d%d" % sys.version_info[:2])')"
            if [[ "$ver" -ge 311 ]]; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

echo "Checking Python 3.11+ ..."
if ! PYTHON="$(find_python)"; then
    echo "Error: Python 3.11 or later is required but was not found." >&2
    echo "Install from https://www.python.org/downloads/ then re-run." >&2
    exit 1
fi
PYTHON_VER="$("$PYTHON" -c 'import sys; print(sys.version.split()[0])')"
echo "  Found: $PYTHON ($PYTHON_VER)"

# ── Virtualenv setup (avoids PEP 668 on Ubuntu 23.04+ / Debian 12+) ──────────

VENV_DIR="${INSTALL_PREFIX}/venv"
echo "Creating virtualenv at ${VENV_DIR} ..."
mkdir -p "${INSTALL_PREFIX}"

if ! "$PYTHON" -m venv --help &>/dev/null 2>&1; then
    echo "  venv module not found — attempting to install ..."
    PY_VER="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    # Package managers need root. Re-run through sudo when not already root —
    # otherwise these installs fail silently (stderr suppressed below) and the
    # user is left with a confusing "venv unavailable, run sudo apt-get ..."
    # error despite the script having "tried" to install it for them.
    SUDO=""
    if [[ "$(id -u)" -ne 0 ]]; then
        if command -v sudo &>/dev/null; then
            SUDO="sudo"
        else
            echo "  Warning: not running as root and 'sudo' is unavailable — cannot auto-install venv." >&2
        fi
    fi
    if command -v apt-get &>/dev/null; then
        $SUDO apt-get install -y "python${PY_VER}-venv" 2>/dev/null || $SUDO apt-get install -y python3-venv 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        $SUDO dnf install -y "python${PY_VER}" 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        $SUDO yum install -y "python3" 2>/dev/null || true
    fi
    if ! "$PYTHON" -m venv --help &>/dev/null 2>&1; then
        echo "Error: venv module unavailable. Run: sudo apt-get install python${PY_VER}-venv" >&2
        exit 1
    fi
    echo "  [OK] venv installed"
fi

"$PYTHON" -m venv "${VENV_DIR}"
VENV_PYTHON="${VENV_DIR}/bin/python"

# ── Download agent bundle from server (web install path) ─────────────────────

echo "Installing files to ${INSTALL_PREFIX} ..."

if [[ -n "$OPT_SERVER" ]]; then
    BUNDLE_URL="${OPT_SERVER%/}/bundle.tar.gz"
    echo "  Downloading agent bundle from ${BUNDLE_URL} ..."
    BUNDLE_TMP="$(mktemp /tmp/sentinel-bundle.XXXXXX.tar.gz)"
    HTTP_CODE=$(curl -sL \
        -H "Authorization: Bearer ${OPT_TOKEN}" \
        "$BUNDLE_URL" \
        -o "$BUNDLE_TMP" \
        -w "%{http_code}" 2>/dev/null)
    if [[ "$HTTP_CODE" == "200" ]] && [[ -s "$BUNDLE_TMP" ]]; then
        tar -xzf "$BUNDLE_TMP" --strip-components=1 -C "${INSTALL_PREFIX}" 2>/dev/null || true
        rm -f "$BUNDLE_TMP"
        echo "  [OK] Agent bundle downloaded and extracted"
    else
        rm -f "$BUNDLE_TMP"
        echo "  Warning: bundle download failed (HTTP ${HTTP_CODE}) — falling back to local files"
    fi
fi

# ── Copy files (local install / fallback) ────────────────────────────────────

for f in agent.py audit.py audit_safe.py storage.py server.py requirements.txt; do
    if [[ -f "${SCRIPT_DIR}/${f}" ]]; then
        install -m 644 "${SCRIPT_DIR}/${f}" "${INSTALL_PREFIX}/${f}"
    fi
done

for d in checks connectors profiles; do
    if [[ -d "${SCRIPT_DIR}/${d}" ]]; then
        cp -r "${SCRIPT_DIR}/${d}" "${INSTALL_PREFIX}/${d}"
    fi
done

if [[ ! -f "${INSTALL_PREFIX}/agent.py" ]]; then
    echo "Error: agent.py not found at ${INSTALL_PREFIX}/agent.py — bundle download may have failed." >&2
    exit 1
fi

chmod 755 "${INSTALL_PREFIX}/agent.py"

# ── Install pip dependencies ─────────────────────────────────────────────────

echo "Installing Python dependencies ..."
if [[ -f "${INSTALL_PREFIX}/requirements.txt" ]]; then
    "${VENV_PYTHON}" -m pip install --quiet --upgrade pip
    "${VENV_PYTHON}" -m pip install --quiet -r "${INSTALL_PREFIX}/requirements.txt"
else
    echo "  Warning: requirements.txt not found, skipping pip install."
fi

PYTHON="${VENV_PYTHON}"

# ── Create config ────────────────────────────────────────────────────────────

echo "Configuring ${CONFIG_FILE} ..."
mkdir -p "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"

if [[ ! -f "${CONFIG_FILE}" ]]; then
    if [[ -f "${SCRIPT_DIR}/agent_config.json.example" ]]; then
        cp "${SCRIPT_DIR}/agent_config.json.example" "${CONFIG_FILE}"
    else
        cat > "${CONFIG_FILE}" <<'EOCFG'
{
  "server":   "http://localhost:7331",
  "token":    "replace-with-your-secret-token",
  "target":   ".",
  "profile":  "default",
  "interval": 3600
}
EOCFG
    fi
fi

if [[ -n "$OPT_SERVER" ]]; then
    "$PYTHON" - "${CONFIG_FILE}" "${OPT_SERVER}" <<'EOPY'
import sys, json
path, server = sys.argv[1], sys.argv[2]
cfg = json.loads(open(path).read())
cfg["server"] = server
open(path, "w").write(json.dumps(cfg, indent=2) + "\n")
EOPY
fi

if [[ -n "$OPT_TOKEN" ]]; then
    "$PYTHON" - "${CONFIG_FILE}" "${OPT_TOKEN}" <<'EOPY'
import sys, json
path, token = sys.argv[1], sys.argv[2]
cfg = json.loads(open(path).read())
cfg["token"] = token
open(path, "w").write(json.dumps(cfg, indent=2) + "\n")
EOPY
fi

chmod 640 "${CONFIG_FILE}"

# ── Service installation ──────────────────────────────────────────────────────

install_systemd() {
    echo "Installing systemd service ..."

    if ! id -u sentinel &>/dev/null; then
        useradd --system --no-create-home --shell /sbin/nologin sentinel
        echo "  Created system user: sentinel"
    fi

    chown -R sentinel:sentinel "${INSTALL_PREFIX}"
    chown root:sentinel "${CONFIG_DIR}"
    chown root:sentinel "${CONFIG_FILE}"

    local unit_src="${SCRIPT_DIR}/deploy/sentinel-agent.service"
    local unit_dst="/etc/systemd/system/${SERVICE_NAME}.service"

    if [[ -f "$unit_src" ]]; then
        install -m 644 "$unit_src" "$unit_dst"
    else
        cat > "$unit_dst" <<EOUNIT
[Unit]
Description=M.A.R.K. Sentinel Agent
Documentation=https://github.com/hash-ai/sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentinel
Group=sentinel
ExecStart=${PYTHON} ${INSTALL_PREFIX}/agent.py --config ${CONFIG_FILE} --daemon
Restart=on-failure
RestartSec=30
Environment=PYTHONUNBUFFERED=1
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel-agent
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${INSTALL_PREFIX} /var/log

[Install]
WantedBy=multi-user.target
EOUNIT
    fi

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"
    echo "  Service enabled and started: ${SERVICE_NAME}"
    systemctl status "${SERVICE_NAME}" --no-pager -l || true
}

install_launchd() {
    echo "Installing launchd daemon ..."

    local plist_src="${SCRIPT_DIR}/deploy/io.hash.sentinel-agent.plist"
    local plist_dst="/Library/LaunchDaemons/io.hash.sentinel-agent.plist"

    if [[ -f "$plist_src" ]]; then
        install -m 644 "$plist_src" "$plist_dst"
    else
        cat > "$plist_dst" <<EOPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>              <string>io.hash.sentinel-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${PYTHON}</string>
    <string>${INSTALL_PREFIX}/agent.py</string>
    <string>--daemon</string>
    <string>--config</string>
    <string>${CONFIG_FILE}</string>
  </array>
  <key>RunAtLoad</key>          <true/>
  <key>KeepAlive</key>          <true/>
  <key>StandardOutPath</key>    <string>/var/log/sentinel-agent.log</string>
  <key>StandardErrorPath</key>  <string>/var/log/sentinel-agent.log</string>
</dict>
</plist>
EOPLIST
    fi

    chmod 644 "$plist_dst"

    if launchctl list | grep -q "io.hash.sentinel-agent" 2>/dev/null; then
        launchctl unload "$plist_dst" 2>/dev/null || true
    fi
    launchctl load -w "$plist_dst"
    echo "  Launch daemon loaded: io.hash.sentinel-agent"
}

if [[ "$OPT_NO_SERVICE" -eq 0 ]]; then
    if [[ "$OS" == "linux" ]]; then
        if command -v systemctl &>/dev/null; then
            install_systemd
        else
            echo "Warning: systemd not found; skipping service installation."
        fi
    elif [[ "$OS" == "macos" ]]; then
        install_launchd
    fi
else
    echo "Skipping service installation (--no-service)."
    echo "To start manually: sudo ${PYTHON} ${INSTALL_PREFIX}/agent.py --config ${CONFIG_FILE} --daemon"
fi

echo ""
echo "M.A.R.K. Sentinel Agent installed successfully."
echo "  Install dir : ${INSTALL_PREFIX}"
echo "  Config      : ${CONFIG_FILE}"
echo ""
if [[ -n "$OPT_SERVER" && -n "$OPT_TOKEN" ]]; then
    echo "Server and token were configured automatically from --server/--token — no further action needed."
else
    echo "Edit ${CONFIG_FILE} to set your server URL and token, then restart the service."
    echo "(tip: pass --server URL --token TOKEN to install.sh to configure this automatically — useful for mass rollouts)"
fi
