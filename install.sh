#!/usr/bin/env bash
set -euo pipefail

# Arckon Sentinel Agent — Linux/macOS Installer (Nuitka binary)
# Usage: sudo bash install.sh --server URL --token TOKEN [--no-service] [--target PATH]
# Or:    curl -sSL http://SERVER:PORT/install.sh | bash -s -- --server URL --token TOKEN

INSTALL_PREFIX="/opt/arckon"
CONFIG_DIR="/etc/arckon"
CONFIG_FILE="${CONFIG_DIR}/agent_config.json"
SERVICE_NAME="arckon-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OPT_SERVER=""
OPT_TOKEN=""
OPT_TARGET=""
OPT_NO_SERVICE=0

usage() {
    echo "Usage: sudo bash install.sh --server URL --token TOKEN [--target PATH] [--no-service]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)     OPT_SERVER="$2";  shift 2 ;;
        --token)      OPT_TOKEN="$2";   shift 2 ;;
        --target)     OPT_TARGET="$2";  shift 2 ;;
        --no-service) OPT_NO_SERVICE=1;  shift ;;
        -h|--help)    usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: this installer must be run as root (use sudo)." >&2
    exit 1
fi

# Validate server URL to prevent command injection
if [[ -n "$OPT_SERVER" ]]; then
    if [[ ! "$OPT_SERVER" =~ ^https?://[a-zA-Z0-9._:/-]+$ ]]; then
        echo "Error: invalid server URL — must match http(s)://host:port format" >&2
        exit 1
    fi
fi

# Validate token (alphanumeric + dash + underscore only)
if [[ -n "$OPT_TOKEN" ]]; then
    if [[ ! "$OPT_TOKEN" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Error: invalid token — must be alphanumeric with dashes/underscores only" >&2
        exit 1
    fi
fi

# ── Detect OS and architecture ────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        *)       echo "unknown" ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "$arch" ;;
    esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"

if [[ "$OS" == "unknown" ]]; then
    echo "Error: unsupported operating system '$(uname -s)'." >&2
    exit 1
fi

echo "Detected: ${OS} (${ARCH})"

# ── Determine download server ────────────────────────────────────────────────

# If --server is provided, use it for both the download and the agent config.
# If not, try to guess from the script source URL (for curl|bash install).
DOWNLOAD_SERVER="${OPT_SERVER}"
if [[ -z "$DOWNLOAD_SERVER" ]]; then
    # Check if we were piped from curl (SCRIPT_DIR won't have the repo)
    if [[ ! -f "${SCRIPT_DIR}/agent.py" && ! -f "${SCRIPT_DIR}/agent" ]]; then
        echo "Error: --server URL is required for remote install." >&2
        echo "Usage: curl -sSL http://SERVER:PORT/install.sh | bash -s -- --server http://SERVER:PORT --token TOKEN" >&2
        exit 1
    fi
    # Local install from repo — binaries should be in dist/
    DOWNLOAD_SERVER=""
fi

# ── Download or copy the Nuitka binary release ───────────────────────────────

echo "Installing Arckon agent to ${INSTALL_PREFIX} ..."
mkdir -p "${INSTALL_PREFIX}"

if [[ -n "$DOWNLOAD_SERVER" ]]; then
    # Remote install: download the signed release from the server
    echo "  Downloading release manifest from ${DOWNLOAD_SERVER} ..."

    # Fetch manifest
    MANIFEST_URL="${DOWNLOAD_SERVER}/releases/${OS}/manifest.json"
    MANIFEST_FILE="$(mktemp)"
    trap "rm -f $MANIFEST_FILE" EXIT

    if ! curl -sSf -H "Authorization: Bearer ${OPT_TOKEN}" -o "$MANIFEST_FILE" "$MANIFEST_URL"; then
        echo "Error: could not download manifest from ${MANIFEST_URL}" >&2
        exit 1
    fi

    # Parse manifest (requires python3 or jq)
    if command -v python3 &>/dev/null; then
        ARTIFACT_NAME=$(python3 -c "import json; print(json.load(open('$MANIFEST_FILE'))['artifact'])")
        ARTIFACT_SHA=$(python3 -c "import json; print(json.load(open('$MANIFEST_FILE'))['sha256'])")
        ARTIFACT_SIZE=$(python3 -c "import json; print(json.load(open('$MANIFEST_FILE'))['size'])")
        ARTIFACT_VERSION=$(python3 -c "import json; print(json.load(open('$MANIFEST_FILE'))['version'])")
    elif command -v jq &>/dev/null; then
        ARTIFACT_NAME=$(jq -r '.artifact' "$MANIFEST_FILE")
        ARTIFACT_SHA=$(jq -r '.sha256' "$MANIFEST_FILE")
        ARTIFACT_SIZE=$(jq -r '.size' "$MANIFEST_FILE")
        ARTIFACT_VERSION=$(jq -r '.version' "$MANIFEST_FILE")
    else
        echo "Error: neither python3 nor jq found — cannot parse manifest." >&2
        exit 1
    fi

    echo "  Release: v${ARTIFACT_VERSION} (${ARTIFACT_NAME}, ${ARTIFACT_SIZE} bytes)"

    # Download artifact
    ARTIFACT_URL="${DOWNLOAD_SERVER}/releases/${OS}/${ARTIFACT_NAME}"
    ARTIFACT_FILE="/tmp/arckon-${ARTIFACT_NAME}"
    echo "  Downloading ${ARTIFACT_URL} ..."
    curl -sSf -H "Authorization: Bearer ${OPT_TOKEN}" -o "$ARTIFACT_FILE" "$ARTIFACT_URL"

    # Verify SHA256
    DOWNLOADED_SHA=$(shasum -a 256 "$ARTIFACT_FILE" 2>/dev/null | awk '{print $1}' || sha256sum "$ARTIFACT_FILE" | awk '{print $1}')
    if [[ "$DOWNLOADED_SHA" != "$ARTIFACT_SHA" ]]; then
        echo "Error: SHA256 mismatch! Expected ${ARTIFACT_SHA}, got ${DOWNLOADED_SHA}" >&2
        rm -f "$ARTIFACT_FILE"
        exit 1
    fi
    echo "  [OK] SHA256 verified"

    # Extract
    echo "  Extracting to ${INSTALL_PREFIX} ..."
    tar xzf "$ARTIFACT_FILE" -C "${INSTALL_PREFIX}" --strip-components=1
    rm -f "$ARTIFACT_FILE"

elif [[ -f "${SCRIPT_DIR}/dist/agent" || -f "${SCRIPT_DIR}/dist/agent.exe" ]]; then
    # Local install from repo dist/
    echo "  Copying from local dist/ ..."
    cp "${SCRIPT_DIR}/dist/agent" "${INSTALL_PREFIX}/agent" 2>/dev/null || true
    cp "${SCRIPT_DIR}/dist/audit" "${INSTALL_PREFIX}/audit" 2>/dev/null || true
    cp "${SCRIPT_DIR}/dist/agent.exe" "${INSTALL_PREFIX}/agent.exe" 2>/dev/null || true
    cp "${SCRIPT_DIR}/dist/audit.exe" "${INSTALL_PREFIX}/audit.exe" 2>/dev/null || true
    # Copy audit.dist directory if present (Windows standalone)
    if [[ -d "${SCRIPT_DIR}/dist/audit.dist" ]]; then
        cp -r "${SCRIPT_DIR}/dist/audit.dist" "${INSTALL_PREFIX}/audit.dist"
    fi
    cp -r "${SCRIPT_DIR}/profiles" "${INSTALL_PREFIX}/profiles" 2>/dev/null || true
else
    echo "Error: no binaries found. Run with --server URL to download, or build locally." >&2
    exit 1
fi

# Verify agent binary exists
if [[ ! -f "${INSTALL_PREFIX}/agent" && ! -f "${INSTALL_PREFIX}/agent.exe" ]]; then
    echo "Error: agent binary not found at ${INSTALL_PREFIX}/" >&2
    exit 1
fi

# Make binaries executable
chmod 755 "${INSTALL_PREFIX}/agent" 2>/dev/null || true
chmod 755 "${INSTALL_PREFIX}/audit" 2>/dev/null || true
chmod 755 "${INSTALL_PREFIX}/agent.exe" 2>/dev/null || true

# ── Create config ─────────────────────────────────────────────────────────────

echo "Configuring ${CONFIG_FILE} ..."
mkdir -p "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"

# Build config JSON
TARGET_PATH="${OPT_TARGET:-.}"
if [[ -z "$OPT_SERVER" ]]; then OPT_SERVER="http://localhost:7331"; fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
    cat > "${CONFIG_FILE}" <<EOCFG
{
  "server":   "${OPT_SERVER}",
  "token":    "${OPT_TOKEN}",
  "target":   "${TARGET_PATH}",
  "profile":  "default",
  "interval": 900
}
EOCFG
else
    # Update existing config with any provided values
    if command -v python3 &>/dev/null; then
        python3 - "${CONFIG_FILE}" "${OPT_SERVER}" "${OPT_TOKEN}" "${TARGET_PATH}" <<'EOPY'
import sys, json
path, server, token, target = sys.argv[1:5]
cfg = json.loads(open(path).read())
if server and server != "http://localhost:7331": cfg["server"] = server
if token and token != "": cfg["token"] = token
if target and target != ".": cfg["target"] = target
open(path, "w").write(json.dumps(cfg, indent=2) + "\n")
EOPY
    fi
fi

chmod 640 "${CONFIG_FILE}"

# ── Service installation ──────────────────────────────────────────────────────

install_systemd() {
    echo "Installing systemd service ..."

    if ! id -u arckon &>/dev/null; then
        useradd --system --no-create-home --shell /sbin/nologin arckon
        echo "  Created system user: arckon"
    fi

    chown -R arckon:arckon "${INSTALL_PREFIX}"
    chown root:arckon "${CONFIG_DIR}"
    chown root:arckon "${CONFIG_FILE}"

    local unit_dst="/etc/systemd/system/${SERVICE_NAME}.service"
    cat > "$unit_dst" <<EOUNIT
[Unit]
Description=Arckon Sentinel Agent
Documentation=https://github.com/audit-forge/mark-sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=arckon
Group=arckon
ExecStart=${INSTALL_PREFIX}/agent --config ${CONFIG_FILE} --daemon
Restart=on-failure
RestartSec=30
Environment=PYTHONUNBUFFERED=1
StandardOutput=journal
StandardError=journal
SyslogIdentifier=arckon-agent
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${INSTALL_PREFIX} /var/log

[Install]
WantedBy=multi-user.target
EOUNIT

    chmod 644 "$unit_dst"
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"
    echo "  Service enabled and started: ${SERVICE_NAME}"
    systemctl status "${SERVICE_NAME}" --no-pager -l || true
}

install_launchd() {
    echo "Installing launchd daemon ..."

    local plist_dst="/Library/LaunchDaemons/ai.mfdynamics.arckon-agent.plist"
    # Early Python-based installers used these labels. Remove them before
    # installing the compiled-agent daemon so they cannot run a stale agent
    # alongside the current service or reference a removed virtualenv.
    for legacy_label in io.riskraven.arckon-agent io.hash.sentinel-agent; do
        local legacy_plist="/Library/LaunchDaemons/${legacy_label}.plist"
        if [[ -f "$legacy_plist" ]]; then
            launchctl bootout "system/${legacy_label}" 2>/dev/null || true
            rm -f "$legacy_plist"
        fi
    done
    cat > "$plist_dst" <<EOPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>              <string>ai.mfdynamics.arckon-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_PREFIX}/agent</string>
    <string>--daemon</string>
    <string>--config</string>
    <string>${CONFIG_FILE}</string>
  </array>
  <key>RunAtLoad</key>          <true/>
  <key>KeepAlive</key>          <true/>
  <key>StandardOutPath</key>    <string>/var/log/arckon-agent.log</string>
  <key>StandardErrorPath</key>  <string>/var/log/arckon-agent.log</string>
</dict>
</plist>
EOPLIST

    chmod 644 "$plist_dst"

    if launchctl list | grep -q "ai.mfdynamics.arckon-agent" 2>/dev/null; then
        launchctl unload "$plist_dst" 2>/dev/null || true
    fi
    launchctl load -w "$plist_dst"
    echo "  Launch daemon loaded: ai.mfdynamics.arckon-agent"
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
    echo "To start manually: sudo ${INSTALL_PREFIX}/agent --config ${CONFIG_FILE} --daemon"
fi

# ── Protected Files monitoring prerequisites ──────────────────────────────────
# These set up the OS-level audit infrastructure the agent needs to detect
# when AI tools access protected files. Skipped with --no-service.

install_protected_files_prereqs() {
    if [[ "$OS" == "linux" ]]; then
        # Install auditd if not present — the Linux collector uses auditctl
        # and ausearch to monitor file access and SSH logins.
        if ! command -v auditctl &>/dev/null; then
            echo "Installing auditd for Protected Files monitoring..."
            if command -v apt-get &>/dev/null; then
                apt-get update -qq && apt-get install -y -qq auditd
            elif command -v yum &>/dev/null; then
                yum install -y -q audit
            elif command -v dnf &>/dev/null; then
                dnf install -y -q audit
            else
                echo "Warning: could not install auditd — Protected Files monitoring"
                echo "         will not work until auditd is installed manually."
            fi
        fi
        # Ensure auditd is running
        if command -v systemctl &>/dev/null; then
            systemctl enable auditd 2>/dev/null || true
            systemctl start auditd 2>/dev/null || true
        fi
        if command -v auditctl &>/dev/null; then
            echo "  auditd: ready ($(auditctl -s 2>/dev/null | head -1 || echo 'enabled'))"
        fi
        elif [[ "$OS" == "macos" ]]; then
        # Install the ArckonESCollector app (Endpoint Security helper) if the
        # installer bundle is present alongside this script. The agent downloads
        # it from the server's /releases/ path during install.
        ES_APP_SRC="${SCRIPT_DIR}/ArckonESCollector.app"
        # Also check the download cache location
        if [[ ! -d "$ES_APP_SRC" ]]; then
            ES_APP_SRC="${INSTALL_PREFIX}/ArckonESCollector.app"
        fi
        if [[ -d "$ES_APP_SRC" ]]; then
            echo "Installing Arckon ES Collector (Endpoint Security helper)..."
            mkdir -p /Library/Arckon
            cp -r "$ES_APP_SRC" /Library/Arckon/
            # Install the LaunchDaemon plist
            ES_PLIST_SRC="${SCRIPT_DIR}/ai.mfdynamics.arckon-es-collector.plist"
            if [[ ! -f "$ES_PLIST_SRC" ]]; then
                ES_PLIST_SRC="${INSTALL_PREFIX}/ai.mfdynamics.arckon-es-collector.plist"
            fi
            if [[ -f "$ES_PLIST_SRC" ]]; then
                cp "$ES_PLIST_SRC" /Library/LaunchDaemons/
                ES_LABEL="ai.mfdynamics.arckon-es-collector"
                # Clear any stale launchd penalty-box state from a prior
                # pre-FDA crash-loop before bootstrapping, so a clean
                # (re)install recovers immediately.
                launchctl bootout "system/${ES_LABEL}" 2>/dev/null || true
                sleep 1
                launchctl bootstrap system "/Library/LaunchDaemons/${ES_LABEL}.plist" 2>/dev/null || true
                echo "  ES Collector: installed and LaunchDaemon loaded"
            else
                echo "  Warning: ES LaunchDaemon plist not found — helper will not auto-start"
            fi
        else
            echo "Note: ArckonESCollector.app not found alongside installer."
            echo "      Protected Files monitoring on macOS requires the ES helper."
            echo "      Download it from the dashboard and install to /Library/Arckon/"
        fi
        # Full Disk Access cannot be granted via script (Apple TCC). If the
        # daemon isn't running after install, the most likely cause is that
        # FDA hasn't been granted yet. Open System Settings directly to the
        # Full Disk Access pane so the user can add the helper in two clicks.
        # (On MDM-managed Macs the PPPC profile grants FDA silently and the
        # daemon is already running — this block is a no-op there.)
        if pgrep -f "arckon-es-collector" &>/dev/null; then
            echo "  ES Collector: running"
        elif [[ -d /Library/Arckon/ArckonESCollector.app ]]; then
            echo "  ⚠ Full Disk Access required for Protected Files monitoring."
            echo "    Opening System Settings → Privacy & Security → Full Disk Access..."
            echo "    Click '+', press Cmd+Shift+G, and add:"
            echo "      /Library/Arckon/ArckonESCollector.app"
            # Open the Full Disk Access pane directly (macOS 13+). Non-fatal
            # if it fails — the message above tells the user the manual path.
            open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true
            echo "    The ES daemon auto-starts within 30s of FDA being granted."
        fi
    fi
}

if [[ "$OPT_NO_SERVICE" -eq 0 ]]; then
    install_protected_files_prereqs
fi

echo ""
echo "Arckon Agent installed successfully."
echo "  Install dir : ${INSTALL_PREFIX}"
echo "  Config      : ${CONFIG_FILE}"
echo "  Binary      : ${INSTALL_PREFIX}/agent (Nuitka-compiled, no Python required)"
echo ""
if [[ -z "$OPT_TOKEN" ]]; then
    echo "Edit ${CONFIG_FILE} to set your server URL and token, then restart the service."
fi
