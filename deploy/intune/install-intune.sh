#!/bin/bash
set -euo pipefail

# Arckon Agent — Intune installer (macOS)
# Designed for Microsoft Intune shell script deployment (runs as root).
#
# Usage: bash install-intune.sh --server URL --token TOKEN
#
# Intune passes scripts to the agent which runs them as root. This script
# downloads the signed Nuitka binary from the Arckon server, installs it
# to /opt/arckon, creates the config, and loads the launchd daemon.

INSTALL_PREFIX="/opt/arckon"
CONFIG_DIR="/etc/arckon"
CONFIG_FILE="${CONFIG_DIR}/agent_config.json"
PLIST_LABEL="ai.mfdynamics.arckon-agent"
PLIST_DST="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
LOG_FILE="/var/log/arckon-agent.log"
SERVER_URL=""
AGENT_TOKEN=""

usage() {
    echo "Usage: bash install-intune.sh --server URL --token TOKEN"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server) SERVER_URL="$2";  shift 2 ;;
        --token)  AGENT_TOKEN="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$SERVER_URL" || -z "$AGENT_TOKEN" ]]; then
    echo "Error: --server and --token are required"
    usage
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: must run as root"
    exit 1
fi

# Validate inputs
if [[ ! "$SERVER_URL" =~ ^https?://[a-zA-Z0-9._:/-]+$ ]]; then
    echo "Error: invalid server URL"
    exit 1
fi
if [[ ! "$AGENT_TOKEN" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: invalid token"
    exit 1
fi

OS="macos"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

echo "Arckon Agent — Intune installation starting (${OS}/${ARCH})"

# -- Stop existing daemon if present -------------------------------------------
if launchctl list | grep -q "$PLIST_LABEL" 2>/dev/null; then
    launchctl bootout "system/${PLIST_LABEL}" 2>/dev/null || true
fi

# Remove legacy labels
for legacy_label in io.riskraven.arckon-agent io.hash.sentinel-agent; do
    if [[ -f "/Library/LaunchDaemons/${legacy_label}.plist" ]]; then
        launchctl bootout "system/${legacy_label}" 2>/dev/null || true
        rm -f "/Library/LaunchDaemons/${legacy_label}.plist"
    fi
done

# -- Prepare directories -------------------------------------------------------
mkdir -p "${INSTALL_PREFIX}"
mkdir -p "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"

# -- Fetch signed release manifest ---------------------------------------------
echo "Fetching release manifest from ${SERVER_URL} ..."
MANIFEST_URL="${SERVER_URL}/releases/${OS}/manifest.json"
MANIFEST_FILE="$(mktemp)"
trap "rm -f $MANIFEST_FILE" EXIT

if ! curl -sSf -H "Authorization: Bearer ${AGENT_TOKEN}" -o "$MANIFEST_FILE" "$MANIFEST_URL"; then
    echo "Error: cannot download manifest from ${MANIFEST_URL}"
    exit 1
fi

if command -v python3 &>/dev/null; then
    ARTIFACT_NAME=$(python3 -c "import json; print(json.load(open('$MANIFEST_FILE'))['artifact'])")
    ARTIFACT_SHA=$(python3 -c "import json; print(json.load(open('$MANIFEST_FILE'))['sha256'])")
    ARTIFACT_VERSION=$(python3 -c "import json; print(json.load(open('$MANIFEST_FILE'))['version'])")
elif command -v jq &>/dev/null; then
    ARTIFACT_NAME=$(jq -r '.artifact' "$MANIFEST_FILE")
    ARTIFACT_SHA=$(jq -r '.sha256' "$MANIFEST_FILE")
    ARTIFACT_VERSION=$(jq -r '.version' "$MANIFEST_FILE")
else
    echo "Error: neither python3 nor jq found"
    exit 1
fi

echo "Release v${ARTIFACT_VERSION} — artifact: ${ARTIFACT_NAME}"

# -- Download artifact ---------------------------------------------------------
ARTIFACT_URL="${SERVER_URL}/releases/${OS}/${ARTIFACT_NAME}"
ARTIFACT_FILE="/tmp/arckon-intune-${ARTIFACT_NAME}"
echo "Downloading ${ARTIFACT_URL} ..."
curl -sSf -H "Authorization: Bearer ${AGENT_TOKEN}" -o "$ARTIFACT_FILE" "$ARTIFACT_URL"

# -- Verify SHA256 -------------------------------------------------------------
DOWNLOADED_SHA=$(shasum -a 256 "$ARTIFACT_FILE" | awk '{print $1}')
if [[ "$DOWNLOADED_SHA" != "$ARTIFACT_SHA" ]]; then
    echo "Error: SHA256 mismatch! Expected ${ARTIFACT_SHA}, got ${DOWNLOADED_SHA}"
    rm -f "$ARTIFACT_FILE"
    exit 1
fi
echo "SHA256 verified"

# -- Extract -------------------------------------------------------------------
echo "Extracting to ${INSTALL_PREFIX} ..."
tar xzf "$ARTIFACT_FILE" -C "${INSTALL_PREFIX}" --strip-components=1
rm -f "$ARTIFACT_FILE"

chmod 755 "${INSTALL_PREFIX}/agent" 2>/dev/null || true
chmod 755 "${INSTALL_PREFIX}/audit" 2>/dev/null || true

if [[ ! -f "${INSTALL_PREFIX}/agent" ]]; then
    echo "Error: agent binary not found at ${INSTALL_PREFIX}/"
    exit 1
fi

# -- Create config -------------------------------------------------------------
echo "Writing config to ${CONFIG_FILE} ..."
cat > "${CONFIG_FILE}" <<EOCFG
{
  "server":   "${SERVER_URL}",
  "token":    "${AGENT_TOKEN}",
  "target":   "~",
  "profile":  "default",
  "interval": 3600
}
EOCFG
chmod 640 "${CONFIG_FILE}"

# -- Install launchd daemon ----------------------------------------------------
echo "Installing launchd daemon ..."
cat > "$PLIST_DST" <<EOPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>              <string>${PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_PREFIX}/agent</string>
    <string>--daemon</string>
    <string>--config</string>
    <string>${CONFIG_FILE}</string>
  </array>
  <key>RunAtLoad</key>          <true/>
  <key>KeepAlive</key>          <true/>
  <key>StandardOutPath</key>    <string>${LOG_FILE}</string>
  <key>StandardErrorPath</key>  <string>${LOG_FILE}</string>
</dict>
</plist>
EOPLIST

chmod 644 "$PLIST_DST"
launchctl load -w "$PLIST_DST"

# -- Verify daemon is running --------------------------------------------------
sleep 3
if launchctl list | grep -q "$PLIST_LABEL" 2>/dev/null; then
    echo "Launch daemon loaded: ${PLIST_LABEL}"
else
    echo "Warning: daemon not loaded — check ${LOG_FILE}"
fi

# -- Verify server connectivity ------------------------------------------------
echo "Verifying server connectivity ..."
HEALTH_URL="${SERVER_URL}/health"
if curl -sSf -o /dev/null --max-time 10 "$HEALTH_URL" 2>/dev/null; then
    echo "Server reachable at ${SERVER_URL}"
else
    echo "Warning: cannot reach ${SERVER_URL} — agent will retry on its own"
fi

echo ""
echo "Arckon Agent installed successfully (v${ARTIFACT_VERSION})"
echo "  Install dir : ${INSTALL_PREFIX}"
echo "  Config      : ${CONFIG_FILE}"
echo "  Log         : ${LOG_FILE}"
exit 0