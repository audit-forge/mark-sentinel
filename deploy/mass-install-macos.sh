#!/usr/bin/env bash
set -euo pipefail

# Arckon Agent — macOS Mass Install Script
# For Apple Remote Desktop (ARD), Jamf Pro, or manual fleet deployment.
# Usage: sudo bash deploy/mass-install-macos.sh --server URL --token TOKEN [--target /]
# Or via ARD: send as a Unix command to selected machines.

INSTALL_PREFIX="/opt/arckon"
CONFIG_DIR="/etc/arckon"
CONFIG_FILE="${CONFIG_DIR}/agent_config.json"
PLIST_LABEL="ai.mfdynamics.arckon-agent"
PLIST_PATH="/Library/LaunchDaemons/${PLIST_LABEL}.plist"

OPT_SERVER=""
OPT_TOKEN=""
OPT_TARGET="/"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server) OPT_SERVER="$2"; shift 2 ;;
        --token)  OPT_TOKEN="$2";  shift 2 ;;
        --target) OPT_TARGET="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: must run as root" >&2
    exit 1
fi

echo "[Arckon] Installing agent to ${INSTALL_PREFIX} ..."
mkdir -p "${INSTALL_PREFIX}"

# Download the signed macOS release
echo "[Arckon] Fetching manifest from ${OPT_SERVER} ..."
MANIFEST=$(curl -sSf -H "Authorization: Bearer ${OPT_TOKEN}" "${OPT_SERVER}/releases/macos/manifest.json")

ARTIFACT=$(echo "$MANIFEST" | python3 -c "import sys,json; print(json.load(sys.stdin)['artifact'])")
SHA256=$(echo "$MANIFEST" | python3 -c "import sys,json; print(json.load(sys.stdin)['sha256'])")
VERSION=$(echo "$MANIFEST" | python3 -c "import sys,json; print(json.load(sys.stdin)['version'])")

echo "[Arckon] Release v${VERSION}: ${ARTIFACT}"

# Download
TARBALL="/tmp/arckon-${ARTIFACT}"
curl -sSf -H "Authorization: Bearer ${OPT_TOKEN}" -o "$TARBALL" "${OPT_SERVER}/releases/macos/${ARTIFACT}"

# Verify
DOWNLOADED_SHA=$(shasum -a 256 "$TARBALL" | awk '{print $1}')
if [[ "$DOWNLOADED_SHA" != "$SHA256" ]]; then
    echo "[Arckon] ERROR: SHA256 mismatch" >&2
    rm -f "$TARBALL"
    exit 1
fi
echo "[Arckon] SHA256 verified"

# Extract
tar xzf "$TARBALL" -C "${INSTALL_PREFIX}" --strip-components=1
rm -f "$TARBALL"
chmod 755 "${INSTALL_PREFIX}/agent" "${INSTALL_PREFIX}/audit"

# Config
mkdir -p "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"
cat > "${CONFIG_FILE}" <<EOCFG
{
  "server":   "${OPT_SERVER}",
  "token":    "${OPT_TOKEN}",
  "target":   "${OPT_TARGET}",
  "profile":  "default",
  "interval": 900
}
EOCFG
chmod 640 "${CONFIG_FILE}"

# launchd daemon (starts at boot, auto-restarts)
cat > "$PLIST_PATH" <<EOPLIST
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
  <key>StandardOutPath</key>    <string>/var/log/arckon-agent.log</string>
  <key>StandardErrorPath</key>  <string>/var/log/arckon-agent.log</string>
</dict>
</plist>
EOPLIST
chmod 644 "$PLIST_PATH"

# Unload if already running, then load
launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load -w "$PLIST_PATH"

echo "[Arckon] Agent installed and started."
echo "[Arckon]   Binary : ${INSTALL_PREFIX}/agent"
echo "[Arckon]   Config : ${CONFIG_FILE}"
echo "[Arckon]   Service: ${PLIST_LABEL}"
echo "[Arckon]   Logs   : /var/log/arckon-agent.log"