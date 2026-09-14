#!/bin/bash
set -euo pipefail

# Arckon Agent — Intune uninstall script (macOS)

PLIST_LABEL="ai.mfdynamics.arckon-agent"
PLIST_DST="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
INSTALL_PREFIX="/opt/arckon"
CONFIG_DIR="/etc/arckon"

# Stop and unload the daemon
if [[ -f "$PLIST_DST" ]]; then
    launchctl bootout "system/${PLIST_LABEL}" 2>/dev/null || true
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    rm -f "$PLIST_DST"
fi

# Remove legacy labels
for legacy_label in io.riskraven.arckon-agent io.hash.sentinel-agent; do
    if [[ -f "/Library/LaunchDaemons/${legacy_label}.plist" ]]; then
        launchctl bootout "system/${legacy_label}" 2>/dev/null || true
        rm -f "/Library/LaunchDaemons/${legacy_label}.plist"
    fi
done

# Remove install directory
rm -rf "$INSTALL_PREFIX" 2>/dev/null || true

# Remove config directory
rm -rf "$CONFIG_DIR" 2>/dev/null || true

echo "Arckon Agent removed"
exit 0