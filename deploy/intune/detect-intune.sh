#!/bin/bash
# Arckon Agent — Intune detection script (macOS)
# Intune runs this to check if the agent is installed.
# Returns exit code 0 if detected, 1 if not.

AGENT_BIN="/opt/arckon/agent"
CONFIG_FILE="/etc/arckon/agent_config.json"
PLIST_FILE="/Library/LaunchDaemons/ai.mfdynamics.arckon-agent.plist"

if [[ -f "$AGENT_BIN" && -f "$CONFIG_FILE" && -f "$PLIST_FILE" ]]; then
    if launchctl list 2>/dev/null | grep -q "ai.mfdynamics.arckon-agent"; then
        echo "Detected: agent + config + plist + daemon loaded"
        exit 0
    fi
fi

echo "Not detected"
exit 1