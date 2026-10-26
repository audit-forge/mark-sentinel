#!/usr/bin/env bash
# RiskRaven Arckon — Linux launcher
# chmod +x launch_sentinel.sh && ./launch_sentinel.sh
# LAN: PUBLIC_DASHBOARD_URL=http://192.168.1.10:7331 ./launch_sentinel.sh
# Set PUBLIC_ADMIN_URL explicitly for a separate admin origin; never trust Host.

set -euo pipefail
umask 077

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

_open_browser() {
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$1"
    elif command -v open >/dev/null 2>&1; then
        open "$1"
    else
        echo "Dashboard ready: $1"
    fi
}

# If server is already running, just open browser
if curl -sf http://localhost:7331/ >/dev/null 2>&1; then
    _open_browser http://localhost:7331
    exit 0
fi

# Find Python 3.11+
PYTHON=""
for cmd in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" >/dev/null 2>&1; then
        _ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
        _maj=$(echo "$_ver" | cut -d. -f1)
        _min=$(echo "$_ver" | cut -d. -f2)
        if [ "$_maj" -ge 3 ] && [ "$_min" -ge 11 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "Error: RiskRaven Arckon requires Python 3.11 or later." >&2
    echo "Install: https://python.org/downloads/" >&2
    exit 1
fi

export ARCKON_MASTER_KEY_FILE="${ARCKON_MASTER_KEY_FILE-$PROJ/.field-secrets/master-key}"
export PUBLIC_DASHBOARD_URL="${PUBLIC_DASHBOARD_URL:-http://localhost:7331}"
export PUBLIC_ADMIN_URL="${PUBLIC_ADMIN_URL:-http://localhost:7331}"
"$PYTHON" "$PROJ/scripts/prepare_local_security.py" --project-dir "$PROJ" || exit 1

nohup "$PYTHON" "$PROJ/server.py" --no-browser >"$PROJ/.sentinel.log" 2>&1 &
echo $! > "$PROJ/.sentinel.pid"

for i in $(seq 1 20); do
    sleep 0.3
    if curl -sf http://localhost:7331/ >/dev/null 2>&1; then
        _open_browser http://localhost:7331
        exit 0
    fi
done

echo "Sentinel failed to start. Check .sentinel.log for details." >&2
exit 1
