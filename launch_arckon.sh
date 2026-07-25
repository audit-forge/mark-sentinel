#!/usr/bin/env bash
# Arckon by RiskRaven — Linux launcher
# chmod +x launch_arckon.sh && ./launch_arckon.sh

PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    echo "Error: Arckon by RiskRaven requires Python 3.11 or later." >&2
    echo "Install: https://python.org/downloads/" >&2
    exit 1
fi

nohup "$PYTHON" "$PROJ/server.py" --no-browser >"$PROJ/.arckon.log" 2>&1 &
echo $! > "$PROJ/.arckon.pid"

for i in $(seq 1 20); do
    sleep 0.3
    if curl -sf http://localhost:7331/ >/dev/null 2>&1; then
        _open_browser http://localhost:7331
        exit 0
    fi
done

echo "Arckon failed to start. Check .arckon.log for details." >&2
exit 1
