#!/bin/bash
# M.A.R.K. Sentinel — Dashboard Launcher (macOS)
# Double-click this file to start the dashboard server and open your browser.

cd "$(dirname "$0")"

if ! command -v python3 &>/dev/null; then
  osascript -e 'display alert "Python 3 not found" message "Install Python 3 from python.org and try again."'
  exit 1
fi

echo "  M.A.R.K. Sentinel — starting dashboard server…"
echo "  Open: http://localhost:7331"
echo "  Press Ctrl+C to stop"
echo ""

python3 server.py
