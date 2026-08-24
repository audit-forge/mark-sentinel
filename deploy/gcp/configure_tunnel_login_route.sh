#!/usr/bin/env bash
# Route an existing customer login flow through public Cloudflare Tunnel hosts.
set -euo pipefail

CUSTOMER_ID="${1:?usage: $0 <customer_id> <app-host> <admin-host>}"
APP_HOST="${2:?usage: $0 <customer_id> <app-host> <admin-host>}"
ADMIN_HOST="${3:?usage: $0 <customer_id> <app-host> <admin-host>}"
CONFIG="/opt/sentinel-nginx/conf.d/${CUSTOMER_ID}.conf"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

test -f "$CONFIG"
python3 "$SCRIPT_DIR/configure_tunnel_login_route.py" "$CONFIG" "$APP_HOST" "$ADMIN_HOST"
docker exec sentinel-nginx nginx -t
docker exec sentinel-nginx nginx -s reload
