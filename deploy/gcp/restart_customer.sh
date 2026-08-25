#!/usr/bin/env bash
# Safely restart a customer container — stop, remove, recreate with correct config.
# Called by sentinel-admin when licenses/config change.
# Usage: restart_customer.sh <customer_id>
set -euo pipefail

CUSTOMER_ID="$1"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
DATA_DIR="/opt/sentinel-data/${CUSTOMER_ID}"
NGINX_PROXY_TOKEN_DIR="${NGINX_PROXY_TOKEN_DIR:-/opt/sentinel-nginx/proxy-tokens}"
PUBLIC_ADMIN_URL="${PUBLIC_ADMIN_URL:-https://admin.riskraven.ai}"
SPEND_SECRET_DIR="${SENTINEL_SPEND_SECRET_ROOT:-/opt/sentinel-data/.spend-secrets}/${CUSTOMER_ID}/spend"
HOST_LICENSES_DIR="${HOST_LICENSES_DIR:-/opt/licenses}"
LICENSE_FILE="${HOST_LICENSES_DIR}/${CUSTOMER_ID}/license.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$DATA_DIR" ]; then
  echo "ERROR: data dir $DATA_DIR not found" >&2
  exit 1
fi

# Persist spend-provider keys outside the customer data mount. Each customer
# receives only its own directory; the container never sees another tenant's
# secrets.
install -d -o 999 -g 999 -m 0700 "$SPEND_SECRET_DIR"

AGENT_TOKEN=$(cat "${DATA_DIR}/agent_token.txt" 2>/dev/null || true)
if [ -z "$AGENT_TOKEN" ]; then
  echo "ERROR: no agent_token.txt in $DATA_DIR" >&2
  exit 1
fi

PROXY_TOKEN_FILE="${DATA_DIR}/proxy_token.txt"
PROXY_TOKEN=$(cat "$PROXY_TOKEN_FILE" 2>/dev/null || true)
if [ -z "$PROXY_TOKEN" ]; then
  PROXY_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  umask 077
  printf '%s\n' "$PROXY_TOKEN" > "$PROXY_TOKEN_FILE"
fi
install -d -m 0750 "$NGINX_PROXY_TOKEN_DIR"
umask 077
printf 'proxy_set_header X-Sentinel-Proxy-Token %s;\n' "$PROXY_TOKEN" \
  > "${NGINX_PROXY_TOKEN_DIR}/${CUSTOMER_ID}.conf"

LICENSE_MOUNT=""
if [ -f "$LICENSE_FILE" ]; then
  LICENSE_MOUNT="-v ${LICENSE_FILE}:/app/license.json:ro"
fi

echo "Restarting ${CONTAINER_NAME}..."

docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm   "$CONTAINER_NAME" 2>/dev/null || true

docker run -d \
  --name "$CONTAINER_NAME" \
  --network sentinel-net \
  --restart always \
  --label "sentinel.customer=${CUSTOMER_ID}" \
   -e "SENTINEL_AGENT_TOKEN_FILE=/app/data/agent_token.txt" \
   -e "SENTINEL_TRUSTED_PROXY_TOKEN=${PROXY_TOKEN}" \
   -e "SENTINEL_ADMIN_LOGOUT_URL=${PUBLIC_ADMIN_URL}/logout" \
  ${LICENSE_MOUNT} \
   -v "${DATA_DIR}:/app/data" \
   -v "${SPEND_SECRET_DIR}:/opt/sentinel-secrets/spend" \
   -v /opt/sentinel/releases:/app/releases:ro \
   mark-sentinel:latest \
  python3 server.py --no-browser --port 7331

docker network connect arckon-net "$CONTAINER_NAME"

# Wait up to 15s for server to be healthy.
# 401 Unauthorized = server is up and enforcing auth (healthy); any HTTP response counts.
for i in $(seq 1 15); do
  if docker exec "$CONTAINER_NAME" python3 -c \
      "import urllib.request, urllib.error, sys
try:
    urllib.request.urlopen('http://localhost:7331/api/status', timeout=2)
except urllib.error.HTTPError as e:
    sys.exit(0 if e.code == 401 else 1)
except Exception:
    sys.exit(1)" \
      2>/dev/null; then
    echo "  healthy after ${i}s"
    break
  fi
  sleep 1
done

# Regenerate the gateway proxy-token map (in case the token changed).
bash "$SCRIPT_DIR/regenerate_proxy_token_map.sh"

docker exec sentinel-nginx nginx -t
docker exec sentinel-nginx nginx -s reload
echo "Done: ${CONTAINER_NAME} restarted and nginx reloaded."
