#!/usr/bin/env bash
# Safely restart a customer container — stop, remove, recreate with correct config.
# Called by sentinel-admin when licenses/config change.
# Usage: restart_customer.sh <customer_id>
set -euo pipefail

CUSTOMER_ID="$1"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
DATA_DIR="${SENTINEL_DATA_ROOT:-/opt/sentinel-data}/${CUSTOMER_ID}"
NGINX_PROXY_TOKEN_DIR="${NGINX_PROXY_TOKEN_DIR:-/opt/sentinel-nginx/proxy-tokens}"
PUBLIC_ADMIN_URL="${PUBLIC_ADMIN_URL:-https://admin.riskraven.ai}"
PUBLIC_DASHBOARD_URL="${PUBLIC_DASHBOARD_URL:-https://arckon.riskraven.ai}"
SPEND_SECRET_DIR="${SENTINEL_SPEND_SECRET_ROOT:-${SENTINEL_DATA_ROOT:-/opt/sentinel-data}/.spend-secrets}/${CUSTOMER_ID}/spend"
HOST_LICENSES_DIR="${HOST_LICENSES_DIR:-/opt/licenses}"
LICENSE_FILE="${HOST_LICENSES_DIR}/${CUSTOMER_ID}/license.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIELD_SECRET_DIR="${SENTINEL_FIELD_SECRET_ROOT:-${SENTINEL_DATA_ROOT:-/opt/sentinel-data}/.field-secrets}/${CUSTOMER_ID}"

if [ ! -d "$DATA_DIR" ]; then
  echo "ERROR: data dir $DATA_DIR not found" >&2
  exit 1
fi

# Missing/invalid keys must leave the running container untouched. Never generate
# or migrate a key during restart, even for an empty tenant directory.
python3 "$SCRIPT_DIR/prepare_customer_security.py" "$CUSTOMER_ID"

# Resolve an explicit deployment/rollback override before removing the container.
if [ -n "${SENTINEL_IMAGE:-}" ]; then
  docker image inspect "$SENTINEL_IMAGE" >/dev/null
fi
SENTINEL_IMAGE="${SENTINEL_IMAGE:-mark-sentinel:latest}"

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
chown 999:999 "$PROXY_TOKEN_FILE"
chmod 0400 "$PROXY_TOKEN_FILE"
install -d -o 101 -g 101 -m 0750 "$NGINX_PROXY_TOKEN_DIR"
umask 077
printf 'proxy_set_header X-Sentinel-Proxy-Token %s;\n' "$PROXY_TOKEN" \
  > "${NGINX_PROXY_TOKEN_DIR}/${CUSTOMER_ID}.conf"
chown 101:101 "${NGINX_PROXY_TOKEN_DIR}/${CUSTOMER_ID}.conf"
chmod 0400 "${NGINX_PROXY_TOKEN_DIR}/${CUSTOMER_ID}.conf"

LICENSE_MOUNT=""
if [ -f "$LICENSE_FILE" ]; then
  LICENSE_MOUNT="-v ${LICENSE_FILE}:/app/license.json:ro"
fi

echo "Restarting ${CONTAINER_NAME}..."

# --restart=always may revive a container after `docker stop`; force removal
# makes the replacement atomic from the caller's perspective.
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

docker run -d \
  --name "$CONTAINER_NAME" \
  --network sentinel-net \
  --restart always \
  --label "sentinel.customer=${CUSTOMER_ID}" \
   --read-only \
   --tmpfs /tmp \
   --memory 2g --memory-swap 2g \
   --cpus 1.0 \
   -e "SENTINEL_AGENT_TOKEN_FILE=/app/data/agent_token.txt" \
   -v "${PROXY_TOKEN_FILE}:/run/secrets/proxy_token:ro" \
   -e "SENTINEL_TRUSTED_PROXY_TOKEN_FILE=/run/secrets/proxy_token" \
   -e "SENTINEL_ADMIN_LOGOUT_URL=${PUBLIC_ADMIN_URL}/logout" \
   -e "PUBLIC_ADMIN_URL=${PUBLIC_ADMIN_URL}" \
   -e "PUBLIC_DASHBOARD_URL=${PUBLIC_DASHBOARD_URL}" \
   --env-file "${FIELD_SECRET_DIR}/runtime.env" \
   --mount "type=bind,src=${FIELD_SECRET_DIR}/master-key,dst=/run/secrets/arckon_master_key,readonly" \
   -e "ARCKON_MASTER_KEY_FILE=/run/secrets/arckon_master_key" \
  ${LICENSE_MOUNT} \
   -v "${DATA_DIR}:/app/data" \
   -v "${SPEND_SECRET_DIR}:/opt/sentinel-secrets/spend" \
   -v /opt/sentinel/releases:/app/releases:ro \
    --pull never \
    "$SENTINEL_IMAGE" \
  python3 server.py --no-browser --port 7331

docker network connect arckon-net "$CONTAINER_NAME"

# Wait up to 15s for server to be healthy.
# Require health 200 AND unauthenticated status 401 (auth enforcement).
READY=false
for i in $(seq 1 15); do
  if docker exec "$CONTAINER_NAME" python3 -c \
      "import urllib.request, urllib.error, sys
try:
    assert urllib.request.urlopen('http://localhost:7331/health', timeout=2).status == 200
except Exception:
    sys.exit(1)
try:
    urllib.request.urlopen('http://localhost:7331/api/status', timeout=2)
    sys.exit(1)
except urllib.error.HTTPError as e:
    sys.exit(0 if e.code == 401 else 1)
except Exception:
    sys.exit(1)" \
      2>/dev/null; then
    echo "  healthy after ${i}s"
    READY=true
    break
  fi
  sleep 1
done
if [ "$READY" != true ]; then
  echo "ERROR: ${CONTAINER_NAME} readiness exhausted" >&2
  exit 1
fi

# Regenerate the gateway proxy-token map (in case the token changed).
bash "$SCRIPT_DIR/regenerate_proxy_token_map.sh"

docker exec sentinel-nginx nginx -t
docker exec sentinel-nginx nginx -s reload
echo "Done: ${CONTAINER_NAME} restarted and nginx reloaded."
