#!/usr/bin/env bash
# Provision a new customer container for the shared-hostname gateway.
#
# All customers share arckon.riskraven.ai on port 80. This script creates the
# customer's Docker container, writes its proxy token, regenerates the gateway
# proxy-token map, and reloads nginx. No dedicated nginx vhost is needed.
#
# Usage: provision_customer.sh <customer_id> [public_ip] [tier] [expires] [max_seats] [customer_name] [port] [agent_token] [baseline_profile]
set -euo pipefail

CUSTOMER_ID="$1"
PUBLIC_IP="${2:-$(curl -sf http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip -H 'Metadata-Flavor: Google' || echo '34.58.90.147')}"
PUBLIC_ADMIN_URL="${PUBLIC_ADMIN_URL:-https://admin.riskraven.ai}"
PUBLIC_DASHBOARD_URL="${PUBLIC_DASHBOARD_URL:-https://arckon.riskraven.ai}"
PUBLIC_DASHBOARD_PORT="${PUBLIC_DASHBOARD_PORT:-80}"
TIER="${3:-standard}"
EXPIRES="${4:-}"
MAX_SEATS="${5:-5}"
CUSTOMER_NAME="${6:-$CUSTOMER_ID}"
PORT="${7:-80}"
if [ "$PORT" = "$PUBLIC_DASHBOARD_PORT" ]; then
  CUSTOMER_DASHBOARD_URL="$PUBLIC_DASHBOARD_URL"
else
  CUSTOMER_DASHBOARD_URL="http://${PUBLIC_IP}:${PORT}"
fi
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
NGINX_CONF_DIR="${NGINX_CONF_DIR:-/opt/sentinel-nginx/conf.d}"
NGINX_PROXY_TOKEN_DIR="${NGINX_PROXY_TOKEN_DIR:-/opt/sentinel-nginx/proxy-tokens}"
HOST_LICENSES_DIR="${HOST_LICENSES_DIR:-/opt/licenses}"
LICENSE_FILE="${HOST_LICENSES_DIR}/${CUSTOMER_ID}/license.json"
DATA_DIR="${SENTINEL_DATA_ROOT:-/opt/sentinel-data}/${CUSTOMER_ID}"
SPEND_SECRET_DIR="${SENTINEL_SPEND_SECRET_ROOT:-${SENTINEL_DATA_ROOT:-/opt/sentinel-data}/.spend-secrets}/${CUSTOMER_ID}/spend"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$DATA_DIR"
chown -R 999:999 "$DATA_DIR"
install -d -o 999 -g 999 -m 0700 "$SPEND_SECRET_DIR"

AGENT_TOKEN="${8:-}"
BASELINE_PROFILE="${9:-default}"
case "$BASELINE_PROFILE" in
  default|iso42001|atlas|financial|fedramp|fedramp_20x|cmmc|biotech|healthcare|lifesciences|owasp_agentic|eu_ai_act|professional_services) ;;
  *) BASELINE_PROFILE="default" ;;
esac
printf '{"profile":"%s"}\n' "$BASELINE_PROFILE" > "${DATA_DIR}/baseline_profile.json"
if [ -z "$AGENT_TOKEN" ] && [ -f "${DATA_DIR}/agent_token.txt" ]; then
  AGENT_TOKEN=$(cat "${DATA_DIR}/agent_token.txt")
fi

# This capability is known only to nginx and its backend. The backend must not
# accept caller-supplied identity headers merely because a proxy marker exists.
PROXY_TOKEN_FILE="${DATA_DIR}/proxy_token.txt"
if [ -f "$PROXY_TOKEN_FILE" ]; then
  PROXY_TOKEN=$(cat "$PROXY_TOKEN_FILE")
else
  PROXY_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  umask 077
  printf '%s\n' "$PROXY_TOKEN" > "$PROXY_TOKEN_FILE"
fi
install -d -m 0750 "$NGINX_PROXY_TOKEN_DIR"
umask 077
# Keep the per-customer file for restart_customer.sh and migrate scripts.
printf 'proxy_set_header X-Sentinel-Proxy-Token %s;\n' "$PROXY_TOKEN" \
  > "${NGINX_PROXY_TOKEN_DIR}/${CUSTOMER_ID}.conf"
if [ -z "$AGENT_TOKEN" ]; then
  AGENT_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  echo "$AGENT_TOKEN" > "${DATA_DIR}/agent_token.txt"
fi

# Build docker run args — conditionally mount license.json only if it exists
LICENSE_MOUNT=""
if [ -f "$LICENSE_FILE" ]; then
  LICENSE_MOUNT="-v ${LICENSE_FILE}:/app/license.json:ro"
fi

docker run -d \
  --name "$CONTAINER_NAME" \
  --network sentinel-net \
  --restart always \
  --label "sentinel.customer=${CUSTOMER_ID}" \
  --label "sentinel.tier=${TIER}" \
   -e "SENTINEL_AGENT_TOKEN_FILE=/app/data/agent_token.txt" \
   -e "SENTINEL_TRUSTED_PROXY_TOKEN=${PROXY_TOKEN}" \
   -e "SENTINEL_ADMIN_LOGOUT_URL=${PUBLIC_ADMIN_URL}/logout" \
   ${LICENSE_MOUNT} \
   -v "${DATA_DIR}:/app/data" \
   -v "${SPEND_SECRET_DIR}:/opt/sentinel-secrets/spend" \
   -v /opt/sentinel/releases:/app/releases:ro \
   mark-sentinel:latest \
  python3 server.py --no-browser --port 7331

# Connect to arckon-net so nginx can reach sentinel-admin for auth_request
docker network connect arckon-net "$CONTAINER_NAME"

# Regenerate the gateway proxy-token map so nginx can route to this customer.
bash "$SCRIPT_DIR/regenerate_proxy_token_map.sh"

# Remove any stale per-customer vhost from the old dedicated-port architecture.
rm -f "${NGINX_CONF_DIR}/${CUSTOMER_ID}.conf"

docker exec sentinel-nginx nginx -t
docker exec sentinel-nginx nginx -s reload
echo "Provisioned: ${CUSTOMER_ID} on ${PUBLIC_DASHBOARD_URL} (${TIER})"