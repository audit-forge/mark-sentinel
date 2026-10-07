#!/usr/bin/env bash
set -euo pipefail

CUSTOMER_ID="$1"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
NGINX_CONF_DIR="${NGINX_CONF_DIR:-/opt/sentinel-nginx/conf.d}"
NGINX_PROXY_TOKEN_DIR="${NGINX_PROXY_TOKEN_DIR:-/opt/sentinel-nginx/proxy-tokens}"
HOST_LICENSES_DIR="${HOST_LICENSES_DIR:-/opt/licenses}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true
rm -f "${NGINX_CONF_DIR}/${CUSTOMER_ID}.conf"
rm -f "${NGINX_PROXY_TOKEN_DIR}/${CUSTOMER_ID}.conf"
rm -rf "${HOST_LICENSES_DIR}/${CUSTOMER_ID}"
bash "$SCRIPT_DIR/regenerate_proxy_token_map.sh"
docker exec sentinel-nginx nginx -s reload 2>/dev/null || true

echo "Removed: $CUSTOMER_ID"
