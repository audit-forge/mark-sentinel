#!/usr/bin/env bash
set -euo pipefail

CUSTOMER_ID="$1"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
NGINX_CONF_DIR="/app/nginx/customers"

docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true
rm -f "${NGINX_CONF_DIR}/${CUSTOMER_ID}.conf"
docker exec sentinel-nginx nginx -s reload 2>/dev/null || true

echo "Removed: $CUSTOMER_ID"
