#!/usr/bin/env bash
set -euo pipefail

CUSTOMER_ID="$1"
PUBLIC_IP="${2:-35.255.19.236}"
TIER="${3:-standard}"
EXPIRES="${4:-}"
MAX_SEATS="${5:-5}"
CUSTOMER_NAME="${6:-$CUSTOMER_ID}"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
NGINX_CONF_DIR="/app/nginx/customers"
LICENSE_FILE="/licenses/${CUSTOMER_ID}/license.json"

docker run -d \
  --name "$CONTAINER_NAME" \
  --network sentinel-net \
  --restart always \
  --label "sentinel.customer=${CUSTOMER_ID}" \
  --label "sentinel.tier=${TIER}" \
  -v "${LICENSE_FILE}:/opt/sentinel/license.json:ro" \
  mark-sentinel:latest \
  python3 server.py --no-browser --port 7331

mkdir -p "$NGINX_CONF_DIR"
cat > "${NGINX_CONF_DIR}/${CUSTOMER_ID}.conf" <<EOF
server {
    listen 80;
    server_name ${CUSTOMER_ID}.${PUBLIC_IP}.nip.io;

    location / {
        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 300;
    }
}
EOF

docker exec sentinel-nginx nginx -s reload
echo "Provisioned: http://${CUSTOMER_ID}.${PUBLIC_IP}.nip.io (${TIER})"
