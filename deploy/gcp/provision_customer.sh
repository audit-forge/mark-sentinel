#!/usr/bin/env bash
set -euo pipefail

CUSTOMER_ID="$1"
PUBLIC_IP="${2:-35.255.19.236}"
TIER="${3:-standard}"
EXPIRES="${4:-}"
MAX_SEATS="${5:-5}"
CUSTOMER_NAME="${6:-$CUSTOMER_ID}"
PORT="${7:-7001}"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
NGINX_CONF_DIR="/opt/sentinel/deploy/gcp/nginx"
LICENSE_FILE="/licenses/${CUSTOMER_ID}/license.json"
DATA_DIR="/opt/sentinel-data/${CUSTOMER_ID}"

mkdir -p "$DATA_DIR"
chown -R 999:999 "$DATA_DIR"

AGENT_TOKEN="${8:-}"
if [ -z "$AGENT_TOKEN" ] && [ -f "${DATA_DIR}/agent_token.txt" ]; then
  AGENT_TOKEN=$(cat "${DATA_DIR}/agent_token.txt")
fi
if [ -z "$AGENT_TOKEN" ]; then
  AGENT_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  echo "$AGENT_TOKEN" > "${DATA_DIR}/agent_token.txt"
fi

docker run -d \
  --name "$CONTAINER_NAME" \
  --network sentinel-net \
  --restart always \
  --label "sentinel.customer=${CUSTOMER_ID}" \
  --label "sentinel.tier=${TIER}" \
  -e "SENTINEL_AGENT_TOKEN=${AGENT_TOKEN}" \
  -v "${LICENSE_FILE}:/opt/sentinel/license.json:ro" \
  -v "${DATA_DIR}:/app/output" \
  mark-sentinel:latest \
  python3 server.py --no-browser --port 7331

mkdir -p "$NGINX_CONF_DIR"
cat > "${NGINX_CONF_DIR}/${CUSTOMER_ID}.conf" <<EOF
server {
    listen ${PORT};
    server_name _;

    location = /_auth {
        internal;
        proxy_pass http://user-manager:8000/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Customer-ID ${CUSTOMER_ID};
        proxy_set_header Cookie \$http_cookie;
    }

    location / {
        auth_request /_auth;
        error_page 401 403 = @login_redirect;

        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 300;
        proxy_buffering off;
    }

    location @login_redirect {
        return 302 http://${PUBLIC_IP}/login?next=http://\$host:\$server_port\$request_uri;
    }
}
EOF

docker exec sentinel-nginx nginx -s reload
echo "Provisioned: http://${PUBLIC_IP}:${PORT} (${TIER})"
