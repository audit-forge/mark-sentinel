#!/usr/bin/env bash
# Provision a new customer container + nginx vhost.
# Usage: provision_customer.sh <customer_id> [public_ip] [tier] [expires] [max_seats] [customer_name] [port] [agent_token]
set -euo pipefail

CUSTOMER_ID="$1"
PUBLIC_IP="${2:-$(curl -sf http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip -H 'Metadata-Flavor: Google' || echo '34.58.90.147')}"
TIER="${3:-standard}"
EXPIRES="${4:-}"
MAX_SEATS="${5:-5}"
CUSTOMER_NAME="${6:-$CUSTOMER_ID}"
PORT="${7:-7001}"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
NGINX_CONF_DIR="${NGINX_CONF_DIR:-/opt/sentinel/deploy/gcp/nginx}"
HOST_LICENSES_DIR="${HOST_LICENSES_DIR:-/opt/licenses}"
LICENSE_FILE="${HOST_LICENSES_DIR}/${CUSTOMER_ID}/license.json"
DATA_DIR="${SENTINEL_DATA_ROOT:-/opt/sentinel-data}/${CUSTOMER_ID}"

mkdir -p "$DATA_DIR"
chown -R 999:999 "$DATA_DIR"

AGENT_TOKEN="${8:-}"
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
  ${LICENSE_MOUNT} \
  -v "${DATA_DIR}:/app/data" \
  mark-sentinel:latest \
  python3 server.py --no-browser --port 7331

# Connect to arckon-net so nginx can reach sentinel-admin for auth_request
docker network connect arckon-net "$CONTAINER_NAME"

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
        proxy_set_header X-Arckon-User-Email "";
        proxy_set_header X-Arckon-User-Role "";
        proxy_set_header X-Arckon-Customer-ID "";
        proxy_set_header X-Arckon-Client-Org-ID "";
        proxy_set_header X-Sentinel-User-Email "";
        proxy_set_header X-Sentinel-User-Role "";
        proxy_set_header X-Sentinel-Customer-ID "";
        proxy_set_header X-Sentinel-Client-Org-ID "";
    }

    # Agent/bundle/install routes bypass auth_request, so nothing here has
    # been vetted by /auth/verify. The upstream runs with
    # SENTINEL_TRUSTED_PROXY=1 and believes any X-Sentinel-* header it is
    # handed, so every one of them must be blanked out on these paths or a
    # caller could mint their own admin (or cross-tenant) identity.
    location /api/agent/ {
        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Sentinel-Proxy-Token "";
        proxy_set_header X-Arckon-User-Email "";
        proxy_set_header X-Arckon-User-Role "";
        proxy_set_header X-Arckon-Customer-ID "";
        proxy_set_header X-Arckon-Client-Org-ID "";
        proxy_set_header X-Arckon-Is-Reseller "";
        proxy_set_header X-Arckon-Is-MSP "";
        proxy_set_header X-Sentinel-User-Email "";
        proxy_set_header X-Sentinel-User-Role "";
        proxy_set_header X-Sentinel-Customer-ID "";
        proxy_set_header X-Sentinel-Client-Org-ID "";
        proxy_set_header X-Sentinel-Is-Reseller     "";
        proxy_set_header X-Sentinel-Is-MSP          "";
        proxy_set_header X-Sentinel-Impersonated-By "";
        proxy_read_timeout 300;
        proxy_buffering off;
    }

    location ~ ^/(bundle\.tar\.gz|agent\.py)$ {
        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Authorization \$http_authorization;
        proxy_set_header X-Sentinel-Proxy-Token "";
        proxy_set_header X-Arckon-User-Email "";
        proxy_set_header X-Arckon-User-Role "";
        proxy_set_header X-Arckon-Customer-ID "";
        proxy_set_header X-Arckon-Client-Org-ID "";
        proxy_set_header X-Arckon-Is-Reseller "";
        proxy_set_header X-Arckon-Is-MSP "";
        proxy_set_header X-Sentinel-User-Email "";
        proxy_set_header X-Sentinel-User-Role "";
        proxy_set_header X-Sentinel-Customer-ID "";
        proxy_set_header X-Sentinel-Client-Org-ID "";
        proxy_set_header X-Sentinel-Is-Reseller     "";
        proxy_set_header X-Sentinel-Is-MSP          "";
        proxy_set_header X-Sentinel-Impersonated-By "";
        proxy_read_timeout 300;
    }

    location /releases/ {
        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Authorization \$http_authorization;
        proxy_set_header X-Sentinel-Proxy-Token "";
        proxy_set_header X-Arckon-User-Email "";
        proxy_set_header X-Arckon-User-Role "";
        proxy_set_header X-Arckon-Customer-ID "";
        proxy_set_header X-Arckon-Client-Org-ID "";
        proxy_set_header X-Arckon-Is-Reseller "";
        proxy_set_header X-Arckon-Is-MSP "";
        proxy_set_header X-Sentinel-User-Email "";
        proxy_set_header X-Sentinel-User-Role "";
        proxy_set_header X-Sentinel-Customer-ID "";
        proxy_set_header X-Sentinel-Client-Org-ID "";
        proxy_set_header X-Sentinel-Is-Reseller     "";
        proxy_set_header X-Sentinel-Is-MSP          "";
        proxy_set_header X-Sentinel-Impersonated-By "";
        proxy_read_timeout 300;
    }

    location /install/ {
        proxy_pass http://sentinel-admin:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Sentinel-Proxy-Token "";
        proxy_set_header X-Arckon-User-Email "";
        proxy_set_header X-Arckon-User-Role "";
        proxy_set_header X-Arckon-Customer-ID "";
        proxy_set_header X-Arckon-Client-Org-ID "";
        proxy_set_header X-Arckon-Is-Reseller "";
        proxy_set_header X-Arckon-Is-MSP "";
        proxy_set_header X-Sentinel-User-Email "";
        proxy_set_header X-Sentinel-User-Role "";
        proxy_set_header X-Sentinel-Customer-ID "";
        proxy_set_header X-Sentinel-Client-Org-ID "";
        proxy_set_header X-Sentinel-Is-Reseller     "";
        proxy_set_header X-Sentinel-Is-MSP          "";
        proxy_set_header X-Sentinel-Impersonated-By "";
    }

    location / {
        auth_request /_auth;
        error_page 401 403 = @login_redirect;
        # Every identity header /auth/verify emits is captured and re-set below.
        # A header that is captured but not proxy_set_header'd
        # is silently replaced by whatever the browser sent; a client_viewer
        # whose Client-Org-ID never arrives is what let one tenant read the
        # whole MSP fleet.
        auth_request_set \$sentinel_user_email      \$upstream_http_x_arckon_user_email;
        auth_request_set \$sentinel_user_role       \$upstream_http_x_arckon_user_role;
        auth_request_set \$sentinel_client_org_id   \$upstream_http_x_arckon_client_org_id;
        auth_request_set \$sentinel_is_reseller     \$upstream_http_x_arckon_is_reseller;
        auth_request_set \$sentinel_is_msp          \$upstream_http_x_arckon_is_msp;
        auth_request_set \$sentinel_verified_user_email      \$upstream_http_x_sentinel_user_email;
        auth_request_set \$sentinel_verified_user_role       \$upstream_http_x_sentinel_user_role;
        auth_request_set \$sentinel_verified_client_org_id   \$upstream_http_x_sentinel_client_org_id;
        auth_request_set \$sentinel_verified_is_reseller     \$upstream_http_x_sentinel_is_reseller;
        auth_request_set \$sentinel_verified_is_msp          \$upstream_http_x_sentinel_is_msp;
        auth_request_set \$sentinel_impersonated_by \$upstream_http_x_sentinel_impersonated_by;

        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Sentinel-Proxy-Token ${PROXY_TOKEN};
        proxy_set_header X-Arckon-User-Email      \$sentinel_user_email;
        proxy_set_header X-Arckon-User-Role       \$sentinel_user_role;
        proxy_set_header X-Arckon-Customer-ID     ${CUSTOMER_ID};
        proxy_set_header X-Arckon-Client-Org-ID   \$sentinel_client_org_id;
        proxy_set_header X-Arckon-Is-Reseller     \$sentinel_is_reseller;
        proxy_set_header X-Arckon-Is-MSP          \$sentinel_is_msp;
        proxy_set_header X-Sentinel-User-Email      \$sentinel_verified_user_email;
        proxy_set_header X-Sentinel-User-Role       \$sentinel_verified_user_role;
        proxy_set_header X-Sentinel-Customer-ID     ${CUSTOMER_ID};
        proxy_set_header X-Sentinel-Client-Org-ID   \$sentinel_verified_client_org_id;
        proxy_set_header X-Sentinel-Is-Reseller     \$sentinel_verified_is_reseller;
        proxy_set_header X-Sentinel-Is-MSP          \$sentinel_verified_is_msp;
        proxy_set_header X-Sentinel-Impersonated-By \$sentinel_impersonated_by;
        proxy_read_timeout 300;
        proxy_buffering off;
    }

    location @login_redirect {
        return 302 http://${PUBLIC_IP}/login?next=http://\$host:\$server_port\$request_uri;
    }
}
EOF
chmod 600 "${NGINX_CONF_DIR}/${CUSTOMER_ID}.conf"

docker exec sentinel-nginx nginx -s reload
echo "Provisioned: ${CUSTOMER_ID} at http://${PUBLIC_IP}:${PORT} (${TIER})"
