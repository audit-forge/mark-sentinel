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
NGINX_CONF_DIR="${NGINX_CONF_DIR:-/opt/sentinel/deploy/gcp/nginx}"
# Use the host-side path (admin container maps /opt/licenses → /licenses internally)
HOST_LICENSES_DIR="${HOST_LICENSES_DIR:-/opt/licenses}"
LICENSE_FILE="${HOST_LICENSES_DIR}/${CUSTOMER_ID}/license.json"
DATA_DIR="${SENTINEL_DATA_ROOT:-/opt/sentinel-data}/${CUSTOMER_ID}"

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
  -v "${LICENSE_FILE}:/app/license.json:ro" \
  -v "${DATA_DIR}:/app/data" \
  mark-sentinel:latest \
  python3 server.py --no-browser --port 7331

mkdir -p "$NGINX_CONF_DIR"

# Every identity header the customer container is willing to trust from this
# proxy (it reads the X-Sentinel-* spelling first and falls back to X-Arckon-*),
# blanked. nginx forwards client request headers to the upstream by default and
# drops only the ones explicitly set to an empty string, so any location that
# does not run the /_auth subrequest has to blank all of them — otherwise a
# browser can simply send "X-Sentinel-User-Role: admin" and the container,
# which trusts this proxy, believes it.
IDENTITY_CLEAR=$(cat <<'CLEAR'
        proxy_set_header X-Arckon-User-Email      "";
        proxy_set_header X-Arckon-User-Role       "";
        proxy_set_header X-Arckon-Customer-ID     "";
        proxy_set_header X-Arckon-Client-Org-ID   "";
        proxy_set_header X-Sentinel-User-Email    "";
        proxy_set_header X-Sentinel-User-Role     "";
        proxy_set_header X-Sentinel-Customer-ID   "";
        proxy_set_header X-Sentinel-Client-Org-ID "";
CLEAR
)

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
${IDENTITY_CLEAR}
    }

    location /api/agent/ {
        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
${IDENTITY_CLEAR}
        proxy_read_timeout 300;
        proxy_buffering off;
    }

    location ~ ^/(bundle\.tar\.gz|agent\.py)$ {
        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Authorization \$http_authorization;
${IDENTITY_CLEAR}
        # Bundle generation tars the whole codebase on the fly (~45s). The
        # nginx default proxy_read_timeout (60s) leaves almost no margin for
        # slower client connections or server load, so downloads intermittently
        # truncate mid-stream and the installer reports a false "connectivity"
        # failure. Match the generous timeout used by the other proxied blocks.
        proxy_read_timeout 300;
        proxy_buffering off;
    }

    location /install/ {
        proxy_pass http://user-manager:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
${IDENTITY_CLEAR}
    }

    location / {
        auth_request /_auth;
        error_page 401 403 = @login_redirect;
        # /auth/verify answers with the caller's *current* identity (it re-reads
        # the users table on every request, so a role change, a client-org move
        # or a deactivation lands here immediately). Capture each header it
        # returns; every one of them must then be re-set below, because
        # auth_request_set values are not forwarded on their own.
        auth_request_set \$arckon_user_email \$upstream_http_x_arckon_user_email;
        auth_request_set \$arckon_user_role  \$upstream_http_x_arckon_user_role;
        auth_request_set \$arckon_client_org \$upstream_http_x_arckon_client_org_id;

        proxy_pass http://${CONTAINER_NAME}:7331;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Arckon-User-Email      \$arckon_user_email;
        proxy_set_header X-Arckon-User-Role       \$arckon_user_role;
        # Pinned to this vhost's own customer, not to the verifier's answer: a
        # super_admin's session carries no customer_id, and an empty value here
        # would send the container looking for the 'default' tenant's data.
        # /auth/verify has already rejected any other customer's session.
        proxy_set_header X-Arckon-Customer-ID     ${CUSTOMER_ID};
        proxy_set_header X-Arckon-Client-Org-ID   \$arckon_client_org;
        # Legacy spelling, set from the same verified values rather than left
        # alone: the container prefers X-Sentinel-* over X-Arckon-*, so a
        # client-supplied copy would otherwise win over the verifier's.
        proxy_set_header X-Sentinel-User-Email    \$arckon_user_email;
        proxy_set_header X-Sentinel-User-Role     \$arckon_user_role;
        proxy_set_header X-Sentinel-Customer-ID   ${CUSTOMER_ID};
        proxy_set_header X-Sentinel-Client-Org-ID \$arckon_client_org;
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
