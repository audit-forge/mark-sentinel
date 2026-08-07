#!/usr/bin/env bash
# Safely restart a customer container — stop, remove, recreate with correct config.
# Called by sentinel-admin when licenses/config change.
# Usage: restart_customer.sh <customer_id>
set -euo pipefail

CUSTOMER_ID="$1"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"
DATA_DIR="/opt/sentinel-data/${CUSTOMER_ID}"
HOST_LICENSES_DIR="${HOST_LICENSES_DIR:-/opt/licenses}"
LICENSE_FILE="${HOST_LICENSES_DIR}/${CUSTOMER_ID}/license.json"

if [ ! -d "$DATA_DIR" ]; then
  echo "ERROR: data dir $DATA_DIR not found" >&2
  exit 1
fi

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

# Migrate existing generated vhosts before replacing their backend. nginx
# overwrites this header, so direct callers never learn the capability.
NGINX_CONF_DIR="${NGINX_CONF_DIR:-/opt/sentinel/deploy/gcp/nginx}"
NGINX_CONF="${NGINX_CONF_DIR}/${CUSTOMER_ID}.conf"
if [ -f "$NGINX_CONF" ]; then
  python3 - "$NGINX_CONF" "$CONTAINER_NAME" "$PROXY_TOKEN" <<'PY'
import sys

path, container, token = sys.argv[1:]
content = open(path, encoding="utf-8").read()
needle = f"proxy_pass http://{container}:7331;"
protected_start = content.find("    location / {")
protected_end = content.find("    location @login_redirect", protected_start)
if protected_start < 0 or protected_end < 0:
    raise SystemExit(f"expected authenticated location not found in {path}")
protected = content[protected_start:protected_end]
if needle not in protected:
    raise SystemExit(f"expected upstream {container!r} not found in {path}")
if "X-Sentinel-Proxy-Token" not in protected:
    protected = protected.replace(
        needle, needle + f"\n        proxy_set_header X-Sentinel-Proxy-Token {token};", 1)
    with open(path, "w", encoding="utf-8") as output:
        output.write(content[:protected_start] + protected + content[protected_end:])
PY
fi

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
  ${LICENSE_MOUNT} \
  -v "${DATA_DIR}:/app/data" \
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

docker exec sentinel-nginx nginx -s reload
echo "Done: ${CONTAINER_NAME} restarted and nginx reloaded."
