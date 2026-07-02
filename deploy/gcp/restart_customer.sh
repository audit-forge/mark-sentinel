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
  -e "SENTINEL_AGENT_TOKEN=${AGENT_TOKEN}" \
  -e "SENTINEL_TRUSTED_PROXY=1" \
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
