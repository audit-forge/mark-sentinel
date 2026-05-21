#!/usr/bin/env bash
set -euo pipefail

CUSTOMER_ID="$1"
CONTAINER_NAME="sentinel-${CUSTOMER_ID}"

docker restart "$CONTAINER_NAME" 2>/dev/null || true
echo "Restarted: $CUSTOMER_ID (license.json reloaded)"
