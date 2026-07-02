#!/usr/bin/env bash
# Rebuild the mark-sentinel Docker image and restart all customer containers.
# Run this after pushing code changes to the GCP VM.
# Usage: redeploy.sh [--no-build]
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/sentinel}"
BUILD=true
if [ "${1:-}" = "--no-build" ]; then
  BUILD=false
fi

if $BUILD; then
  echo "==> Building mark-sentinel:latest..."
  docker build --no-cache -t mark-sentinel:latest "$REPO_DIR"
  echo "    Build complete."
fi

# Find all running customer containers by label
CUSTOMERS=$(docker ps --filter "label=sentinel.customer" --format "{{.Labels}}" \
  | grep -oP 'sentinel\.customer=\K[^,]+' || true)

if [ -z "$CUSTOMERS" ]; then
  echo "No customer containers running."
  exit 0
fi

echo "==> Restarting customer containers: $CUSTOMERS"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for CUSTOMER_ID in $CUSTOMERS; do
  echo ""
  echo "--- ${CUSTOMER_ID} ---"
  bash "${SCRIPT_DIR}/restart_customer.sh" "$CUSTOMER_ID"
done

echo ""
echo "==> Redeploy complete."
