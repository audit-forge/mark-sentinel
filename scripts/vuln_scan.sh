#!/bin/bash
# Sentinel full vulnerability scan
# Usage: bash scripts/vuln_scan.sh
# Runs on the GCP VM via: gcloud compute ssh mark-sentinel ... --command "bash /opt/sentinel/scripts/vuln_scan.sh"

set -euo pipefail

GCP_PROJECT="infra-analyzer-496922-p0"
GCP_ZONE="us-central1-a"
GCP_VM="mark-sentinel"

echo "=============================="
echo "SENTINEL VULNERABILITY SCAN"
echo "=============================="
echo ""

# ── 1. Container image CVE scan ──────────────────────────────────────────────
echo "[ 1/4 ] Container CVE scan (trivy)"
for IMAGE in nginx:alpine mark-sentinel:latest gcp-user-manager:latest; do
  echo ""
  echo "--- $IMAGE ---"
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy:latest image --severity HIGH,CRITICAL --no-progress \
    "$IMAGE" 2>/dev/null \
    | grep -E "Total:|CRITICAL|HIGH|CVE-" | head -20 \
    || echo "  (scan failed or image not found)"
done

# ── 2. SECRET_KEY check ───────────────────────────────────────────────────────
echo ""
echo "[ 2/4 ] Admin SECRET_KEY check"
KEY_VAL=$(docker exec sentinel-admin env 2>/dev/null | grep SECRET_KEY | cut -d= -f2)
if [ -z "$KEY_VAL" ]; then
  echo "  CRITICAL: SECRET_KEY is empty — JWT tokens are forgeable"
elif [ ${#KEY_VAL} -lt 32 ]; then
  echo "  HIGH: SECRET_KEY is only ${#KEY_VAL} chars — should be 32+ random bytes"
else
  echo "  OK: SECRET_KEY is set (${#KEY_VAL} chars)"
fi

# ── 3. Unauthenticated endpoint probe ─────────────────────────────────────────
echo ""
echo "[ 3/4 ] Unauthenticated endpoint probe (via nginx)"
SENTINEL_PORT=$(docker inspect sentinel-nginx --format '{{json .HostConfig.PortBindings}}' 2>/dev/null \
  | python3 -c "import json,sys; p=json.load(sys.stdin); print(list(p.keys())[0].split('/')[0])" 2>/dev/null || echo "7001")

for EP in / /login /api/devices /api/fleet/shadow /api/fleet/inventory /api/scan \
           /api/config /api/users /api/system/update /api/system/restart-server; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://localhost:${SENTINEL_PORT}${EP}")
  if [ "$CODE" = "200" ]; then
    echo "  WARN  $CODE  $EP  (returned 200 without auth)"
  else
    echo "  ok    $CODE  $EP"
  fi
done

# ── 4. GCP firewall audit ─────────────────────────────────────────────────────
echo ""
echo "[ 4/4 ] Running containers"
docker ps --format "  {{.Names}}\t{{.Status}}\t{{.Image}}"

echo ""
echo "=============================="
echo "SCAN COMPLETE"
echo "=============================="
