#!/bin/bash
# /opt/arckon-deploy/deploy.sh on the production VM (mark-sentinel).
# Polls gs://arckon-deploy-artifacts/latest/manifest.json for new deployments,
# run every 60s by the arckon-deploy.timer systemd unit.
#
# This is the source of truth for that VM-side script — after changing it
# here, copy it up to /opt/arckon-deploy/deploy.sh on the box (it is not
# fetched automatically; there is no bootstrap step that pulls it from git).
set -euo pipefail

BUCKET="gs://arckon-deploy-artifacts/latest"
STATE_FILE="/opt/arckon-deploy/last_sha"
TMP="/tmp/arckon-deploy-$$"
mkdir -p "$TMP"
trap "rm -rf $TMP" EXIT

# Fetch manifest
gsutil cp "$BUCKET/manifest.json" "$TMP/manifest.json" 2>/dev/null || exit 0
NEW_SHA=$(python3 -c "import json; print(json.load(open('$TMP/manifest.json'))['sha'])")

# Compare with last deployed SHA
LAST_SHA=""
[ -f "$STATE_FILE" ] && LAST_SHA=$(cat "$STATE_FILE")

if [ "$NEW_SHA" = "$LAST_SHA" ]; then
  exit 0
fi

echo "[arckon-deploy] New deployment: $NEW_SHA (was: ${LAST_SHA:-none})"

# Download artifacts — compiled binaries plus a tarball of the full
# application source (all top-level *.py, connectors/, checks/, profiles/).
# A hand-picked file list here previously missed alerts.py, storage.py,
# connectors/, and several other lazily-imported modules, so anything
# changed in those files silently never reached production.
gsutil cp "$BUCKET/agent"       "$TMP/agent"
gsutil cp "$BUCKET/audit"       "$TMP/audit"
gsutil cp "$BUCKET/app.tar.gz"  "$TMP/app.tar.gz"

chmod +x "$TMP/agent" "$TMP/audit"
mkdir -p "$TMP/app"
tar xzf "$TMP/app.tar.gz" -C "$TMP/app"

# license.json is a per-customer bind mount inside the running container. It
# must never be delivered by a generic application release or docker cp will
# fail trying to replace the mounted file.
rm -f "$TMP/app/license.json"

# Deploy into the running container
docker cp "$TMP/agent"   sentinel-mfdynamicsllc:/app/agent
docker cp "$TMP/audit"   sentinel-mfdynamicsllc:/app/audit
docker cp "$TMP/app/."   sentinel-mfdynamicsllc:/app/
docker restart sentinel-mfdynamicsllc

# Record deployed SHA
echo "$NEW_SHA" > "$STATE_FILE"
echo "[arckon-deploy] Deployed $NEW_SHA successfully"
