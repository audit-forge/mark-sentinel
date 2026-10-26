#!/bin/bash
# Build arckon locally on Mac (Nuitka), then push to GCP and recreate the container.
set -euo pipefail

PROJECT="infra-analyzer-496922-p0"
ZONE="us-central1-a"
VM="arckon"
IMAGE="arckon:latest"
CONTAINER="arckon-mfdynamicsllc"
ARCKON_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_TAR="/tmp/arckon-$(date +%s).tar.gz"

echo "==> Building $IMAGE locally for linux/amd64 (this takes 15-20 min with Nuitka)..."
docker build --platform linux/amd64 -t "$IMAGE" "$ARCKON_DIR"

echo "==> Saving image to $TMP_TAR..."
docker save "$IMAGE" | gzip > "$TMP_TAR"
SIZE=$(du -sh "$TMP_TAR" | cut -f1)
echo "    Image archive: $SIZE"

echo "==> Uploading to GCP ($VM)..."
gcloud compute scp "$TMP_TAR" "$VM":/tmp/arckon.tar.gz \
    --project="$PROJECT" --zone="$ZONE"
rm -f "$TMP_TAR"

echo "==> Loading image on GCP and recreating container..."
gcloud compute ssh "$VM" --project="$PROJECT" --zone="$ZONE" --command="
set -e
echo '  -> Loading image...'
sudo docker load < /tmp/arckon.tar.gz
sudo rm -f /tmp/arckon.tar.gz

# Preserve the existing credential without putting it in source, output or argv.
# Refuse replacement if it cannot be recovered BEFORE stopping the old container.
TOKEN_ENV=\$(sudo mktemp /run/arckon-agent-env.XXXXXX)
trap 'sudo rm -f \"\$TOKEN_ENV\"' EXIT
sudo docker inspect $CONTAINER | sudo python3 -c '
import json, os, sys
items = json.load(sys.stdin)[0][\"Config\"][\"Env\"]
values = [v for v in items if v.startswith(\"ARCKON_AGENT_TOKEN=\")]
if len(values) != 1 or not values[0].split(\"=\", 1)[1] or any(c in values[0] for c in \"\\r\\n\"):
    sys.exit(\"Existing agent credential unavailable; refusing replacement\")
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
with os.fdopen(fd, \"w\") as stream:
    os.fchmod(stream.fileno(), 0o600)
    stream.write(values[0] + \"\\n\")
' \"\$TOKEN_ENV\"

echo '  -> Stopping old container...'
sudo docker stop $CONTAINER 2>/dev/null || true
sudo docker rm   $CONTAINER 2>/dev/null || true

echo '  -> Starting new container...'
sudo docker run -d \
    --name $CONTAINER \
    --network arckon-net \
    --restart always \
    -e ARCKON_TRUSTED_PROXY=1 \
    --env-file \"\$TOKEN_ENV\" \
    -e ARCKON_ADMIN_URL=http://arckon-admin:8000 \
    -v /opt/licenses/mfdynamicsllc/license.json:/app/license.json \
    -v /opt/arckon-data/mfdynamicsllc:/app/data \
    $IMAGE

echo '  -> Container status:'
sudo docker ps --filter name=$CONTAINER --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
"

echo ""
echo "==> Deploy complete. Arckon is running the new Nuitka build."
