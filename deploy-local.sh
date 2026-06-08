#!/bin/bash
# Build mark-sentinel locally on Mac (Nuitka), then push to GCP and recreate the container.
set -euo pipefail

PROJECT="infra-analyzer-496922-p0"
ZONE="us-central1-a"
VM="mark-sentinel"
IMAGE="mark-sentinel:latest"
CONTAINER="sentinel-mfdynamicsllc"
SENTINEL_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_TAR="/tmp/mark-sentinel-$(date +%s).tar.gz"

echo "==> Building $IMAGE locally for linux/amd64 (this takes 15-20 min with Nuitka)..."
docker build --platform linux/amd64 -t "$IMAGE" "$SENTINEL_DIR"

echo "==> Saving image to $TMP_TAR..."
docker save "$IMAGE" | gzip > "$TMP_TAR"
SIZE=$(du -sh "$TMP_TAR" | cut -f1)
echo "    Image archive: $SIZE"

echo "==> Uploading to GCP ($VM)..."
gcloud compute scp "$TMP_TAR" "$VM":/tmp/mark-sentinel.tar.gz \
    --project="$PROJECT" --zone="$ZONE"
rm -f "$TMP_TAR"

echo "==> Loading image on GCP and recreating container..."
gcloud compute ssh "$VM" --project="$PROJECT" --zone="$ZONE" --command="
set -e
echo '  -> Loading image...'
sudo docker load < /tmp/mark-sentinel.tar.gz
sudo rm -f /tmp/mark-sentinel.tar.gz

echo '  -> Stopping old container...'
sudo docker stop $CONTAINER 2>/dev/null || true
sudo docker rm   $CONTAINER 2>/dev/null || true

echo '  -> Starting new container...'
sudo docker run -d \
    --name $CONTAINER \
    --network sentinel-net \
    --restart always \
    -e SENTINEL_TRUSTED_PROXY=1 \
    -e SENTINEL_AGENT_TOKEN=3rn1MGzsh3KgNc1NuopD7LJk-isKoxmk3Pwv_QsC6NY \
    -e SENTINEL_ADMIN_URL=http://sentinel-admin:8000 \
    -v /opt/licenses/mfdynamicsllc/license.json:/app/license.json \
    -v /opt/sentinel-data/mfdynamicsllc:/app/data \
    $IMAGE

echo '  -> Container status:'
sudo docker ps --filter name=$CONTAINER --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
"

echo ""
echo "==> Deploy complete. Sentinel is running the new Nuitka build."
