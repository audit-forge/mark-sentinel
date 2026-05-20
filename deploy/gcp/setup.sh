#!/usr/bin/env bash
set -euo pipefail

PROJECT="infra-analyzer-496922-p0"
ZONE="us-central1-a"
VM_NAME="mark-sentinel"
MACHINE_TYPE="e2-small"
IMAGE_FAMILY="ubuntu-2204-lts"
IMAGE_PROJECT="ubuntu-os-cloud"
DISK_SIZE="20GB"
PORT=7331

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

gcloud config set project "$PROJECT" --quiet
gcloud config set compute/zone "$ZONE" --quiet

echo "Creating firewall rule..."
gcloud compute firewall-rules create sentinel-allow-dashboard \
  --allow "tcp:$PORT" \
  --target-tags sentinel-server \
  --description "M.A.R.K. Sentinel dashboard" \
  --project "$PROJECT" 2>/dev/null \
  || echo "Firewall rule already exists, skipping."

echo "Creating VM: $VM_NAME..."
gcloud compute instances create "$VM_NAME" \
  --machine-type="$MACHINE_TYPE" \
  --image-family="$IMAGE_FAMILY" \
  --image-project="$IMAGE_PROJECT" \
  --boot-disk-size="$DISK_SIZE" \
  --boot-disk-type="pd-standard" \
  --zone="$ZONE" \
  --tags=sentinel-server \
  --metadata-from-file=startup-script="$SCRIPT_DIR/startup.sh" \
  --project="$PROJECT"

echo ""
echo "VM created. Sentinel installs and starts automatically (~2 min)."
echo ""
echo "Run ./status.sh to get your dashboard URL once it's ready."
