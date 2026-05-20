#!/usr/bin/env bash
set -euo pipefail

PROJECT="infra-analyzer-496922-p0"
ZONE="us-central1-a"
VM_NAME="mark-sentinel"

echo "Deleting VM: $VM_NAME..."
gcloud compute instances delete "$VM_NAME" \
  --zone="$ZONE" \
  --project="$PROJECT" \
  --quiet

echo "Deleting firewall rule..."
gcloud compute firewall-rules delete sentinel-allow-dashboard \
  --project="$PROJECT" \
  --quiet

echo "Done. All Sentinel GCP resources deleted."
