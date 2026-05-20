#!/usr/bin/env bash
set -euo pipefail

PROJECT="infra-analyzer-496922-p0"
ZONE="us-central1-a"
VM_NAME="mark-sentinel"

IP=$(gcloud compute instances describe "$VM_NAME" \
  --zone="$ZONE" \
  --project="$PROJECT" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null || echo "")

STATUS=$(gcloud compute instances describe "$VM_NAME" \
  --zone="$ZONE" \
  --project="$PROJECT" \
  --format='value(status)' 2>/dev/null || echo "NOT FOUND")

echo "VM:        $VM_NAME"
echo "Status:    $STATUS"
echo "Public IP: ${IP:-"(not assigned yet)"}"
if [[ -n "$IP" ]]; then
  echo "Dashboard: http://$IP:7331"
fi
