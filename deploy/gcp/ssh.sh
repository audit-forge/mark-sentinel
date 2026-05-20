#!/usr/bin/env bash
set -euo pipefail

PROJECT="infra-analyzer-496922-p0"
ZONE="us-central1-a"
VM_NAME="mark-sentinel"

gcloud compute ssh "$VM_NAME" \
  --zone="$ZONE" \
  --project="$PROJECT"
