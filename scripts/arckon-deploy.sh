#!/bin/bash
# Installed host code only. Never fetch or execute deployment scripts from GCS.
set -euo pipefail
if [[ "${1:-}" != "--poll" || "$#" != 1 ]]; then
  echo "Deployment disabled without explicit --poll. Run upgrade_customer_security.py and manually approve host readiness first. No files copied or containers restarted." >&2
  exit 1
fi
exec /opt/sentinel/venv/bin/python /opt/sentinel/scripts/promote_deployment.py poll \
  --bucket gs://arckon-deploy-artifacts --state-dir /opt/arckon-deploy
