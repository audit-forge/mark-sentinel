#!/bin/bash
# Thin wrapper around scripts/publish_release.py with production defaults.
# Usage:
#   ./scripts/publish_release.sh v1.0.17
#
# Override any default by exporting the corresponding environment variable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export ARCKON_RELEASE_HOST="${ARCKON_RELEASE_HOST:-mark-sentinel}"
export ARCKON_RELEASE_HOST_ZONE="${ARCKON_RELEASE_HOST_ZONE:-us-central1-a}"
export ARCKON_RELEASE_HOST_PROJECT="${ARCKON_RELEASE_HOST_PROJECT:-infra-analyzer-496922-p0}"
# Leave ARCKON_RELEASE_HOST_USER unset to use the active gcloud account.

if [ $# -ne 1 ]; then
    echo "Usage: $0 <tag>" >&2
    echo "Example: $0 v1.0.17" >&2
    exit 1
fi

TAG="$1"
python3 "${SCRIPT_DIR}/publish_release.py" "$TAG"
