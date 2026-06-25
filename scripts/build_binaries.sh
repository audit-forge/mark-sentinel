#!/usr/bin/env bash
# build_binaries.sh — compile agent and audit binaries for linux/amd64
# Run this on your Mac before building/deploying the Docker image.
#
# Requires: Docker with buildx (comes with Docker Desktop)
# Output:   dist/audit   — scanner binary (never distributed to customers)
#           dist/agent   — agent binary   (shipped to customers via bundle.tar.gz)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO_ROOT/dist"
mkdir -p "$DIST"

echo "==> Building linux/amd64 binaries via Docker buildx..."

# Use a temporary builder container with Nuitka to cross-compile for linux/amd64.
# This avoids needing GCC/Nuitka installed locally and ensures the binary
# matches the target platform regardless of whether you're on Apple Silicon.

docker buildx build \
  --platform linux/amd64 \
  --file "$REPO_ROOT/scripts/Dockerfile.build" \
  --output "type=local,dest=$DIST" \
  "$REPO_ROOT"

echo ""
echo "==> Built binaries:"
ls -lh "$DIST"/audit "$DIST"/agent 2>/dev/null || echo "  WARNING: one or both binaries missing"
echo ""
echo "==> Done. Run 'docker compose build' to bake them into the server image."
