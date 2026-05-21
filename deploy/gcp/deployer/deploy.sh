#!/bin/sh
LOCK=/tmp/deploying
cleanup() { rm -f "$LOCK"; echo "[deployer] Lock released"; }
trap cleanup EXIT

REPO_DIR="${REPO_DIR:-/opt/sentinel}"

echo "[deployer] Starting deploy at $(date)"
cd "$REPO_DIR"

git pull
echo "[deployer] Git pull complete"

cd "$REPO_DIR/deploy/gcp"
docker compose up -d --build --no-deps user-manager
echo "[deployer] Deploy complete at $(date)"
