#!/bin/sh
LOCK=/tmp/deploying
cleanup() { rm -f "$LOCK"; echo "[deployer] Lock released"; }
trap cleanup EXIT

REPO_DIR="${REPO_DIR:-/opt/sentinel}"

echo "[deployer] Starting deploy at $(date)"
cd "$REPO_DIR"

git pull
echo "[deployer] Git pull complete"

# Hot-patch running customer containers with updated Python source files.
# This is necessary because mark-sentinel:latest is only rebuilt on new VM setup;
# Python source changes arrive via git pull and must be copied in live.
for cname in $(docker ps --format '{{.Names}}' | grep '^sentinel-' | grep -vE '^sentinel-(nginx|admin|deployer)$'); do
    echo "[deployer] Patching $cname..."
    docker cp "$REPO_DIR/server.py"            "$cname:/app/server.py"            2>/dev/null || true
    docker cp "$REPO_DIR/alerts.py"            "$cname:/app/alerts.py"            2>/dev/null || true
    docker cp "$REPO_DIR/eu_ai_act_report.py"  "$cname:/app/eu_ai_act_report.py"  2>/dev/null || true
    docker cp "$REPO_DIR/aibom_generator.py"   "$cname:/app/aibom_generator.py"   2>/dev/null || true
    docker cp "$REPO_DIR/connectors/."         "$cname:/app/connectors/"          2>/dev/null || true
    docker restart "$cname" 2>/dev/null || true
    echo "[deployer] Patched and restarted $cname"
done

cd "$REPO_DIR/deploy/gcp"
docker compose up -d --build --no-deps user-manager deployer
echo "[deployer] Deploy complete at $(date)"
