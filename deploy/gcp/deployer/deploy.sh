#!/bin/sh
set -eu

LOCK=/run/deployer/deploy.lock
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
    docker cp "$REPO_DIR/agent.py"             "$cname:/app/agent.py"              2>/dev/null || true
    docker restart "$cname" 2>/dev/null || true
    echo "[deployer] Patched and restarted $cname"
done

# Hot-patch the admin container with updated templates and installers
echo "[deployer] Patching sentinel-admin..."
docker cp "$REPO_DIR/admin/templates/."       "sentinel-admin:/app/templates/"       2>/dev/null || true
docker cp "$REPO_DIR/install.sh"                "sentinel-admin:/app/install.sh"        2>/dev/null || true
docker cp "$REPO_DIR/install.ps1"                "sentinel-admin:/app/install.ps1"      2>/dev/null || true
mkdir -p "$REPO_DIR/deploy" 2>/dev/null || true
docker exec sentinel-admin mkdir -p /app/deploy 2>/dev/null || true
docker cp "$REPO_DIR/deploy/install.sh"         "sentinel-admin:/app/deploy/install.sh" 2>/dev/null || true
docker restart sentinel-admin 2>/dev/null || true
echo "[deployer] Patched and restarted sentinel-admin"

cd "$REPO_DIR/deploy/gcp"
docker compose up -d --build --no-deps user-manager deployer
echo "[deployer] Deploy complete at $(date)"
