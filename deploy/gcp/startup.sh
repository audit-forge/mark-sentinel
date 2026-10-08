#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── Docker ────────────────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg git openssl

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin

systemctl enable docker
systemctl start docker
docker network inspect arckon-net >/dev/null 2>&1 || docker network create arckon-net

# ── Clone repo ────────────────────────────────────────────────────────────────
git clone --branch feat/user-manager \
  https://github.com/audit-forge/mark-sentinel.git /opt/sentinel

# ── Build Sentinel image ──────────────────────────────────────────────────────
docker build -t mark-sentinel:latest /opt/sentinel

# ── Configure environment ─────────────────────────────────────────────────────
PUBLIC_IP=$(curl -sf \
  "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" \
  -H "Metadata-Flavor: Google")

SECRET_KEY=$(openssl rand -hex 32)

# Per-customer secrets live in a root-owned directory; tokens are generated
# with openssl and written mode 0400 so only the mounted container can read them.
install -d -m 0700 /opt/sentinel-secrets
[ -f /opt/sentinel-secrets/admin-secret-key ] || printf '%s\n' "$SECRET_KEY" > /opt/sentinel-secrets/admin-secret-key
[ -f /opt/sentinel-secrets/deployer-token ] || openssl rand -hex 32 > /opt/sentinel-secrets/deployer-token
# A separate, scoped token gates the /deploy route so the lifecycle token
# cannot trigger a full git pull + rebuild + restart of every customer.
[ -f /opt/sentinel-secrets/deployer-op-token ] || openssl rand -hex 32 > /opt/sentinel-secrets/deployer-op-token
[ -f /opt/sentinel-secrets/admin-password ] || openssl rand -base64 16 > /opt/sentinel-secrets/admin-password
chmod 0400 /opt/sentinel-secrets/*

mkdir -p /opt/licenses

cat > /opt/sentinel/deploy/gcp/.env <<EOF
SECRET_KEY=${SECRET_KEY}
ADMIN_EMAIL=keith@mfdynamics.ai
ADMIN_PASSWORD=$(openssl rand -base64 16)
PUBLIC_IP=${PUBLIC_IP}
MAX_CUSTOMERS=0
EOF

# ── Start stack ───────────────────────────────────────────────────────────────
chmod +x /opt/sentinel/deploy/gcp/provision_customer.sh
chmod +x /opt/sentinel/deploy/gcp/remove_customer.sh

cd /opt/sentinel/deploy/gcp
docker compose up -d --build

echo "Sentinel stack is up."
echo "Admin panel: http://admin.${PUBLIC_IP}.nip.io"
echo "Credentials in: /opt/sentinel/deploy/gcp/.env"
