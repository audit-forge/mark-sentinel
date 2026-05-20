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

cat > /opt/sentinel/deploy/gcp/.env <<EOF
SECRET_KEY=${SECRET_KEY}
ADMIN_EMAIL=keith@mfdynamics.ai
ADMIN_PASSWORD=$(openssl rand -base64 16)
PUBLIC_IP=${PUBLIC_IP}
EOF

# ── Start stack ───────────────────────────────────────────────────────────────
chmod +x /opt/sentinel/deploy/gcp/provision_customer.sh
chmod +x /opt/sentinel/deploy/gcp/remove_customer.sh

cd /opt/sentinel/deploy/gcp
docker compose up -d --build

echo "Sentinel stack is up."
echo "Admin panel: http://admin.${PUBLIC_IP}.nip.io"
echo "Credentials in: /opt/sentinel/deploy/gcp/.env"
