#!/usr/bin/env bash
# Install a Cloudflare Tunnel token without putting it in shell history, Docker
# environment variables, compose files, or the application data volume.
set -euo pipefail

TOKEN_FILE="/opt/sentinel-secrets/cloudflare-tunnel-token"
COMPOSE_DIR="/opt/sentinel/deploy/gcp"

install -d -m 0700 /opt/sentinel-secrets
read -r -s -p "Cloudflare Tunnel token: " TUNNEL_TOKEN
printf '\n'
if [ -z "$TUNNEL_TOKEN" ]; then
  echo "ERROR: token is required" >&2
  exit 1
fi

umask 077
printf '%s' "$TUNNEL_TOKEN" > "$TOKEN_FILE"
unset TUNNEL_TOKEN
# cloudflared's distroless image runs as UID/GID 65532. This grants only that
# connector process read access; the host directory remains root-only.
chown 65532:65532 "$TOKEN_FILE"
chmod 0400 "$TOKEN_FILE"

docker compose --project-directory "$COMPOSE_DIR" up -d cloudflared
echo "Cloudflare Tunnel connector started. Configure public hostnames in Cloudflare Zero Trust."
