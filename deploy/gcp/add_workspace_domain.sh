#!/usr/bin/env bash
# Add an additional Google Workspace domain forwarder for an existing tenant.
#
# Each Workspace domain requires its own:
#   - Service account key (from the Google Cloud project for that domain)
#   - Delegated admin email (a Workspace admin for that domain)
#   - State file (so each domain polls independently)
#
# The ingest token is shared from the tenant's primary directory.
#
# Usage:
#   add_workspace_domain.sh <customer_id> <workspace_domain> <admin_email> <service_account_key_path>
#
# Example:
#   add_workspace_domain.sh mfdynamicsllc riskraven.ai admin@riskraven.ai ./sa-riskraven.json
set -euo pipefail

CUSTOMER_ID="$1"
DOMAIN="$2"
ADMIN_EMAIL="$3"
SA_KEY_PATH="$4"

INSTANCE="${CUSTOMER_ID}-${DOMAIN}"

# Validate arguments
if [ -z "$CUSTOMER_ID" ] || [ -z "$DOMAIN" ] || [ -z "$ADMIN_EMAIL" ] || [ -z "$SA_KEY_PATH" ]; then
    echo "Usage: $0 <customer_id> <workspace_domain> <admin_email> <service_account_key_path>" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root" >&2
    exit 1
fi

if [ ! -f "$SA_KEY_PATH" ]; then
    echo "Service account key not found: $SA_KEY_PATH" >&2
    exit 1
fi

# Check that the primary tenant forwarder exists
PRIMARY_ENV="/etc/arckon-drive-forwarder/${CUSTOMER_ID}.env"
if [ ! -f "$PRIMARY_ENV" ]; then
    echo "Primary tenant env file not found: $PRIMARY_ENV" >&2
    echo "Provision the tenant first with provision_customer.sh" >&2
    exit 1
fi

# Read the ingest token path from the primary tenant
PRIMARY_TOKEN="/opt/sentinel-secrets/${CUSTOMER_ID}/drive-forwarder-ingest-token"
if [ ! -f "$PRIMARY_TOKEN" ]; then
    echo "Primary ingest token not found: $PRIMARY_TOKEN" >&2
    exit 1
fi

# Read ARCKON_URL from the primary env file, or construct it
ARCKON_URL=$(grep '^ARCKON_URL=' "$PRIMARY_ENV" | cut -d= -f2- || true)
if [ -z "$ARCKON_URL" ]; then
    ARCKON_URL="http://sentinel-${CUSTOMER_ID}:7331"
fi

# Create the per-domain env file
ENV_FILE="/etc/arckon-drive-forwarder/${INSTANCE}.env"
cat > "$ENV_FILE" <<EOF
# Additional Google Workspace Drive audit forwarder for ${CUSTOMER_ID} domain ${DOMAIN}
ADMIN_EMAIL=${ADMIN_EMAIL}
WORKSPACE_DOMAIN=${DOMAIN}
ARCKON_URL=${ARCKON_URL}
EOF
chmod 600 "$ENV_FILE"

# Install the service account key
SECRET_DIR="/opt/sentinel-secrets/${INSTANCE}"
mkdir -p "$SECRET_DIR"
chmod 700 "$SECRET_DIR"
install -m 600 "$SA_KEY_PATH" "${SECRET_DIR}/drive-forwarder-service-account.json"

# Symlink the ingest token from the primary tenant
ln -sf "$PRIMARY_TOKEN" "${SECRET_DIR}/drive-forwarder-ingest-token"

# Create the state directory
STATE_DIR="/opt/sentinel-data/${INSTANCE}/drive-forwarder-state"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

# Enable and start the timer for this domain
systemctl enable "arckon-gworkspace-drive-forwarder@${INSTANCE}.timer"
systemctl start "arckon-gworkspace-drive-forwarder@${INSTANCE}.timer"

echo "Added Workspace domain forwarder: ${INSTANCE}"
echo "  Domain:         ${DOMAIN}"
echo "  Admin email:    ${ADMIN_EMAIL}"
echo "  Arckon URL:     ${ARCKON_URL}"
echo "  Timer:          arckon-gworkspace-drive-forwarder@${INSTANCE}.timer"
echo ""
echo "Verify the service account has domain-wide delegation for:"
echo "  https://www.googleapis.com/auth/admin.reports.audit.readonly"
echo "  in the ${DOMAIN} Google Workspace Admin Console."
