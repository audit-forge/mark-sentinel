#!/usr/bin/env bash
# One-time maintenance action: apply staged Ubuntu packages, then reboot once.
set -euo pipefail

LOG_FILE="/var/log/arckon-os-maintenance.log"
exec >>"$LOG_FILE" 2>&1

date -u '+%Y-%m-%dT%H:%M:%SZ starting Arckon OS maintenance'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
date -u '+%Y-%m-%dT%H:%M:%SZ packages updated; rebooting'
systemctl reboot
