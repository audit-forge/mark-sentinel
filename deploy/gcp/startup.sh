#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl

git clone https://github.com/audit-forge/mark-sentinel.git /opt/sentinel

cd /opt/sentinel
python3 -m venv /opt/sentinel/venv
/opt/sentinel/venv/bin/pip install -q -r requirements.txt

cat > /etc/systemd/system/sentinel.service <<'EOF'
[Unit]
Description=M.A.R.K. Sentinel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/sentinel
ExecStart=/opt/sentinel/venv/bin/python3 /opt/sentinel/server.py --no-browser --port 7331
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentinel
systemctl start sentinel
