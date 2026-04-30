#!/usr/bin/env bash
# One-command installer for SMBs: installs into a virtualenv and prints next steps.
set -euo pipefail
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "Installation complete. To run a quick scan: source .venv/bin/activate && python3 audit.py --mode config --target test/fixtures/deploy-hardened --output compliance --out-file output/artifacts/hardened_run"
