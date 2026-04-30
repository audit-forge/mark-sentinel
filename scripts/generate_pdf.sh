#!/usr/bin/env bash
# Simple script: run a config scan and convert the compliance markdown output to PDF (requires pandoc)
set -euo pipefail
OUT_MD="output/artifacts/hardened_run.md"
OUT_PDF="output/artifacts/hardened_run.pdf"

# Ensure virtualenv
if [ ! -d ".venv" ]; then
  echo "Virtualenv not found. Run ./scripts/install.sh first or create a .venv"
  exit 1
fi

. .venv/bin/activate

# Run a quick config scan (uses 'smb' profile by default)
python3 audit.py --mode config --profile smb --target test/fixtures/deploy-hardened --output compliance,plain --out-file output/artifacts/hardened_run

# Convert to PDF using pandoc
if command -v pandoc >/dev/null 2>&1; then
  pandoc "$OUT_MD" -o "$OUT_PDF" && echo "PDF written: $OUT_PDF"
else
  echo "pandoc not found — install pandoc to generate PDF. Markdown report is at: $OUT_MD"
fi
