# M.A.R.K. Sentinel — AI Security Audit Tool

Short summary
- M.A.R.K. Sentinel (ai-stig-audit) is a self-hosted AI security and compliance scanner that produces plain-English summaries for SMBs and framework-mapped compliance artifacts (SARIF/MD/JSON) for enterprise use (FedRAMP, CMMC, NIST AI RMF).

Quick links
- Phase 4 (SMB polish & packaging branch): phase4/smb-packaging — https://github.com/audit-forge/mark-sentinel/pull/2
- Release (v0.1.0-phase3): https://github.com/audit-forge/mark-sentinel/releases/tag/v0.1.0-phase3

1) SMB Quickstart (Plain English)

This section gets a non-technical user from zero to a readable security report in three commands.

Requirements
- Linux/macOS with Python 3.11+ installed
- Optional: pandoc + wkhtmltopdf (for PDF report generation)

Install and run (one-command install + quick scan)

```bash
# clone (if needed)
git clone https://github.com/audit-forge/mark-sentinel.git
cd mark-sentinel

# One-command installer (creates a local virtualenv and installs runtime deps)
./scripts/install.sh

# Run a sample config-mode scan and write plain-English + compliance output
source .venv/bin/activate
python3 audit.py --mode config --profile smb --target test/fixtures/deploy-hardened --output compliance,plain --out-file output/artifacts/hardened_run

# Read the plain-English report
less output/artifacts/hardened_run.md

# Optional: produce a PDF (requires pandoc + wkhtmltopdf)
pandoc output/artifacts/hardened_run.md -o output/artifacts/hardened_run.pdf
```

What the report contains (SMB-friendly)
- One-line overall status (PASS / WARN / FAIL)
- Short explanation of each failing item in plain English (what it means and a suggested fix)
- A short prioritized next-steps checklist (15–60 minute fixes where applicable)

2) Enterprise / Developer README (developer-oriented)

This section is for engineers, auditors, and CI integrators who need artifacts and automation.

Running scans (dev)
```bash
# local virtualenv
source .venv/bin/activate

# run a live API probe (requires API endpoint creds)
python3 audit.py --mode api --target https://api.example.com --profile fedramp --output sarif,json,compliance --out-file output/artifacts/hardened_run

# docker/k8s mode (requires docker or kubectl access)
python3 audit.py --mode docker --target <container-id> --output sarif,json --out-file output/artifacts/hardened_run
```

CI / packaging notes
- We publish SARIF and JSON artifacts for CI systems to consume.
- Phase 4 will add a Docker image build workflow and a PyPI packaging flow (pyproject.toml included in Phase 4 scaffolding).

Support
- Open an issue on GitHub or email the maintainer.

