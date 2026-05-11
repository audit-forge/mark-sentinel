# M.A.R.K. Sentinel — AI Security Audit Tool

Short summary
- M.A.R.K. Sentinel (ai-stig-audit) is a self-hosted AI security and compliance scanner that produces plain-English summaries for SMBs and framework-mapped compliance artifacts (SARIF/MD/JSON) for enterprise use (FedRAMP, CMMC, NIST AI RMF).

Quick links
- Phase 4 (SMB polish & packaging branch): phase4/smb-packaging — https://github.com/audit-forge/mark-sentinel/pull/2
- Release (v0.1.0-phase3): https://github.com/audit-forge/mark-sentinel/releases/tag/v0.1.0-phase3

1) SMB Quickstart (Plain English)

This section gets a non-technical user from zero to a readable security report in three commands.

Requirements
- Windows 10/11, Linux, or macOS
- Python 3.9+ installed (https://www.python.org/downloads/)
  - Windows: check "Add Python to PATH" during installation
- Optional: pandoc + wkhtmltopdf (for PDF report generation)

Install and run — Windows

```powershell
# clone (if needed)
git clone https://github.com/audit-forge/mark-sentinel.git
cd mark-sentinel

# One-command installer (PowerShell — recommended)
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

# OR: plain batch installer (no PowerShell required)
scripts\install.bat

# Run a sample config-mode scan
.venv\Scripts\python.exe audit.py --mode config --profile smb --target test\fixtures\deploy-hardened --output plain

# Scan your own project directory
.venv\Scripts\python.exe audit.py --mode config --target C:\path\to\your\project --profile smb --output plain
```

Install and run — Linux / macOS

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

Example plain-English output (trimmed)

```
AI Safety Check — Your Results
================================
Overall: ⚠️ Some issues found (3 of 12 checks flagged)

🔴 RISK: System prompt disclosure (AI-OUT-003)
  What this means: The agent can reveal its system prompt when prompted.
  What to do: Use provider features to lock the system prompt and add input filters.

🟡 WARNING: No logging enabled (AI-DEPLOY-003)
  What this means: If something goes wrong, you have no record of the conversation.
  What to do: Enable conversation logging and rotate logs regularly.

✅ PASS: API keys not found in repo (AI-DEPLOY-001)

Next steps (15–60 minutes)
- Add an input filter to strip suspicious tokens from user prompts
- Enable basic logging retention for 30 days
- Re-run the quick scan after fixes
```

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

FAQ (SMB-friendly)
Q: I ran the scan — is my data sent anywhere?
A: No. The tool runs locally and does not transmit your files unless you explicitly configure a remote connector.

Q: How long does a scan take?
A: A config-mode scan on a small directory typically takes < 30 seconds. Live API probes depend on network latency and may take up to a few minutes.

Q: I’m not technical — who can help?
A: Open an issue on GitHub or email the maintainer (see repo contact). The SMB Quickstart provides step-by-step commands.

Support
- Open an issue on GitHub or email the maintainer.



---

© 2026 M.A.R.K. AI Systems. All rights reserved. Patent Pending.
M.A.R.K. Sentinel is protected by U.S. and international copyright law.
