SMB Quickstart — Plain English guide

Goal: get a small business to run a basic safety scan with one command and understand the results.

1) Install (one-command)
   ./scripts/install.sh

2) Run a sample config scan (local files)
   source .venv/bin/activate
   python3 audit.py --mode config --profile smb --target test/fixtures/deploy-hardened --output compliance,plain --out-file output/artifacts/hardened_run

3) Read the plain-English report
   - output/artifacts/hardened_run.txt (or .md) contains a human-friendly summary: what failed, why it matters, and suggested fixes.

4) Share the PDF report with stakeholders
   - Use the sample PDF generator (see docs/SAMPLE_PDF_REPORT.md)

5) Support
   - For help, open an issue on GitHub or email the maintainer.
