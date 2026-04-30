# SMB Guide — Quick Start (Plain English)

This guide helps a non-technical user run a basic M.A.R.K. Sentinel check and
understand the results.

Prerequisites
- A computer with Python 3.9+ installed
- The ai-stig-audit repo checked out (or download the release tarball)
- Optional: Ollama running locally for live model checks

Quick start (10 minutes)
1. Open a terminal.
2. Install the one required dependency (optional but recommended):
   pip install -r requirements.txt
3. Run a config-only quick check on the example fixtures:
   python audit.py --mode config --profile smb --target test/fixtures/deploy-hardened --output plain

How to read the results
- Overall result: at the top you will see PASS/WARN/FAIL summary and a short sentence.
- Findings: each finding includes a short title, why it matters, and a simple "What to do".
- If you see anything marked CRITICAL or FAIL, stop and follow the remediation steps (they are actionable and prioritized).

What non-technical users should check first
- API keys: If the tool reports exposed API keys, rotate them immediately and contact your developer.
- Authentication: If the tool warns that your AI endpoint has no authentication, do not expose it to the internet — change the settings or take the service offline until fixed.
- Data retention & policy: If the report says there is no data retention policy or AI usage policy, create a short one-page policy and store it in your internal wiki.

Getting help
- If you run into errors running the tool, collect the output (plain or SARIF) and attach it to an issue in the project repository.
- For pilot support, follow the steps in docs/PILOT_TESTER_HANDOFF.md and include the artifacts produced.

Notes
- This guide is for the SMB profile which focuses on plain-English output and prioritized remediation.
- For compliance-grade reports (FedRAMP/CMMC) run the fedramp or cmmc profile and request the compliance.md artifact.
