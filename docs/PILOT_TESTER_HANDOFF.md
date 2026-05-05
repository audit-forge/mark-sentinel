# PILOT TESTER HANDOFF

This document explains how a pilot tester can run M.A.R.K. Sentinel (ai-stig-audit)
locally to validate the v1.0 feature set. It assumes the project is checked out
and Python 3.11+ is available.

Quick checklist
- Install dependencies: pip install -r requirements.txt
- Run fixture validation: pytest -q test/run_fixture_validation.py
- Run a config-mode scan (SMB profile):
  python audit.py --mode config --profile smb --output plain
- Run a local Ollama scan (if Ollama available):
  python audit.py --mode local --ollama-host http://localhost:11434 --model llama3 --output sarif,plain

What to validate
- Config mode should detect insecure baseline fixture and pass hardened fixture.
- SARIF output should be syntactically valid JSON (use `jq .` to validate).
- Plain English output should include human-friendly remediation guidance.

Reporting issues
- Open an issue in the repo with the following template:
  - command run
  - OS / Python version
  - output (attach SARIF or plain output)
  - any stacktrace or failing test logs

Notes for pilot testers
- The Phase 3 connectors (docker & kubectl) are implemented and unit-tested against
  repository fixtures. Live cluster scans are not performed in the default fixtures.
- Anthropic-specific live probes are deferred while Anthropic API access is restricted.
  Use Ollama or OpenAI-compatible endpoints for equivalent testing during the pilot.

Contact
- Project owner: Keith Ferguson
- Technical owner for handoff: Hash (local agent)
