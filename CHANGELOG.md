# Changelog

All notable changes to this project will be documented in this file.

## 1.0.0 — 2026-07-31

### Added
- Signed agent release pipeline: pinned Ed25519 manifest signatures, immutable packaging, and automated GitHub release workflow.
- Agent self-update client: verifies HTTPS origin, pinned signature, newer numeric version, artifact size, and SHA-256 before applying any update.
- MFDynamics migration runbook and preflight script for hostname-based HTTPS / signed-update cutover.
- Tenant-aware proxy authentication with `X-Sentinel-Proxy-Token` and least-privilege default roles.
- Canned-response content for findings and Notion wiki integration.
- Docker image build workflow and PyPI packaging.
- SMB Quickstart guide, sample PDF report generator, and one-command installers for Linux/macOS/Windows.

### Changed
- Rebranded package metadata to `arckon` v1.0.0 and aligned Python requirement to 3.11+.
- Hardened deploy workflow: legacy GCS upload now requires explicit confirmation and no longer silently omits lazily-imported modules.

### Security
- Agent update path only trusts `https` origins and a pinned Ed25519 public key.
- Release artifacts are packaged with an allowlist and signed out-of-repo; private key never enters source control.
- Proxy identity headers are cleared on non-authenticated routes and require a shared proxy token.

## Unreleased (Phase 4: SMB polish & packaging)

### Added
- One-command installer (scripts/install.sh)
- SMB Quickstart + Sample PDF generator
- README polish and FAQ
- CI smoke workflow, Docker & PyPI workflow scaffolds

- One-command installer script
- SMB Quickstart guide (plain-English)
- Sample PDF report generator and template
- Docker image and Docker Hub publishing workflow
- PyPI packaging (pyproject.toml + sdist/wheel)
- README updates targeting both SMB and Enterprise audiences
