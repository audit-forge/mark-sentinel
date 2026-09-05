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

## 1.0.42 — 2026-09-05

### Fixed
- Release promotion manifest now records the SHA of the checked-out release tag rather than the workflow's default-branch SHA, ensuring the production deployer applies every tagged release.

## 1.0.41 — 2026-09-05

### Fixed
- Protected Cloud Assets now creates and stores a dedicated per-customer CloudTrail forwarder token with `0600` permissions, rather than relying on an environment variable. Dashboard admins can reveal it explicitly for forwarder configuration.

## 1.0.40 — 2026-09-05

### Added
- **Protected Cloud Assets (AWS S3)**: explicit bucket/prefix policies with optional `Criticality=Critical` tag matching, authenticated CloudTrail S3 data-event ingestion, idempotency by CloudTrail event ID, tamper-evident event storage, CRITICAL alerts, dashboard policy/event views, and a least-privilege deployment guide.

## 1.0.39 — 2026-09-05

### Added
- **Active issue detail panel**: click any active issue card to open a modal with full details — check ID, device, severity, last-seen timestamp, and the full finding description. False Positive / Accept Risk / Close buttons available inside the panel. Esc key or backdrop click closes it.

## 1.0.38 — 2026-09-04

### Added
- **Alert detail panel**: click any alert in the Alert History feed to open a modal with full details — event type, check ID, device, host, process, source, status, channels, timestamp, and alert ID. Close with the Close button, Esc key, or clicking outside. "Mark reviewed" is available from inside the panel too.

## 1.0.37 — 2026-09-04

### Fixed (macOS Protected Files reliability)
- ES collector daemon now **sleep-and-retries on ERR_NOT_PERMITTED** (Full Disk Access not granted) instead of exiting, eliminating launchd's crash-loop "penalty box" that prevented auto-recovery once FDA was granted.
- LaunchDaemon plist adds `ThrottleInterval` (5s) to prevent launchd penalty-box throttling.
- **Agent now auto-starts the ES daemon** if the LaunchDaemon is dead (penalty-box, never installed, or post-FDA grant), so Protected Files monitoring works without manual intervention on non-managed Macs.
- `install.sh` now **opens System Settings → Full Disk Access** directly and clears stale launchd penalty-box state on reinstall.
- `.pkg` postinstall reports daemon state clearly and tells the user the actionable next step.

### Changed
- Protected Files access alert severity raised from **HIGH → CRITICAL** (an AI process reading a protected/secret file is a critical-signal event).

## 1.0.36 — 2026-09-04

### Added
- Protected Files monitoring agent collector: macOS EndpointSecurity (ES) bridge, Linux auditd collector, Windows Event Log collector, AI-process path correlation, bounded event queue, and `post_access_events()` uploader.
- Agent handles `set_protected_paths:` command and auto-starts the platform-appropriate collector on scan cycles.
- `install.sh` auto-installs auditd (Linux) and the signed ArckonESCollector.app + LaunchDaemon (macOS).

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
