# Incident: arckon-agent device token baked into mark-sentinel image layers

**Date:** 2026-08-24
**Device:** mark-sentinel (GCP `infra-analyzer-496922-p0`, `us-central1-a`, 34.58.90.147)
**Source:** RiskRaven / Arckon self-scan, `AI-DEPLOY-002` — No Hardcoded Credentials in Model Config
**Severity:** HIGH

## What happened

An untracked file `/opt/sentinel/agent_config.json` sat inside the `mark-sentinel`
Docker build context (`/opt/sentinel`, where `Dockerfile` does `COPY . .`). It held
a copy of the live arckon-agent device token (device `f70c3cd4e4cc62b5`, used by
`arckon-agent.service` to report scans to `https://arckon.riskraven.ai`) — confirmed
identical via SHA-256 comparison against `/etc/arckon/agent_config.json` and
`/etc/sentinel/agent_config.json`, not a stale/different value.

Because the file wasn't excluded by `.dockerignore` at the time, repeated
`docker build` runs baked it into `/app/agent_config.json` inside the image.
Confirmed present in 14 old containerd overlayfs layer snapshots on local disk.

**The compromised token itself was not rotated as part of this incident** — no
token-issuance or rotation path for the arckon-agent's own device credential
(device `f70c3cd4e4cc62b5`) was found anywhere in this codebase. `admin/app.py`'s
`/customers/rotate-token` only rotates customer EDR fleet tokens (e.g.
`mfdynamicsllc`), a separate system. Rotation is blocked pending identification of
the actual enrollment/rotation authority for the general Arckon fleet backend.

## Root cause

1. `_docker_context_credential_findings()` in `checks/deploy.py` only checked
   whether *any* Dockerfile anywhere in a scan does `COPY . .`, then flagged
   every `agent_config.json`/`agent_token.txt`/`.env`-shaped file found
   *anywhere in the whole scan*, not just inside that Dockerfile's own build
   context — and only ever looked up `.dockerignore` at the scan root, never at
   the Dockerfile's own directory. Fixed in commit `ee4b020`.
2. A stray, untracked `agent_config.json` sat inside `/opt/sentinel`'s build
   context. Root cause of *why* it was there is unknown — file was `chattr +i`
   immutable, owned by `neepai`, birth 2026-06-23. No script or systemd unit in
   this repo sets that flag.

## Files removed from the host (not from git — they were never tracked)

| Path | Mode | Attrs | SHA-256 | Removed |
|---|---|---|---|---|
| `/opt/sentinel/agent_config.json` | 0644, uid/gid 1001/1002 (neepai) | immutable (`i`) + extents (`e`) | `31c19b8335c3261e0e795a7c8c07206be814e1dcc692af97e14ff99269c70f43` | `chattr -i` + `shred -u -n 3`, verified absent |
| `/opt/sentinel/agent_token.txt` | 0600, owner neepai, June 13 | extents (`e`) only | not recorded | `rm -f`, verified absent |
| `/tmp/pharaoh-build/` | — | — | — | `rm -rf`, unrelated Pharaoh checkout, confirmed stale before removal |

Contents were never printed, logged, or copied anywhere in this incident's
record — only path, permissions, attributes, and hash.

**Confirmed before removal:** no *active* service referenced
`/opt/sentinel/agent_config.json`. `sentinel-agent.service` (a third,
disabled/inactive "Arckon Sentinel Agent" running `agent.py` via `venv312`)
does reference this exact path in its `ExecStart`, but was confirmed
dormant/deprecated and not slated for re-enablement before deletion proceeded.

## Remediation

- `checks/deploy.py`: scoped Docker-baked-credential detection to each
  Dockerfile's actual build-context directory and its own `.dockerignore`
  (`ee4b020`, tests in `tests/test_supply006_and_docker_context.py`)
- `.dockerignore` already excluded `agent_config.json`/`agent_token.txt`
  (earlier commit `05cfd94`) — confirmed the new image is clean
  (`docker run --rm mark-sentinel:latest sh -c 'ls /app/agent_config.json'` →
  `NOT_PRESENT`)
- `mark-sentinel:latest` rebuilt (`299421920764`, 2026-08-24 22:37:23 UTC)
  from `dist/audit`/`dist/agent` compiled fresh on-host from the fixed source
- `sentinel-mfdynamicsllc` restarted onto the rebuilt image, verified healthy
- Re-ran the production self-scan (`/opt/arckon/audit --target / --profile
  lifesciences`) with the freshly-compiled, fixed `audit` binary directly:
  `AI-DEPLOY-002` now returns `PASS`
- Both stray files removed from the host per the table above

## Still open

- **Device token rotation for `f70c3cd4e4cc62b5`** — blocked, no known
  rotation authority identified yet. Treat the leaked token as compromised
  until rotated.
- **Fleet-wide rollout of the check fix** — the running `arckon-agent.service`
  binary is still v1.0.19 (pre-fix). Planned: cut v1.0.20 from the fixed
  source through the normal signed-release workflow
  (`scripts/publish_release.py`), let the agent self-update through its
  normal signed-update path, then verify version and scan output.
