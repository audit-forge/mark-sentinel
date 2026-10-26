# Security Rollout: 2026-10-26

## Compatibility Contract

Keep the shared admin JWT signing key, `token` cookie, cookie domain, and gateway
authentication routing unchanged. Enrollment administrators must retain working
Linux, macOS, MDM, and Windows installer credentials. Agent bearer endpoints do
not require browser Origin headers. Browser mutations require an explicitly
configured admin/dashboard Origin or Referer; internal admin relays preserve it.

The automated live smoke check uses transient test accounts, public TLS ingress,
and real password login. It verifies the shared cookie, immediate dashboard
access without a second login, authenticated APIs, administrator enrollment,
rejected cross-origin mutation, passive collection queueing, and logout. Test
accounts are removed in `finally`. This is HTTP-level verification, not a manual
Safari/Chrome UI test or a vulnerability-free certification.

## Existing-Tenant Upgrade

Never replace modules and restart an old container: it lacks the new key mount.
The old GCS hot-patch entrypoints intentionally refuse to deploy. Keep their
timer stopped until replaced with a reviewed full-image deployment workflow.

1. Build the reviewed image as `mark-sentinel:security-upgrade`.
2. Quiesce lifecycle automation and other database/config writers.
3. Run `scripts/upgrade_customer_security.py CUSTOMER --image
   mark-sentinel:security-upgrade --maintenance --legacy-dev-key` only after
   confirming that the tenant used the legacy fallback. Configured-key tenants
   require their actual old key, not the legacy flag.
4. The tool preserves legacy SIEM config, takes paired backups, authenticates and
   re-encrypts active and historical policy paths and SIEM credentials, verifies
   the result, and hands the key to UID 999 with mode 0400. It leaves the tenant
   stopped and does not change login credentials.
5. Start the admin service before lifecycle scripts run nginx configuration
   validation, because its upstream hostname must resolve.
6. Tag the reviewed image as `mark-sentinel:latest`, then use
   `deploy/gcp/restart_customer.sh CUSTOMER` and rerun live smoke checks.

Runtime keys reside outside writable tenant data at
`/opt/sentinel-data/.field-secrets/CUSTOMER/master-key`. Only that tenant's key is
mounted read-only at `/run/secrets/arckon_master_key`. Keys must be backed up
securely; replacing a key without re-encrypting its data loses readability.

If migration fails with a `.migration-pending` marker, keep writers stopped.
Follow the migration tool's paired recovery procedure. Restore SQLite through
its backup API and restore the matching SIEM config; never copy a live database
without its WAL, roll back only the key, or delete a marker to bypass recovery.

## Outbound Integrations

Public HTTP(S) destinations are validated and DNS-pinned. Redirects, ambient
proxies, metadata destinations, and unapproved private addresses are blocked.
TLS certificate verification cannot be disabled by tenant configuration.

Operators can approve a specific internal origin and address range through a
root-owned mode-0600 file at
`/opt/sentinel-data/.field-secrets/CUSTOMER/outbound-private-origins.json`:

```json
{"https://siem.internal:8088": ["10.20.30.40/32"]}
```

Use a trusted CA for internal HTTPS. Do not approve an entire private network or
enable a TLS bypass as a workaround. Endpoint discovery retains its separate
authorized private-network behavior.

The live inventory found an enabled integration targeting an unavailable test
receiver. Its owner authorized retirement rather than restoring forwarding.
The retirement tool removes only that exact test hostname and retains private
backups; it refuses to remove a real receiver. Issuer-side revocation cannot be
claimed for an unavailable retired service.

## Credential Hygiene And Limits

Local runtime license and SIEM files were moved to ignored `data/` paths without
discarding their contents. Their previous Git versions remain in history.
No provider credential rotation or destructive history rewrite was performed.
Retired test credentials are removed from active configurations, but retained
history and recovery evidence must still be treated as sensitive.

Agent changes are distributed through the signed three-platform release workflow,
gated on the exact tagged revision's full tests and extracted-runtime checks.
Windows/direct-Python
standalone deployments need explicit key and public-origin configuration.

## Verified Outcome

- Full repository pytest run: 729 passed (test-only signing secret, isolated admin
  dependencies installed). Legacy mock HTTP servers now explicitly approve only
  their own dynamically allocated loopback origins; production policy was not
  relaxed to make tests pass.
- Rendered dashboard JavaScript syntax and Git whitespace checks passed.
- All live tenants passed the public HTTPS single-login smoke test, both
  before and after another full container recreation.
- Corrected a root-owned proxy capability to backend UID 999/mode 0400;
  lifecycle scripts now enforce readability. This prevented a real second-login
  redirect detected by the live test.
- Runtime key/decryption and metadata-denial verification passed for every tenant.
- Rebuilt image verification confirms runtime SIEM credentials and licenses are
  absent from the image. Customer-specific mounts remain authoritative.
- Temporary live test users were removed. Existing signing keys, customer
  passwords, shared-cookie settings, and enrollment tokens were not rotated.

Paired migration backups reside below the tenant's operator-only field-secret
directory. Exact backup locations are recorded privately, not in source control.
Backups contain sensitive old data and must remain private. The old hot-patch
poller is replaced by signed image/catalog promotion with failure quarantine,
health gates, lifecycle-alias promotion, and image rollback.

## Release And Automation Closure

- The owner approved committing/pushing the reviewed changes and retiring the
  orphaned test integration. Active local and tenant configurations no longer
  contain that test receiver or its credential; private evidence is retained.
- `v1.0.69` was cancelled before publication after the dependency audit found
  advisories. Its tag was not moved or reused.
- `v1.0.70` was published at revision
  `9236358827a2f68db792ec21f1e652e9528f0dc5`, with all three signed update
  manifests, artifact hash checks, extracted-runtime checks, and 866 passing
  tests on the exact release revision. Server and admin dependencies both passed
  the known-vulnerability audit.
- The signed full-image/catalog deployment was applied and verified on the host.
  All public platform manifests serve `1.0.70`. The replacement systemd timer is
  enabled; subsequent polls succeed without redeploying an unchanged revision.
- Host bootstrap fixes retain `NoNewPrivileges` and `PrivateTmp`; the service
  uses the Cloud CLI executable directly, not its privilege-changing Snap launcher.
- A failed manual image rollout exercised rollback successfully. A subsequent
  canary/full rollout succeeded, followed by repeated public single-login checks.
- Enrollment smoke now validates the actual displayed token against gateway
  authority, including its tenant binding. A stale persisted token file was
  reconciled to its existing authoritative record; no credential was rotated.
- Final local verification: 877 tests passed, Ruff passed, and the combined
  server/admin dependency audit reported no known vulnerabilities. Security CI
  passed. Online macOS/Linux agents reported `1.0.70`; offline endpoints have
  update commands queued and cannot be claimed installed until they reconnect.

Release: https://github.com/audit-forge/mark-sentinel/releases/tag/v1.0.70

Signed build: https://github.com/audit-forge/mark-sentinel/actions/runs/40373547333

Immutable promotion: https://github.com/audit-forge/mark-sentinel/actions/runs/40382504468
