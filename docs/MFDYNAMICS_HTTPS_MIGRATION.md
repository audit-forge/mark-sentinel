# MFDynamics HTTPS And Signed-Update Migration

## Scope and invariants

This is an operator runbook for moving MFDynamics customers from public,
dedicated direct ports to hostname-based HTTPS and signed agent updates without
an outage. The migration is complete: all customer traffic now flows through
Cloudflare Tunnel to nginx on port 80, routed by `server_name`. The
`7001-7100` port range has been removed from `deploy/gcp/docker-compose.yml`
and the corresponding GCP firewall rule (`sentinel-customer-ports`) has been
deleted. No customer-facing ports are exposed publicly.

The update client accepts only `https` origins, verifies a pinned Ed25519
signature, requires a newer version, and verifies artifact size and SHA-256.
The server's `/releases/current/` route requires an agent bearer token. Do not
claim signed updates are available until all proxy and release gates pass.

Run the repository-only checks before requesting access:

```sh
scripts/mfdynamics_https_preflight.sh
```

Use the optional live, read-only checks only in the approved change window:

```sh
scripts/mfdynamics_https_preflight.sh --iap \
  --project PROJECT_ID --zone ZONE --instance INSTANCE \
  --https-host updates.example.com \
  --cohort-file /restricted/path/canary-customer-ids.txt
```

`--iap` uses `gcloud compute ssh --tunnel-through-iap`; it never falls back to
public SSH. The script does not print, read, pass, or log token values, private
keys, cookies, or authorization headers. Its remote commands only inspect
configuration validity, file metadata, listener state, HTTP status, and counts.

## Release gates

All gates are required. Record command output, UTC timestamp, change ticket,
release version, artifact SHA-256, manifest SHA-256, manifest signature SHA-256,
and approver in the change evidence location. Do not put credentials in it.

1. **HTTPS gate:** the canonical hostname resolves to the intended HTTPS
   ingress; a TLS 1.2+ handshake validates with the production CA; the
   certificate SAN includes the hostname; and unauthenticated
   `https://HOST/releases/current/manifest.json` returns `401`, not a redirect,
   `200`, or a certificate error. Stop immediately on any TLS failure. Do not
   bypass validation with `-k`, HTTP, an IP address, or a temporary certificate.
2. **Proxy gate:** nginx has an explicit `/releases/current/` location that
   proxies to the correct customer backend, forwards only the incoming
   `Authorization` header, and clears all `X-Arckon-*`, `X-Sentinel-*`, and
   proxy-capability headers. It must not route releases through browser
   `auth_request` or permit client-supplied authenticated identity headers.
   Validate with `nginx -t` before reload; a reload is a later, separately
   approved change.
3. **Signed-release gate:** run `scripts/create_release.py` only in the
   approved signing environment. It must produce canonical `manifest.json`,
   `manifest.sig`, and the named artifact; the private key must match the pinned
   public key. Independently verify the manifest signature, artifact SHA-256,
   exact artifact size, product `sentinel-agent`, and strictly newer numeric
   version. The signing key never resides in the repository, release directory,
   command line, or evidence.
4. **Release-permission gate:** the deployed release root is
   `/opt/sentinel/releases/current` unless the approved deployment specifies a
   different mounted root. It must be a non-symlink directory owned by `root`
   and the web-service read group (default `nginx`), mode `0750`; regular
   release files must be non-symlink, `root:nginx`, mode `0640`, and none may be
   group- or world-writable. `manifest.json`, `manifest.sig`, and the manifest's
   artifact must exist and be non-empty. Confirm the container mount is
   read-only and maps this exact root to the server's `releases/current` path.
5. **Cohort/token gate:** prepare a restricted, one-customer-ID-per-line
   canary file with no tokens. Every listed customer must have an active device
   cohort, a non-empty per-customer `agent_token.txt`, and the token file must
   be `root:root 0600` with no group/world access. Record customer and device
   counts, token-presence count, and the SHA-256 of the sorted ID list, never
   token values or token hashes. The IAP preflight compares that list digest and
   count with on-host customer data directories.
6. **Backup/rollback gate:** before any ingress or agent setting changes,
   create and verify a restore-tested backup of nginx configuration, compose
   inputs, customer data/database, release directory, and the prior signed
   release. Record immutable backup URI/version, SHA-256, creation time,
   restore-test time, restore-test operator, and successful `nginx -t` result.
   Keep the prior artifact, manifest, and signature available. A backup that
   only exists is not rollback evidence.

Any failed gate is a stop condition. Keep current ports unchanged, make no
agent update request, and open a remediation/change record.

## Canary and rollback

1. Select a small, representative, consented cohort across OS/version/customer
   boundaries. Exclude critical or unmanaged devices. Freeze its customer IDs,
   device count, current agent versions, and expected token-presence count in
   the evidence record.
2. Enable the HTTPS release route for the canary while leaving each existing
   direct port and vhost operational. Validate one authorized request per
   customer with an approved test agent, never by putting a bearer token in a
   shell history, URL, curl command, ticket, or log.
3. Request update checks in bounded batches. For each batch, collect release
   version, signature/hash acceptance, download success, restart time, check-in
   health, command/telemetry continuity, and errors. Compare counts to the
   frozen cohort after each batch and observe for the agreed soak period.
4. Roll back immediately for TLS failure, signature/hash failure, unexpected
   customer/device association, token-auth failure, health regression, or a
   missed batch threshold. Stop new updates; restore the prior ingress and
   signed release from the verified backup; leave direct ports open; validate
   both the restored canary and a direct-port control device. Record the
   decision, timestamps, operator, artifacts, and validation result.
5. Expand only after the canary's signed update, restart, and post-restart
   health evidence is approved. Repeat batch evidence for every cohort.

## Closure gate

The direct-port retirement is complete. The `7001-7100` port range has been
removed from `deploy/gcp/docker-compose.yml`, the GCP firewall rule
`sentinel-customer-ports` has been deleted, and the per-customer port-7001
nginx vhost (`mfdynamicsllc.conf`) has been replaced by a shared port-80 vhost
(`arckon.conf`) that routes by `server_name`. All customer traffic flows
through Cloudflare Tunnel to nginx on port 80. No customer-facing ports are
exposed publicly.
