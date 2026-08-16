# Cloudflare Setup for Arckon — arckon.riskraven.ai

This guide connects the `arckon.riskraven.ai` subdomain to the live Arckon GCP VM using Cloudflare's Free plan.

## Live Arckon VM details

| Property | Value |
| --- | --- |
| GCP project | `infra-analyzer-496922-p0` |
| Instance name | `mark-sentinel` |
| Zone | `us-central1-a` |
| External IP | `34.58.90.147` |
| Internal IP | `10.128.0.2` |
| Admin panel (direct) | `http://admin.34.58.90.147.nip.io` |
| SSH user | `neepai` |

> Do not use the old `35.255.19.236` IP. It was replaced and no longer points to the Arckon VM.

## 1. Add `riskraven.ai` to Cloudflare

1. Log into the Cloudflare dashboard at `https://dash.cloudflare.com/`.
2. Navigate to **Add site** (or open `https://dash.cloudflare.com/<account-id>/add-site`).
3. Choose **Connect a domain**.
4. Enter `riskraven.ai` and click **Continue**.
5. Select the **Free** plan.
6. Review the DNS records Cloudflare discovers. Keep any existing records for other subdomains or services (e.g., MX, TXT, other A records).
7. Copy the two Cloudflare nameservers Cloudflare assigns to you.
8. At your current domain registrar / DNS provider for `riskraven.ai`, replace the existing nameservers with the two Cloudflare nameservers.
9. Return to Cloudflare and click **Done, check nameservers**. Propagation typically takes a few minutes to a few hours.

## 2. Create the `arckon` A record

Once `riskraven.ai` is active in Cloudflare:

1. Select the `riskraven.ai` zone.
2. Go to **DNS → Records**.
3. Click **Add record**.
4. Configure the record:

| Field | Value |
| --- | --- |
| Type | `A` |
| Name | `arckon` |
| IPv4 address | `34.58.90.147` |
| Proxy status | **Proxied** (orange cloud) |
| TTL | Auto |

5. Click **Save**.

This makes `arckon.riskraven.ai` resolve to the Arckon VM, with Cloudflare proxying and SSL in front.

## 3. Choose a Cloudflare SSL/TLS mode

The Arckon admin panel currently serves plain HTTP on port 80. In Cloudflare:

1. Go to **SSL/TLS → Overview**.
2. Select one of the following modes:

| Mode | When to use |
| --- | --- |
| **Flexible** | Use temporarily if the GCP VM does **not** yet have a valid TLS certificate. Traffic is encrypted from browser to Cloudflare, but Cloudflare connects to the origin over HTTP. |
| **Full (strict)** | Use once the VM has a valid, publicly trusted TLS certificate (e.g., Let's Encrypt). This is the recommended end state. |

> Do not leave Flexible enabled long-term. Plan to install a certificate on the VM and switch to Full (strict).

## 4. Lock down the GCP firewall to Cloudflare (recommended)

If the orange-cloud proxy is enabled, restrict inbound HTTP/HTTPS traffic on the GCP firewall to Cloudflare's IPv4 ranges:

```text
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
```

Apply this to the firewall rule(s) that allow traffic to the Arckon VM on ports `80` and `443`.

For initial testing, you may leave the source as `0.0.0.0/0` and tighten it after confirming the site works.

## 5. Update Arckon to know the new hostname

After DNS is live:

1. SSH into the VM:
   ```bash
   ssh neepai@34.58.90.147
   ```
   Or via IAP tunnel:
   ```bash
   gcloud compute ssh mark-sentinel --project=infra-analyzer-496922-p0 --zone=us-central1-a --tunnel-through-iap
   ```
2. Inspect how Arckon is started (e.g., `deploy/gcp/docker-compose.yml`, systemd units, or startup scripts in `/opt/sentinel/`).
3. If the app binds to a specific IP or references the old `nip.io` hostname, update it to `arckon.riskraven.ai`.
4. Restart the Arckon services as needed.

## 6. Verify the setup

From your local machine:

```bash
# Check DNS resolution
nslookup arckon.riskraven.ai

# If proxied, you should see Cloudflare IPs. If DNS-only, you should see 34.58.90.147.
dig arckon.riskraven.ai
```

Then visit:

```text
https://arckon.riskraven.ai
```

Confirm the Arckon admin panel loads and the certificate is valid.

## 7. Update other Arckon references

After the cutover, update any Arckon agent configs or documentation that still reference the old direct IP or `nip.io` hostname. Example files in this repository:

- `agent_config.json` — set `"server"` to the new origin if agents should use the Cloudflare hostname.
- Customer onboarding guides that mention `admin.34.58.90.147.nip.io`.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `DNS_PROBE_FINISHED_NXDOMAIN` | Nameservers not yet propagated or wrong record | Wait, or verify nameservers and A record |
| `521 Web Server Is Down` (Cloudflare error) | VM not listening on port 80/443 or firewall blocking Cloudflare | Check VM service and GCP firewall |
| `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` | SSL/TLS mode too strict for HTTP-only origin | Switch to Flexible temporarily, then add origin TLS |
| Browser shows invalid certificate | DNS-only mode or wrong SSL mode | Enable proxy or set correct SSL/TLS mode |

## Related runbooks

- `docs/MFDYNAMICS_HTTPS_MIGRATION.md` — full HTTPS and signed-agent-update migration procedure for MFDynamics customers.
- `ARCHITECTURE.md` — current Arckon architecture and VM details.
