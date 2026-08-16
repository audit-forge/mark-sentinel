# Cloudflare Tunnel for Arckon

Use a named Cloudflare Tunnel rather than a proxied DNS record to the VM. The
tunnel makes outbound-only connections, so Arckon does not need a public port,
an origin TLS certificate, or Cloudflare IP firewall allowlists.

## Create the tunnel

1. In the Cloudflare dashboard, open **Zero Trust**.
2. Select **Networks** -> **Tunnels** -> **Create a tunnel**.
3. Choose **Cloudflared**, name it `arckon-gcp`, and copy the Docker token.
4. Do not paste the token into chat, source control, or a compose file.
5. Install the token on the VM through an interactive IAP session:

```bash
gcloud compute ssh mark-sentinel \
  --project=infra-analyzer-496922-p0 \
  --zone=us-central1-a \
  --tunnel-through-iap \
  -- -t 'sudo bash /opt/sentinel/deploy/gcp/configure_cloudflare_tunnel.sh'
```

The script reads the token without echoing it and writes it to
`/opt/sentinel-secrets/cloudflare-tunnel-token`, mode `0400`, readable only by
Cloudflared's unprivileged container UID. Its parent directory remains
root-only.

## Public hostnames

After the connector is healthy, add these public hostnames to the tunnel:

| Hostname | Service |
| --- | --- |
| `arckon.riskraven.ai` | `http://sentinel-nginx:7001` |
| `admin.riskraven.ai` | `http://sentinel-nginx:80` |

Cloudflare creates the required proxied DNS records. Remove the existing
proxied `A` record for `arckon.riskraven.ai`; it must not point directly at the
VM after the tunnel route is active.

## Cloudflare settings

1. In **SSL/TLS**, use **Full (strict)**. The tunnel terminates the public TLS
   connection; do not select Flexible.
2. Leave the Cloudflare proxy enabled for both hostnames.
3. Do not expose port `7001` publicly after the tunnel has been verified.

## Verify

```bash
sudo docker logs --tail 50 sentinel-cloudflared
curl -I https://arckon.riskraven.ai/
```

The connector log should show connected tunnel sessions. The public URL should
return the Arckon login flow rather than a Cloudflare 522 error.
