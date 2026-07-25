# Arckon Edge DNS Sensor

Status: v1.0.0 scaffold. This component parses authorized resolver logs locally,
matches reviewed AI provider domains, and emits minimized JSON Lines events. It
does not currently upload to Arckon SaaS; the authenticated tenant ingestion API,
event persistence, dashboard, alerts, remote configuration, and update channel
are the next implementation milestone.

## What It Observes

The sensor supports query logs from `dnsmasq` and Unbound. It records only
matched events with a timestamp, sensor ID, client IPv4 address, queried domain,
provider, category, and confidence. It does not retain raw lines, DNS responses,
packet captures, prompts, or TLS content.

DNS observation means that a device requested a provider-associated domain. It
does not prove a user submitted a prompt, uploaded data, or completed a session.

The sensor only covers DNS traffic made visible by its deployment source. A
workstation, VM, or standard Kubernetes pod cannot observe other Wi-Fi clients
unless it receives DNS logs, is the resolver, or is placed on an authorized
gateway/mirror path. Encrypted DNS, VPNs, cellular data, and alternate resolvers
may bypass it.

## Local Test

Use a copy of an authorized resolver log. The `--once` option reads existing
lines and prints only AI-domain matches as JSON Lines:

```bash
python3 edge_dns.py --source dnsmasq --sensor-id lab-dns-01 \
  --log-file /var/log/dnsmasq.log --once
```

For continuous tailing, omit `--once`. Write a local JSONL spool instead of
stdout with `--out-file /var/lib/arckon-edge/events.jsonl`.

## Docker / Customer-Managed VM

Copy the resolver logs to, or mount them into, a small customer-managed Linux VM.
Set the variables below and start the sensor:

```bash
export ARCKON_SENSOR_ID=customer-site-a
export ARCKON_DNS_LOG_DIR=/var/log
export ARCKON_DNS_LOG_FILE=dnsmasq.log
export ARCKON_DNS_SOURCE=dnsmasq
docker compose -f deploy/edge-dns/docker-compose.yml up -d --build
```

The sensor has no network listener and no elevated packet-capture permissions.
For production, the eventual SaaS uploader must use an outbound-only,
tenant-scoped TLS connection and local encrypted credential storage.

## Kubernetes

`deploy/k8s/arckon-edge-dns.yaml` is a log-ingestion template, not a network
sniffer. Replace its example `hostPath` with a read-only PVC or a supported
log-forwarding sidecar that exposes the DNS resolver log. Update the image,
sensor ID, source, and log filename before applying it.

## Provider Catalog

`edge_ai_domains.json` is the reviewed initial catalog. Match only first-party
provider domains or domains with a documented high-confidence association; do
not add shared CDN domains. Catalog changes should be reviewed, versioned, and
auditable before release.

## SaaS Integration Contract

The future ingestion API should accept the emitted event schema in batches,
authenticate each sensor with a tenant-scoped credential, enforce schema and
rate limits, deduplicate events, and retain only customer-configured data. It
must not accept arbitrary raw DNS logs by default.
