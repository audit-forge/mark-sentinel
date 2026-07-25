# Arckon 30,000 Endpoint GCP Capacity And Cost Plan

## Executive Summary

The current Arckon deployment is appropriate for internal use and small pilots,
single GCP virtual machine with local SQLite storage, synchronous report
handling, and frequent agent polling. Scaling that virtual machine vertically
would not solve the underlying storage, availability, and command-delivery
limitations.

Arckon can support a 30,000-endpoint deployment after the platform is moved to
target is a regional high-availability deployment in us-central1, with a
planning infrastructure budget of $4,000 to $7,500 per month. The first phase
can be operated closer to $2,500 to $4,000 per month if it uses regional HA,
strict retention controls, and measured capacity limits.

This estimate excludes engineering payroll, 24/7 operations staffing,
third-party SIEM fees, customer identity-provider fees, SMS/email charges, and
customer-specific data-residency requirements.

## Current-State Assessment

Current deployment facts:

- One e2-small GCP VM with a 20 GB standard disk.
- Docker, nginx, admin, and tenant application containers share one host.
- Python ThreadingHTTPServer processes requests in one application process.
- SQLite files hold devices, reports, sessions, commands, and tenant data.
- Reports are parsed and stored synchronously in the request handler.
- Fleet reports and evidence exports load and process entire fleets in memory.
- Agents currently poll commands every 15 seconds.

These characteristics are acceptable for a pilot but create single points of
failure and serialized local-disk bottlenecks at enterprise fleet size.

## 30,000 Endpoint Planning Assumptions

| Assumption | Value |
| --- | --- |
| Endpoints | 30,000 |
| Region | us-central1 |
| Report cadence | One report per endpoint per day |
| Average compressed report payload | 100 KB |
| Raw-report retention | 90 days |
| Command/heartbeat cadence | Five minutes or long polling |
| Agent payload security | Tenant-scoped credentials over outbound TLS |

Expected workload under these assumptions:

- 900,000 reports per month.
- Approximately 90 GB of new report payload per month.
- Approximately 270 GB retained at a 90-day window, before backups and indexes.
- Approximately 259 million five-minute heartbeat/command checks per month.

The present 15-second polling pattern would generate approximately 2,000 polls
per second at 30,000 endpoints. It must not be retained for enterprise scale.

## Recommended GCP Architecture

```text
Agents and edge sensors
        |
HTTPS Load Balancer and Cloud Armor
        |
Cloud Run ingestion API
        |
Pub/Sub topics
        |
Cloud Run workers
   |        |        |
Cloud SQL   GCS      Memorystore Redis
Postgres    Reports  Rate limits, cache, device presence
        |
Cloud Run dashboard and reporting API
```

### Core Services

- Cloud Run: stateless agent-ingest, dashboard, command, scheduler, and worker
  services. Separate interactive APIs from background processing.
- Cloud SQL for PostgreSQL, high availability: tenant, device, policy, command,
  report-summary, and finding metadata. Use tenant IDs and database-enforced
  authorization controls.
- Cloud Storage: raw reports, PDF/CSV exports, evidence packages, and lifecycle
  retention. Keep large artifacts out of PostgreSQL.
- Pub/Sub: durable report, command, alert, retry, and scheduled-work queues.
- Memorystore for Redis Standard Tier: distributed rate limits, short-lived
  device presence, command availability, and dashboard caching.
- Global HTTPS Load Balancer plus Cloud Armor: TLS termination, WAF, rate
  limits, health checks, and public endpoint protection.
- Cloud KMS and Secret Manager: per-service secrets, encryption keys, rotation,
  and least-privilege service accounts.
- Cloud Logging and Monitoring: metrics, SLOs, traceability, audit events, and
  actionable alerting. Successful heartbeats and raw reports must be excluded
  or sampled to control logging cost.

## Required Product Changes

1. Replace SQLite with PostgreSQL and a tenant-aware data model.
2. Send raw reports to object storage and retain only searchable summaries and
   findings in PostgreSQL.
3. Replace frequent polling with long polling, managed delivery, or a durable
   pull command queue.
4. Acknowledge reports quickly after authentication, validation, and durable
   enqueueing; process reports asynchronously.
5. Use durable queues for alerts, SIEM forwarding, scan commands, retries, and
   scheduled work.
6. Add idempotency keys, device/report sequence numbers, backpressure, and
   bounded local agent spooling.
7. Generate fleet reports and evidence exports asynchronously, with a job ID
   and a signed Cloud Storage download link.
8. Add per-device credential issuance, revocation, rotation, and audit trails.
9. Add load, resilience, tenant-isolation, backup/restore, and disaster-recovery
   test suites before making a 30,000-endpoint capacity claim.

## Monthly Cost Estimate

| Service | Planning configuration | Monthly estimate |
| --- | --- | ---: |
| Cloud Run | Ingestion API, dashboard, workers, scheduler | $250 to $800 |
| Cloud SQL PostgreSQL HA | 8 to 16 vCPU, 32 to 64 GB RAM, backups, 500 GB to 1 TB storage | $1,200 to $3,000 |
| Cloud Storage | Raw reports, exports, lifecycle-managed retention | $25 to $150 |
| Pub/Sub | Report, command, alert, and retry topics | $50 to $250 |
| Memorystore Redis HA | 5 to 10 GiB Standard Tier | $200 to $500 |
| Global HTTPS Load Balancer | Public API and dashboard entry point | $25 to $150 |
| Cloud Armor Standard | WAF, rate limiting, and request protection | $50 to $300 |
| Cloud KMS and Secret Manager | Key and secret management | $25 to $100 |
| Cloud Logging and Monitoring | Metrics, alerts, audit, and controlled logs | $300 to $1,500 |
| VPC, Cloud NAT, private connectivity | Private service access and worker egress | $100 to $400 |
| Artifact Registry and Cloud Build | Images and CI/CD | $25 to $150 |
| Backup and disaster recovery | Database backup and cross-region artifact replication | $150 to $800 |
| Total: lean regional production | Controlled workload and retention | $2,500 to $4,000 |
| Total: enterprise HA production | Recommended 30,000-endpoint target | $4,000 to $7,500 |
| Total: regulated or multi-region DR | Higher availability and residency needs | $7,500 to $15,000+ |

The primary cost drivers are Cloud SQL HA, logging volume, agent command
delivery, retained artifact volume, and internet egress for reports and
updates. These are estimates that must be refined using real p50/p95 report
sizes, reporting cadence, dashboard usage, and retention requirements.

## Public Price Reference Points

- Cloud Run request-based CPU in us-central1: $0.000024 per vCPU-second.
- Pub/Sub standard throughput: $40 per TiB after the free tier.
- Cloud Storage Standard in us-central1: approximately $0.02 per GiB-month.
- Cloud Armor Standard global requests: $0.75 per million requests, plus
  policy/rule charges.
- Memorystore Redis Standard Tier is billed by provisioned GiB-hour.

GCP pricing changes over time. Final commercial pricing must use the Google
Cloud Pricing Calculator with actual measured traffic and storage data.

## Cost Controls

- Use five-minute heartbeats, long polling, or queue delivery; do not use
  15-second state-writing polls at enterprise scale.
- Exclude successful heartbeats and raw report bodies from Cloud Logging.
- Use Cloud Storage lifecycle rules and artifact retention tiers.
- Store report summaries and latest device state in PostgreSQL; avoid
  whole-fleet JSON deserialization for dashboard pages.
- Generate exports asynchronously and use signed object-storage downloads.
- Set report-size limits, per-tenant quotas, request limits, and budget alerts.
- Purchase committed-use discounts only after six to twelve months of stable
  measured capacity.

## Rollout Plan

### Phase 1: Pilot Stabilization

- Enforce HTTPS and Cloud Armor.
- Remove public deployment tooling and Docker socket exposure.
- Add backups, health checks, metrics, structured logs, and budget alerts.
- Limit large fleet exports and set a documented pilot endpoint cap.

### Phase 2: Scale Foundation

- Deploy PostgreSQL, Cloud Storage, Pub/Sub, and Redis.
- Implement asynchronous ingestion and command delivery.
- Move agents to durable report spooling and lower-frequency presence updates.

### Phase 3: Enterprise Production

- Deploy stateless services on Cloud Run behind the global load balancer.
- Add tenant quotas, per-device identities, reporting jobs, and SLOs.
- Execute staged load tests at 1,000, 5,000, 15,000, and 30,000 endpoints.

### Phase 4: Regulated And Multi-Region

- Add cross-region object replication, tested restore procedures, and formal DR.
- Evaluate multi-region database strategy, residency controls, and contractual
  SLA/SLO requirements.

## Decision

Do not position the current single-VM deployment as 30,000-endpoint capable.
Position it as an internal/pilot platform. Authorize the managed GCP redesign
before committing to a 30,000-endpoint enterprise deployment or pricing tier.

## Customer-Facing 12-Device Demo Network

### Purpose

Create a separate GCP project and VPC that presents Arckon as a professional,
customer-ready platform. The environment should demonstrate endpoint inventory,
AI tool detection, self-hosted AI discovery, DNS telemetry, policy findings,
fleet remediation, and executive reporting without using production customer
data.

### Recommended Network Layout

| Segment | Contents | Purpose |
| --- | --- | --- |
| Management | Arckon command center, DNS collector, monitoring | Restricted management and telemetry path |
| Users | Linux and Windows endpoint personas | Simulated employee and developer devices |
| AI Services | Ollama, LocalAI, Jupyter, demo APIs | Self-hosted AI discovery and posture scenarios |

Use a separate `arckon-demo` GCP project, a dedicated VPC, Cloud DNS, HTTPS,

### Twelve Demo Personas

| Persona | Count | Demonstrated scenario |
| --- | ---: | --- |
| Linux employee/developer endpoints | 5 | Agents, code tools, policy/config findings |
| Windows endpoints | 2 | Cross-platform inventory and endpoint visibility |
| AI development hosts | 2 | Claude Code, Cursor, Copilot, and agent instructions |
| Self-hosted AI service hosts | 2 | Ollama, LocalAI, Jupyter, or OpenAI-compatible APIs |
| DNS/edge sensor | 1 | AI-domain telemetry and device/IP correlation |

Use real GCE VMs for the command center, DNS collector, AI service hosts, and
several endpoint personas. Docker can provide the remaining Linux personas
when full operating-system realism is not needed.

### Monthly Demo Cost

| Component | Monthly estimate |
| --- | ---: |
| Arckon command-center VM | $50 to $85 |
| Seven to nine small Linux endpoint VMs | $80 to $160 |
| Two Windows endpoint VMs, including licenses | $90 to $180 |
| One to two AI service VMs | $80 to $160 |
| DNS collector/resolver VM | $15 to $35 |
| Cloud NAT and private egress | $35 to $75 |
| HTTPS load balancer, static IP, and Cloud DNS | $25 to $60 |
| Logging, storage, backups, and monitoring | $20 to $75 |
| Optional Cloud Armor | $20 to $80 |
| Recommended customer-facing demo total | $350 to $650 |

### Cost Levels

| Option | Monthly estimate | Best use |
| --- | ---: | --- |
| Lean internal lab | $150 to $250 | Docker-heavy internal demonstrations |
| Recommended sales demo | $350 to $650 | Segmented VPC, 12 personas, AI services, and DNS telemetry |
| Enterprise showcase | $650 to $1,200 | Additional monitoring, WAF, resilience, and richer scenarios |

### Demo Cost Controls

- Shut down nonessential endpoint VMs outside demonstrations.
- Keep only the command center, DNS collector, and one AI service host always on.
- Use IAP instead of public SSH.
- Use CPU-based small models; do not use GPUs for the core demonstration.
- Exclude routine agent heartbeat noise from Cloud Logging.
- Keep raw demo artifacts in lifecycle-managed Cloud Storage.

### Demo Decision

Approve the recommended sales demo at $350 to $650 per month. It is the right
balance of customer credibility, technical realism, and operating cost while
