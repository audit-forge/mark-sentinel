# Quarterly Access Review — Q4 2026

## Review Record

| Field | Value |
|---|---|
| Review Date | 2026-11-19 |
| Reviewer | Keith Ferguson, CEO |
| Next Review Due | 2027-02-19 (quarterly) |

## GCP Access

### Human Users
| User | Role | Justification | Still Required? |
|---|---|---|---|
| keith@mfdynamics.ai | roles/owner | CEO, sole developer, infrastructure administrator | Yes |

### Service Accounts
| Service Account | Role(s) | Purpose | Still Required? |
|---|---|---|---|
| arckon-deploy@infra-analyzer-496922-p0.iam.gserviceaccount.com | arckonDeploy, compute.instanceGroupManagerServiceAgent, compute.osAdminLogin, iap.tunnelResourceAccessor, owner | CI/CD deployment automation | Yes |
| pharaoh-cli@infra-analyzer-496922-p0.iam.gserviceaccount.com | (no direct IAM bindings) | Pharaoh CLI automation | Review — verify if still used |
| pharaoh-cloud-scanner@infra-analyzer-496922-p0.iam.gserviceaccount.com | bigquery.metadataViewer, cloudasset.viewer, compute.viewer, iam.securityReviewer | Pharaoh cloud security scanning | Yes |
| pharaoh-scanner@infra-analyzer-496922-p0.iam.gserviceaccount.com | compute.instanceGroupManagerServiceAgent, iap.tunnelResourceAccessor | Pharaoh infrastructure scanning | Yes |
| arckon-drive-audit-forwarder@infra-analyzer-496922-p0.iam.gserviceaccount.com | (no direct IAM bindings) | Google Workspace Drive audit forwarder | Yes |
| 730280285522-compute@developer.gserviceaccount.com | compute.serviceAgent | Compute Engine default service account | Yes (GCP-managed) |

### GCP Firewall Rules
| Rule | Direction | Source | Ports | Assessment |
|---|---|---|---|---|
| allow-iap-ssh | Ingress | 35.235.240.0/20 (IAP only) | TCP 22 | Appropriate — IAP-scoped only |
| allow-iap-rdp | Ingress | 35.235.240.0/20 (IAP only) | TCP 3389 | Appropriate — IAP-scoped only |
| default-allow-icmp | Ingress | 0.0.0.0/0 | ICMP | Acceptable — standard GCP default |
| default-allow-internal | Ingress | 10.128.0.0/9 | All | Acceptable — internal network only |

**No public internet ingress rules exist. All access is IAP-scoped or internal only.**

## GitHub Access

| User | Role | Justification | Still Required? |
|---|---|---|---|
| keithferg2018 | Collaborator (admin) | CEO, sole developer | Yes |

### Branch Protection
- Main branch: protected
- Required status checks: lint, test
- Linear history: enforced
- Force pushes: blocked
- Deletions: blocked
- Admin enforcement: enabled
- Pull request required: yes (0 approving reviews for single-person team)

## Google Workspace Access

| User | Role | MFA Status | Still Required? |
|---|---|---|---|
| keith@mfdynamics.ai | Super Admin | 2-Step Verification On (since May 20, 2026) | Yes |

### Linked Apps Review
Total linked apps: 22. Key apps with potential data access:
- Google Cloud SDK — required for infrastructure management
- Google Cloud Shell — required for infrastructure management
- macOS — Google Drive sync (not currently installed on primary Mac)
- Slack — collaboration tool
- Read AI — meeting/calendar analysis (no Drive access)
- RavenOps — internal tool

**No unrecognized or suspicious linked apps identified.**

## MFA Verification
- GCP (via Google account): 2-Step Verification On
- GitHub: MFA enabled (verified via account settings)
- Google Workspace: 2-Step Verification On, Authenticator + Google prompt

## Review Conclusion
All access is appropriate and required. No unauthorized access identified.
Single-admin setup is documented and accepted for current team size.
Access will be reviewed again on 2027-02-19.

## Action Items
1. Verify whether pharaoh-cli service account is still actively used
2. Enable GCP scheduled disk snapshots for off-VM backup
3. Consider adding a second admin account when team grows beyond one person
