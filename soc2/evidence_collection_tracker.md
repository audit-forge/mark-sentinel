# SOC 2 Evidence Collection Tracker

## Purpose
This checklist defines what evidence must be collected during the SOC 2
observation period, where it is stored, and who is responsible for
collecting it. This ensures nothing is missed when the auditor requests
evidence.

## Observation Period
- Start Date: TBD (after policy approval)
- End Date: Start + 3-6 months
- Auditor Engagement: After observation period ends

## Evidence Checklist

### CC1 — Control Environment
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Signed policy acknowledgments | Google Docs | Screenshot/pDF of signed policies | One-time at start | Pending |
| Org chart / roles documentation | Internal | Document in this folder | One-time | Pending |

### CC2 — Communication and Information
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Policy distribution evidence | Email / Google Docs | Screenshot of sharing settings | One-time | Pending |
| Customer communication records | Email / dashboard | Email logs, dashboard banners | Ongoing | Active |

### CC3 — Risk Assessment
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Risk assessment documentation | This folder | Annual risk assessment document | Annual | Pending |
| Vendor risk reviews | vendor_inventory.md | Quarterly review sign-off | Quarterly | Active |

### CC5 — Control Activities
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Arckon security check results | Arckon dashboard | Export findings report | Monthly | Active |
| Endpoint AI inventory | Arckon dashboard | Export inventory CSV | Monthly | Active |

### CC6 — Logical and Physical Access
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Access review documentation | access_review_*.md | Quarterly review in this folder | Quarterly | Active (Q4 2026 done) |
| MFA enforcement evidence | Google Workspace admin | Screenshot of MFA settings | One-time + on change | Verified 2026-11-19 |
| GCP IAM policy export | gcloud CLI | `gcloud projects get-iam-policy` output | Quarterly | First export done |
| GitHub collaborator list | GitHub API | `gh api repos/.../collaborators` | Quarterly | First export done |
| Branch protection evidence | GitHub API | `gh api repos/.../branches/main/protection` | Quarterly | Active |
| Firewall rules export | gcloud CLI | `gcloud compute firewall-rules list` | Quarterly | First export done |

### CC7 — System Operations
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Backup restore test | backup_restore_test.md | Run test, document results | Quarterly | Active (Q4 2026 done) |
| Vulnerability scan results | CI logs, pentest report | Export CI logs, retain pentest report | Quarterly + CI | Active |
| Security event alerts | Arckon alerts | Export alert log | Monthly | Active |
| Incident response documentation | This folder | Document any incidents | As they occur | No incidents to date |
| System uptime / availability | GCP monitoring | GCP console screenshots | Monthly | Pending |

### CC8 — Change Management
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| PR review evidence | GitHub | PR history export | Monthly | Active |
| Deployment approval evidence | GitHub Actions | Workflow run logs | Per deployment | Active |
| Signed release manifests | GCS / GitHub | Manifest.json + .sig files | Per release | Active |

### CC9 — Risk Mitigation
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Vendor inventory | vendor_inventory.md | Quarterly review | Quarterly | Active |
| Vendor compliance certifications | Vendor websites | Screenshot/PDF of certifications | Annual | First review done |

### A1 — Availability
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Uptime monitoring | Cloudflare / GCP | Status dashboard screenshots | Monthly | Pending |
| DR plan test | BC/DR Plan document | Tabletop exercise documentation | Annual | Pending |

### C1 — Confidentiality
| Evidence | Source | Collection Method | Frequency | Status |
|---|---|---|---|---|
| Encryption configuration | Cloudflare / GCP | TLS settings screenshot, encryption settings | One-time + on change | Verified 2026-11-19 |
| Data classification | Data Classification Policy | Policy document | One-time | Pending approval |
| Tenant isolation evidence | Architecture docs | nginx config, Docker isolation documentation | One-time | Active |

## Evidence Storage
All evidence is stored in:
- This repository (`soc2/` folder) — for markdown documentation
- Google Drive (shared folder) — for screenshots, PDFs, exported reports
- GitHub Actions logs — for CI/CD evidence (retained per GitHub's policy)
- GCP Cloud Audit Logs — for infrastructure access evidence (retained 400 days)

## Related Documents
- All policy documents (Google Docs)
- backup_restore_test.md
- access_review_q4_2026.md
- vulnerability_management_program.md
- vendor_inventory.md
- compliance_platform_comparison.md
