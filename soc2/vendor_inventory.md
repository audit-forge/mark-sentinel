# Vendor and Subprocessor Inventory

## Review Record

| Field | Value |
|---|---|
| Last Updated | 2026-11-19 |
| Reviewer | Keith Ferguson |
| Next Review Due | 2027-02-19 (quarterly) |

## Vendor Inventory

### Google Cloud Platform (GCP)
| Field | Value |
|---|---|
| Services Used | Compute Engine, Cloud Storage, IAM, IAP |
| Data Accessed | Customer telemetry, application code, backups, infrastructure metadata |
| Compliance | SOC 2 Type II, ISO 27001, FedRAMP High, HIPAA |
| DPA Status | Covered under Google Cloud Agreement |
| Risk Level | Low — major cloud provider with extensive certifications |
| Review Date | 2026-11-19 |
| Still Required | Yes — core infrastructure provider |

### Cloudflare
| Field | Value |
|---|---|
| Services Used | Tunnel, DNS, WAF, TLS termination, DDoS protection, caching |
| Data Accessed | HTTP headers, TLS metadata, IP addresses (not customer data contents) |
| Compliance | SOC 2 Type II, ISO 27001 |
| DPA Status | Covered under Cloudflare Privacy Policy and DPA |
| Risk Level | Low — major CDN/security provider |
| Review Date | 2026-11-19 |
| Still Required | Yes — network boundary protection |

### Google Workspace
| Field | Value |
|---|---|
| Services Used | Gmail, Docs, Sheets, Drive, Admin SDK (Reports API) |
| Data Accessed | Internal communications, policy documents, customer audit metadata |
| Compliance | SOC 2 Type II, ISO 27001 |
| DPA Status | Covered under Google Workspace Agreement |
| Risk Level | Low |
| Review Date | 2026-11-19 |
| Still Required | Yes — email, document collaboration, Drive audit forwarding |

### GitHub (Microsoft)
| Field | Value |
|---|---|
| Services Used | Source code hosting, CI/CD (GitHub Actions), issue tracking |
| Data Accessed | Source code, deployment workflows, release artifacts |
| Compliance | SOC 2 Type II, ISO 27001 |
| DPA Status | Covered under GitHub Terms of Service |
| Risk Level | Low — major development platform |
| Review Date | 2026-11-19 |
| Still Required | Yes — code hosting and CI/CD |

### Resend
| Field | Value |
|---|---|
| Services Used | Email delivery (transactional emails) |
| Data Accessed | Email addresses, email content for transactional emails |
| Compliance | SOC 2 Type II (verified via Resend security page) |
| DPA Status | Review required — confirm DPA is in place |
| Risk Level | Medium — smaller vendor, compliance posture verified but DPA status needs confirmation |
| Review Date | 2026-11-19 |
| Still Required | Yes — transactional email delivery |

## Action Items
1. Confirm DPA with Resend
2. Monitor for any new vendors added to the stack
3. Review vendor compliance certifications annually

## Vendor Assessment Criteria
New vendors must be assessed before engagement:
- [ ] Security posture reviewed (SOC 2, ISO 27001, or equivalent)
- [ ] Data access scope documented (what data the vendor can access)
- [ ] DPA executed (for vendors handling customer data)
- [ ] Risk level assigned (Low, Medium, High)
- [ ] CEO approval documented

## Vendor Termination Procedure
Upon vendor termination:
1. Revoke all access credentials and API keys
2. Retrieve or destroy vendor-held data
3. Document termination date and data disposition
4. Update this inventory
5. For critical vendors (GCP, Cloudflare): maintain a transition plan

## Related Documents
- Information Security Policy
- Data Classification and Retention Policy
