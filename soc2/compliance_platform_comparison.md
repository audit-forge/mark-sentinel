# Compliance Automation Platform Comparison

## Purpose
Compare the leading compliance automation platforms to determine which best
fits Arckon's needs for SOC 2 Type II preparation and ongoing compliance.

## Evaluation Criteria
- GCP integration (Arckon's primary infrastructure)
- Cloudflare integration
- GitHub integration
- Policy template coverage
- Auditor partnerships
- Pricing for small teams
- Ease of setup

## Platform Comparison

| Feature | Vanta | Drata | Secureframe |
|---|---|---|---|
| **GCP Integration** | Yes — reads IAM, firewall, compute configs | Yes — reads IAM, firewall, compute | Yes — reads IAM, firewall |
| **Cloudflare Integration** | Limited — DNS and some security settings | Limited | Limited |
| **GitHub Integration** | Yes — branch protection, PR reviews, commit signing | Yes — branch protection, access reviews | Yes — branch protection |
| **Google Workspace Integration** | Yes — MFA, access, linked apps | Yes — MFA, access | Yes — MFA, access |
| **SOC 2 Policy Templates** | Yes — comprehensive library | Yes — comprehensive library | Yes — comprehensive library |
| **Automated Evidence Collection** | Yes — continuous monitoring of connected systems | Yes — continuous monitoring | Yes — continuous monitoring |
| **Auditor Partnerships** | Yes — partnered with multiple CPA firms | Yes — partnered with multiple CPA firms | Yes — partnered with multiple CPA firms |
| **Pricing (startup/small team)** | ~$8K-$12K/year for SOC 2 | ~$8K-$15K/year for SOC 2 | ~$8K-$12K/year for SOC 2 |
| **Time to Readiness** | 4-8 weeks (with existing controls) | 4-8 weeks | 4-8 weeks |
| **Employee Onboarding** | Automated access reviews | Automated access reviews | Automated access reviews |
| **Trust Center** | Yes — public-facing trust portal | Yes — public-facing trust portal | Yes — public-facing trust portal |
| **API / Custom Integrations** | Limited API | Good API coverage | Limited API |

## Recommendation

For Arckon's current situation (single-person team, GCP + Cloudflare
infrastructure, all policies already drafted):

**Vanta** is the recommended choice because:
1. Strong GCP integration — can verify IAM, firewall, and compute configs automatically
2. Comprehensive SOC 2 policy templates (can import our existing policies)
3. Widely recognized by CPA firms — smoothest path to audit engagement
4. Public trust center — can share compliance status with prospects
5. Competitive pricing for small teams

**Drata** is a close second — similar features and pricing, with slightly
better API coverage if custom integrations are needed later.

**Secureframe** is also viable but has less mature GCP integration.

## Next Steps
1. Schedule demos with Vanta and Drata (both offer free consultations)
2. Confirm pricing for Arckon's team size
3. Verify GCP and Cloudflare integration depth in the demo
4. Select platform and begin onboarding
5. Import existing policy documents into the platform
6. Connect GCP, Cloudflare, GitHub, and Google Workspace accounts
7. Begin automated evidence collection (this starts the observation period)

## Note
A compliance automation platform does NOT replace a CPA auditor. It prepares
you for the audit and collects evidence continuously, but the actual SOC 2
report must be issued by a licensed CPA firm after formal fieldwork.
