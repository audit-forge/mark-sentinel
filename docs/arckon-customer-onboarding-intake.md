# Arckon Customer Onboarding Intake

Thank you for choosing Arckon by RiskRaven. Complete this intake before the onboarding session so we can configure the right tenant, deployment method, baseline, integrations, and reporting scope. Do not include passwords, API keys, private keys, recovery codes, or full tokens in this document.

## 1. Primary Contacts

| Item | Response |
| --- | --- |
| Legal organization name | |
| Preferred organization name in Arckon | |
| Primary technical contact: name, title, email, phone | |
| Security/compliance contact | |
| Executive sponsor | |
| Billing contact | |
| Emergency or after-hours contact | |
| Time zone and normal maintenance window | |

## 2. Business And Compliance Context

| Item | Response |
| --- | --- |
| Industry and primary business services | |
| Countries/regions where systems or data are hosted | |
| Data classifications handled by AI-enabled systems | Public / Internal / Confidential / Regulated |
| Required frameworks or contractual obligations | ISO 42001 / NIST / FedRAMP / CMMC / HIPAA / PCI DSS / SOC 2 / GDPR / Other |
| Any prohibited AI providers, tools, or data types | |
| Current AI governance policy or owner | |
| Required reporting cadence and recipients | |

## 3. Environment Overview

| Item | Response |
| --- | --- |
| Approximate number of Windows endpoints | |
| Approximate number of macOS endpoints | |
| Approximate number of Linux endpoints | |
| Servers or virtual machines in scope | |
| Remote workforce or VPN requirements | |
| Cloud providers and accounts in scope | AWS / Azure / GCP / Other |
| Docker hosts or container platforms | |
| Kubernetes clusters, distributions, and namespaces in scope | |
| Development environments, CI/CD platforms, and source-control providers | |
| Existing EDR, vulnerability management, or SIEM tools | |

## 4. Endpoint Deployment And MDM

Select the management method for each operating system. Arckon does not require remote-control access to endpoints; it runs locally and reports results to the customer dashboard.

| Platform | Quantity | Management method | Administrator/owner | Notes |
| --- | --- | --- | --- | --- |
| Windows | | Intune / SCCM / RMM / GPO / manual / other | | |
| macOS | | Jamf Pro / Kandji / Mosyle / Intune / RMM / manual / other | | |
| Linux | | Ansible / RMM / package management / manual / other | | |

Provide the following deployment information where applicable:

- MDM/RMM product name, tenant/organization name, and technical owner.
- Preferred deployment mechanism: Intune Win32 app, Jamf package/script, RMM script, Ansible, or manual installation.
- Endpoint groups or smart groups that define the pilot and production rings.
- Whether users have local administrator rights, and any change-control requirements.
- Proxy, TLS inspection, firewall, VPN, or egress restrictions that agents must use.
- Allowed service account or deployment account process, if required. Share credentials only through the approved secret-management process, never in this intake.

## 5. Network And Connectivity

| Item | Response |
| --- | --- |
| Arckon dashboard hostname or approved public URL | |
| Is outbound HTTPS from managed endpoints allowed? | Yes / No / Proxy required |
| Proxy host, port, authentication method, and PAC-file requirements | |
| Firewall or egress allowlisting process | |
| Private networks/VPNs where agents will run | |
| Approved internal subnets for any future active discovery | |
| DNS, DHCP, NAC, or CMDB sources available for asset context | |
| Network change window and approval process | |

## 6. Identity And Access

| Item | Response |
| --- | --- |
| Identity provider | Microsoft Entra ID / Okta / Google Workspace / Other |
| MFA requirement for Arckon administrators | |
| Initial Arckon customer administrators | name, email, role |
| Client organizations or business units that need scoped access | |
| Required roles | MSP admin / customer admin / client viewer |
| Account provisioning and deprovisioning owner | |
| SSO requirement or roadmap | |

## 7. AI And Application Inventory

List known AI usage so discoveries can be validated and governed.

| System, tool, or provider | Business owner | Users/team | Data processed | Approved? | Notes |
| --- | --- | --- | --- | --- | --- |
| ChatGPT / OpenAI | | | | | |
| Claude / Anthropic | | | | | |
| Microsoft Copilot / GitHub Copilot | | | | | |
| Google Gemini / Vertex AI | | | | | |
| Local models: Ollama, LM Studio, vLLM, etc. | | | | | |
| AI agents, MCP servers, automation tools, or custom applications | | | | | |

Also identify:

- AI repositories, applications, model endpoints, and API gateways in scope.
- Package manifests or dependency sources used by AI projects: `requirements.txt`, `package-lock.json`, `poetry.lock`, `uv.lock`, container images, model registries, etc.
- Any AI vendor risk assessments, AI-BOM/SBOM records, model cards, or governance documentation already available.

## 8. Security Integrations And Alerts

| Integration | Needed? | Owner | Information needed during secure setup |
| --- | --- | --- | --- |
| Google Chat / Slack / Microsoft Teams alerts | | | Incoming webhook created by customer administrator |
| Email/SMTP alerts | | | SMTP host, port, sender, recipient group, approved authentication method |
| SIEM | Splunk / Sentinel / Elastic / QRadar / Other | | Destination URL, format, allowlisting, secure token handoff process |
| PSA/ticketing | ConnectWise / Autotask / HaloPSA / Jira / Other | | API owner, queue/board/project, priority mapping, secure credential process |
| Notion or documentation system | | | Integration owner and target workspace/database |

Do not paste webhook URLs, API tokens, SMTP passwords, or private keys into this intake. Provide them only through the agreed secure channel during configuration.

## 9. Scan Scope And Baseline

| Item | Response |
| --- | --- |
| Pilot devices and owners | |
| Production deployment rings and order | |
| Default baseline preference | Base Scan / OWASP Agentic / ISO 42001 / FedRAMP / CMMC / Healthcare / Financial / Professional Services / Other |
| Scan target exclusions or sensitive directories | |
| Docker hosts in scope | |
| Kubernetes cluster access approach | |
| Scan schedule, preferred stagger rate, and blackout windows | |
| Alert severity threshold and escalation recipients | |

## 10. Success Criteria And Approval

Confirm the outcomes required to complete onboarding:

- [ ] Customer tenant and named administrators are created.
- [ ] Pilot endpoints are enrolled and reporting.
- [ ] Default scan baseline is selected and documented.
- [ ] Known AI services are reviewed in AI Asset Inventory.
- [ ] Alerts and integrations are tested with a non-production test event.
- [ ] Reporting recipients and cadence are confirmed.
- [ ] Customer receives the Arckon Customer User Guide and escalation path.
- [ ] Production rollout approval is documented.

| Approval item | Name | Date | Notes |
| --- | --- | --- | --- |
| Technical readiness confirmed | | | |
| Security/compliance readiness confirmed | | | |
| Production rollout approved | | | |

## Secure Information Exchange

Use the customer-approved password manager, encrypted file exchange, or secure ticketing process for secrets. Never send secrets by email, chat, or this onboarding document.

Arckon implementation contact: ____________________

Customer technical owner: ____________________
