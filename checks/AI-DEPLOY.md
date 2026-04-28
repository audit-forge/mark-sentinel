# AI-DEPLOY — Deployment Security Checks

**Category:** Deployment Security
**Check IDs:** AI-DEPLOY-001 through AI-DEPLOY-006
**Count:** 6 checks

Framework references: OWASP LLM07, LLM08 | NIST AI RMF GOVERN 1.1, MANAGE 2.2 | FedRAMP AC-3, SC-8

---

## AI-DEPLOY-001: API Keys Not Exposed

**Severity:** CRITICAL
**Check type:** Static config + environment scan

### Description
Verifies that API keys and secrets used to authenticate with AI providers are not exposed in environment variables accessible to untrusted processes, hardcoded in source code, committed to version control, or written to application logs.

Exposed API keys are the single most common AI security failure in practice. An attacker who obtains your OpenAI, Anthropic, or other AI provider key can run up massive bills, exfiltrate your conversation history, and access any fine-tuned models you've built.

### SMB Explanation
Your AI needs a password (called an API key) to connect to services like ChatGPT. If that password is written down in the wrong place — like inside your website's code or in a file anyone can read — someone could steal it and use your account to do things without your permission, costing you money and exposing your customers' conversations.

### PASS Criteria
- API keys loaded exclusively from a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) or a protected `.env` file not committed to version control
- No API key patterns detected in source files, config files, or log output
- `.gitignore` includes `.env` and credential files
- Keys are not passed as command-line arguments (visible in process lists)

### FAIL Criteria
- API key found in source code (hardcoded string)
- API key found in a committed `.env` or config file in version control history
- API key found in application log output
- API key found in a Dockerfile ENV instruction
- API key found in Kubernetes manifest (not a Secret object)
- API key passed as a CLI argument visible in `ps aux`

### Remediation
1. Immediately rotate any exposed key at the provider dashboard
2. Move all keys to environment variables loaded from a protected `.env` file (not committed) or a secrets manager
3. Add `.env`, `*.env`, `config/secrets.*` to `.gitignore`
4. Run `git log --all -S "sk-" -- .` to check if keys are in git history; if found, use `git-filter-repo` to purge them
5. Configure log scrubbing to redact patterns matching API key formats
6. For production: use a secrets manager and inject keys at runtime, never at build time

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM07 — System Prompt Leakage (credential context), LLM08 — Vector and Embedding Weaknesses |
| NIST AI RMF | GOVERN 1.1 — Policies and accountability; MANAGE 2.2 — Risk treatment |
| FedRAMP / NIST 800-53 | IA-5 — Authenticator Management; SC-28 — Protection of Information at Rest |
| CMMC 2.0 | IA.L2-3.5.10 — Protect authenticators |

---

## AI-DEPLOY-002: No Hardcoded Credentials in Model Config

**Severity:** HIGH
**Check type:** Static config scan

### Description
Checks model configuration files, inference server configs, and deployment manifests for hardcoded credentials beyond API keys — including database passwords, internal service tokens, basic auth credentials, and bearer tokens used by the AI service.

This differs from AI-DEPLOY-001 in scope: -001 focuses on AI provider API keys; -002 covers all other credentials that an AI service deployment might contain, including credentials it uses to connect to databases, vector stores, and internal APIs.

### SMB Explanation
Your AI tool probably connects to other systems — maybe your customer database, your booking system, or a search index. Each of those connections needs a password too. If those passwords are typed directly into your AI's configuration files, they're just as exposed as the main API key.

### PASS Criteria
- No credential patterns (passwords, tokens, connection strings with passwords) found in model config files, docker-compose files, or k8s manifests
- Connection strings use environment variable references (`${DB_PASSWORD}`, `$(DB_PASSWORD)`)
- Kubernetes Secrets used for sensitive values (not ConfigMaps)
- Service account tokens rotated and scoped to minimum required permissions

### FAIL Criteria
- Password found in `database_url` or connection string in config file
- Bearer token hardcoded in model server configuration
- Basic auth credentials in a docker-compose `environment:` block
- Kubernetes ConfigMap containing a password

### Remediation
1. Audit all config files for credential patterns: `grep -rn "password\|token\|secret\|bearer\|auth" ./config/`
2. Replace hardcoded values with environment variable references
3. For Kubernetes: migrate ConfigMap secrets to Kubernetes Secret objects; consider External Secrets Operator
4. Rotate all credentials found during audit

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM07 — System Prompt Leakage |
| NIST AI RMF | MANAGE 2.2 — Risk treatment practices |
| FedRAMP / NIST 800-53 | IA-5 — Authenticator Management; CM-6 — Configuration Settings |
| CMMC 2.0 | IA.L2-3.5.10 — Protect authenticators |

---

## AI-DEPLOY-003: Logging Enabled and Retained

**Severity:** HIGH
**Check type:** Config + runtime probe

### Description
Verifies that the AI deployment has structured logging enabled, that logs capture sufficient context to reconstruct what happened (who asked what, what the model returned, what tools were called), and that logs are retained for a sufficient period to support incident response and compliance audits.

Without logging, you cannot detect misuse, cannot investigate incidents, and cannot produce compliance evidence. This check is foundational for everything else — an AI system with no logs is essentially unmonitorable.

### SMB Explanation
If something goes wrong with your AI — a customer complains it said something inappropriate, or you suspect someone is trying to abuse it — you need a record of what happened. Logging is that record. Without it, you're flying blind and can't prove what your AI did or didn't do.

### PASS Criteria
- Logging framework configured and actively writing logs
- Each log entry includes: timestamp, session/request ID, input summary or hash, output summary or hash, model used, latency
- Logs retained for minimum 30 days (90 days for regulated environments)
- Log storage is write-protected (logs cannot be modified or deleted by the application)
- Logs accessible for review without requiring production access

### FAIL Criteria
- No logging configured
- Logging configured but disabled in current environment
- Log retention less than 7 days
- Logs contain full raw user input/output but no anonymization — creates separate privacy risk
- No mechanism to search or review logs

### Remediation
1. Enable structured logging at the AI gateway or application layer
2. At minimum, log: timestamp, user/session identifier (hashed), request ID, model used, latency, error codes
3. Do NOT log raw PII-containing inputs by default — log a hash or truncated summary
4. Configure log rotation with minimum 90-day retention for regulated use; 30 days minimum for SMB
5. Route logs to a write-protected sink (CloudWatch, Splunk, ELK, even a protected log file)
6. Test log completeness: send a known test query and verify it appears in logs within 60 seconds

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM10 — Unbounded Consumption (detection requires logs) |
| OWASP Agentic Top 10 | OAGNT-09 — Insufficient Audit and Observability |
| NIST AI RMF | MEASURE 2.5 — AI risk monitoring; MANAGE 4.1 — Incident response |
| FedRAMP / NIST 800-53 | AU-2 — Audit Events; AU-9 — Protection of Audit Information; AU-11 — Audit Record Retention |
| CMMC 2.0 | AU.L2-3.3.1 — Create system audit logs |

---

## AI-DEPLOY-004: Access Controls on AI Endpoint

**Severity:** CRITICAL
**Check type:** Network + config probe

### Description
Verifies that the AI inference endpoint is not publicly accessible without authentication. This includes checking whether the API requires a valid token or key, whether there is network-level access control (firewall rules, VPC/private network), and whether the endpoint is not accidentally exposed to the public internet.

An unprotected AI endpoint is immediately exploitable: attackers can enumerate it, use it for free at your expense, feed it malicious inputs, and extract information from your system prompts or fine-tuned model knowledge.

### SMB Explanation
Your AI is like a smart employee who follows instructions. If anyone in the world can walk up and give it instructions — not just your customers and staff — you have a serious problem. This check makes sure your AI only listens to people you've authorized.

### PASS Criteria
- AI endpoint requires authentication on every request (API key, JWT, OAuth token)
- Unauthenticated requests return 401/403, not model output
- For internal-only deployments: endpoint not reachable from outside the private network
- For public-facing deployments: authentication is enforced at the gateway layer, not just at the app layer
- Admin/management endpoints are on a separate, more restricted path

### FAIL Criteria
- AI endpoint returns model output without any authentication header
- Authentication bypass possible via path traversal or method override
- AI endpoint reachable from public internet without auth (even if "not documented")
- Internal endpoint accessible from any network segment without restriction

### Remediation
1. Add authentication middleware to all AI endpoint routes — no exceptions for "internal" routes
2. Test: `curl -X POST https://your-ai-endpoint/v1/chat/completions -d '{"model":"...","messages":[{"role":"user","content":"test"}]}'` — should return 401
3. Audit network rules: confirm the endpoint is not reachable without credentials from outside your expected network
4. If using a cloud provider, check security groups / firewall rules — "0.0.0.0/0" on AI ports is a fail
5. Implement API gateway with auth enforcement before traffic reaches the AI service

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM07 — System Prompt Leakage; LLM08 — Vector and Embedding Weaknesses |
| NIST AI RMF | GOVERN 1.1 — Organizational AI policies; MANAGE 2.2 — Risk treatment |
| FedRAMP / NIST 800-53 | AC-3 — Access Enforcement; AC-17 — Remote Access; SC-7 — Boundary Protection |
| CMMC 2.0 | AC.L1-3.1.1 — Limit system access; AC.L2-3.1.3 — Control information flow |

---

## AI-DEPLOY-005: TLS/HTTPS Enforced on All AI Connections

**Severity:** HIGH
**Check type:** Network probe + config scan

### Description
Verifies that all connections to and from the AI service use TLS 1.2 or higher, that plain HTTP is rejected or redirected, that certificates are valid and not self-signed in production, and that connections between internal components (AI gateway → model server, AI service → database) also use TLS.

AI traffic is particularly sensitive: it carries user queries, system prompts (which often contain business logic and secrets), model responses, and potentially PII. Unencrypted AI traffic is trivially interceptable on any shared network.

### SMB Explanation
Encryption (HTTPS) protects everything your customers type into your AI from being read by anyone who can see your network traffic — like someone on the same Wi-Fi, or a compromised router. This check makes sure your AI conversations are encrypted end-to-end.

### PASS Criteria
- AI endpoint accessible only via HTTPS (HTTP redirects to HTTPS or returns 301)
- TLS 1.2+ enforced; TLS 1.0 and 1.1 disabled
- Certificate is valid, not expired, issued by a trusted CA (not self-signed in production)
- Internal service-to-service connections also use TLS (vector store, database, model server)
- HSTS header present on public-facing endpoints

### FAIL Criteria
- AI endpoint accessible via plain HTTP without redirect
- TLS 1.0 or 1.1 accepted
- Self-signed certificate in production (or no certificate validation on the client side)
- Certificate expired
- Internal traffic between components is unencrypted

### Remediation
1. Obtain a valid certificate from a trusted CA (Let's Encrypt is free for most use cases)
2. Configure your web server or load balancer to reject HTTP connections or redirect to HTTPS
3. Set minimum TLS version to 1.2 in server config
4. Enable HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains`
5. For internal services: use mTLS or at minimum TLS with trusted internal CA
6. Test: `curl http://your-ai-endpoint` — should get 301/302, not model output

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM08 — Vector and Embedding Weaknesses (data in transit) |
| NIST AI RMF | MANAGE 2.2 — Risk treatment |
| FedRAMP / NIST 800-53 | SC-8 — Transmission Confidentiality and Integrity; SC-28 — Protection of Information at Rest |
| CMMC 2.0 | SC.L2-3.13.8 — Implement cryptographic mechanisms |

---

## AI-DEPLOY-006: Rate Limiting Configured to Prevent Abuse

**Severity:** MEDIUM
**Check type:** Runtime probe + config scan

### Description
Verifies that the AI deployment has rate limiting configured to prevent a single user, session, or IP address from consuming excessive resources. This protects against: accidental runaway loops in agentic workflows, deliberate abuse by malicious users, API cost exhaustion attacks, and degraded service for legitimate users.

Rate limiting is the primary defense against LLM10 (Unbounded Consumption) from OWASP's LLM Top 10. Without it, a single attacker or misconfigured agent can exhaust your entire monthly API budget in minutes.

### SMB Explanation
Without limits, a single person (or an automated script) could use your AI thousands of times in a few minutes, running up a huge bill and slowing it down or crashing it for everyone else. Rate limiting is like a bouncer that lets normal usage through but stops abuse.

### PASS Criteria
- Per-user or per-session request rate limit configured (e.g., 100 requests/minute)
- Per-user or per-session token limit configured (e.g., 100,000 tokens/day)
- Global rate limit configured to cap total API spend per period
- Rate limit exceeded returns 429 with Retry-After header (not 500)
- Agentic workflows have per-run token budget enforced at the orchestration layer

### FAIL Criteria
- No rate limiting configured at any layer
- Rate limits exist but are set so high they provide no practical protection
- Rate limits only on HTTP layer, not on token consumption
- Agentic workflows have no maximum iteration or token cap

### Remediation
1. Add rate limiting at the API gateway layer (nginx: `limit_req_zone`, AWS API Gateway throttling, Cloudflare rate limiting)
2. Set per-IP and per-user limits appropriate to your use case (start conservative, relax based on usage data)
3. Configure global spend limits directly in your AI provider dashboard (OpenAI, Anthropic all support monthly hard limits)
4. For agentic workflows: add explicit `max_iterations` and `max_tokens` parameters to every agent run
5. Monitor and alert on rate limit hit rate — frequent hits indicate either legitimate heavy usage or an attack

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM10 — Unbounded Consumption |
| NIST AI RMF | MANAGE 2.2 — Risk treatment; MEASURE 2.7 — AI performance monitoring |
| FedRAMP / NIST 800-53 | SC-5 — Denial-of-Service Protection; AU-2 — Audit Events |
| CMMC 2.0 | SC.L1-3.13.1 — Monitor communications |
