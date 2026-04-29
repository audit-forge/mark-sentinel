# deploy-baseline fixture

Represents a realistic "out of the box" small business AI deployment.
Uses synthetic API keys — not real credentials.

## Expected results

| Check | Expected | Reason |
|---|---|---|
| AI-DEPLOY-001 | FAIL | API key in config.json (not in .env) |
| AI-DEPLOY-002 | PASS | No hardcoded DB credentials |
| AI-DEPLOY-003 | WARN | log_enabled=false, no log config |
| AI-DEPLOY-004 | FAIL | Port 8080 exposed with no auth |
| AI-DEPLOY-005 | WARN | No TLS configuration found |
| AI-DEPLOY-006 | FAIL | No rate limiting configured |
| AI-INP-005 | WARN | No max_tokens or input limit config |
| AI-SUPPLY-005 | FAIL | Uses gpt-4o (floating) and :latest tag |
