## AI-TOOL-001 : Gemini CLI — Credential Security

**Severity:** HIGH
**Category:** AI-TOOL
**Frameworks:** NIST AI RMF: GOVERN 1.7, OWASP LLM: LLM06

### Description
Detects the Gemini CLI tool and the google-generativeai Python package. These tools authenticate via credential files in ~/.gemini/ and do not open network ports, so they are invisible to port-based scanners. If credential files are world-readable, any user on the machine can exfiltrate the Google API key.

### SMB Explanation
Gemini CLI stores your Google AI key in a file. If that file has loose permissions, any other account on the computer can read it and use your key — potentially running up charges or accessing sensitive data.

### PASS Criteria
- Gemini CLI or google-generativeai package found
- Credential files in ~/.gemini/ are readable only by the owner (chmod 600)

### FAIL Criteria
- ~/.gemini/credentials.json or related files are world-readable (permissions include o+r)

### Remediation
chmod 600 ~/.gemini/credentials.json
chmod 700 ~/.gemini

---

## AI-TOOL-002 : Claude Code CLI — Credential Security

**Severity:** HIGH
**Category:** AI-TOOL
**Frameworks:** NIST AI RMF: GOVERN 1.7, OWASP LLM: LLM06

### Description
Detects the Claude Code CLI (installed via npm as @anthropic-ai/claude-code) and the anthropic Python package. Configuration and session data are stored in ~/.claude/. If these files are world-readable, Anthropic API keys and session tokens are exposed to other users on the system.

### SMB Explanation
Claude Code stores your Anthropic API key and session data locally. If the permissions on that folder are too open, other accounts on the machine can read your credentials.

### PASS Criteria
- Claude Code CLI or anthropic package found
- ~/.claude/ files are readable only by the owner

### FAIL Criteria
- Files under ~/.claude/ are world-readable

### Remediation
chmod -R 600 ~/.claude/*.json
chmod 700 ~/.claude

---

## AI-TOOL-003 : OpenAI CLI — Credential Security

**Severity:** HIGH
**Category:** AI-TOOL
**Frameworks:** NIST AI RMF: GOVERN 1.7, OWASP LLM: LLM06

### Description
Detects the OpenAI CLI tool and Python SDK. Credentials may be stored in ~/.openai/ or ~/.config/openai/. World-readable credential files expose the OPENAI_API_KEY to other system users.

### SMB Explanation
The OpenAI CLI saves your API key locally. Loose file permissions mean other accounts can read and use your key without your knowledge.

### PASS Criteria
- OpenAI CLI or openai package found
- Credential files are owner-readable only

### FAIL Criteria
- Credential files under ~/.openai/ or ~/.config/openai/ are world-readable

### Remediation
chmod 600 ~/.openai/*
chmod 700 ~/.openai

---

## AI-TOOL-004 : Aider — Hardcoded Key Detection

**Severity:** CRITICAL
**Category:** AI-TOOL
**Frameworks:** NIST AI RMF: GOVERN 1.7, OWASP LLM: LLM06, FedRAMP: IA-5

### Description
Detects the Aider AI coding assistant and scans its config files (.aider.conf.yml, .aider.model.settings.yml) for hardcoded API keys. Aider users sometimes paste API keys directly into config files, which can then be accidentally committed to version control.

### SMB Explanation
Aider is a terminal-based AI coding tool. Some users put their API keys directly in Aider's config files. If those config files end up in git, the keys become public. This check finds keys before that happens.

### PASS Criteria
- Aider installed, no API keys found in config files

### FAIL Criteria
- OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, or similar found as plaintext values in .aider.conf.yml or similar config files

### Remediation
Remove API keys from aider config files.
Set keys via environment variables instead:
  export OPENAI_API_KEY=sk-...
Add .aider.conf.yml to .gitignore to prevent accidental commits.

---

## AI-TOOL-005 : GitHub Copilot CLI — Credential Security

**Severity:** HIGH
**Category:** AI-TOOL
**Frameworks:** NIST AI RMF: GOVERN 1.7, OWASP LLM: LLM06

### Description
Detects the GitHub Copilot CLI extension (gh copilot) and its credential storage in ~/.config/github-copilot/. GitHub OAuth tokens stored there with loose permissions can be read by other users on the system.

### SMB Explanation
GitHub Copilot CLI stores your GitHub authentication token locally. If the token file is readable by other accounts, they can use it to access GitHub on your behalf.

### PASS Criteria
- Copilot CLI found, credential files are owner-readable only

### FAIL Criteria
- Files under ~/.config/github-copilot/ are world-readable

### Remediation
chmod -R 600 ~/.config/github-copilot/

---

## AI-TOOL-006 : Cursor IDE — Data Policy Review

**Severity:** LOW
**Category:** AI-TOOL
**Frameworks:** NIST AI RMF: GOVERN 2.2, OWASP LLM: LLM06

### Description
Detects the Cursor IDE. By default Cursor sends code context to AI providers including for model training. In regulated environments this may violate data handling requirements. Privacy Mode must be explicitly enabled to prevent code from leaving the machine for training purposes.

### SMB Explanation
Cursor is an AI-powered code editor. By default it sends your code to AI providers. If you work with sensitive or proprietary code, you need to turn on Privacy Mode to prevent your code from being used for AI training.

### PASS Criteria
- Cursor not installed

### FAIL Criteria
- N/A (always WARN when detected — requires manual policy review)

### Remediation
In Cursor: Settings → Privacy → enable Privacy Mode.
Review Settings → Models to confirm only approved AI providers are enabled.
Document the exception in your AI asset inventory if Cursor is approved for use.

---

## AI-TOOL-007 : AI API Keys in Shell Profile Files

**Severity:** CRITICAL
**Category:** AI-TOOL
**Frameworks:** NIST AI RMF: GOVERN 1.7, OWASP LLM: LLM06, FedRAMP: IA-5 SC-28, CMMC 2.0: IA.L2-3.5.10

### Description
Scans shell profile files (.bashrc, .zshrc, .profile, .bash_profile, .env, .envrc) and system environment files (/etc/environment, /etc/profile) for hardcoded AI API keys. Keys exported in profile files are visible to any process running as that user and may be logged in audit trails or accidentally shared.

### SMB Explanation
Many developers set their AI API keys in .bashrc or .zshrc for convenience. This means every terminal session, every script, and every background process on that account has access to the key — and if /etc/environment is used, every user on the machine does. This check finds keys stored this way.

### PASS Criteria
- No AI API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY, GEMINI_API_KEY, etc.) found in shell profile or system environment files

### FAIL Criteria
- One or more AI API keys found as exported values in .bashrc, .zshrc, .profile, /etc/environment, or similar files
- CRITICAL if found in system-wide files (/etc/); HIGH if in user profile files

### Remediation
Remove API keys from shell profile files.
Use a secrets manager:
  - macOS: Keychain (security add-generic-password)
  - Linux: pass, HashiCorp Vault, AWS Secrets Manager
  - CI/CD: inject via pipeline secrets store (GitHub Actions secrets, GitLab CI variables)
For local development, use a per-project .env file with .gitignore protection and load via direnv or dotenv.
