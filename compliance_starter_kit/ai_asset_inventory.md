# AI Asset Inventory

**Organisation:** [YOUR ORGANISATION]
**Version:** 1.0
**Last updated:** [EFFECTIVE DATE YYYY-MM-DD]
**Last reviewed:** [EFFECTIVE DATE YYYY-MM-DD]
**Responsible party:** [RESPONSIBLE PARTY NAME] ([responsible-party@example.com])

This inventory documents every AI system, service, and tool in use on [THIS DEVICE].

---

## AI System 1 — HASH (local agent)

- **AI system name:** HASH
- **System owner:** [RESPONSIBLE PARTY NAME]
- **Model name / id / version:** qwen3:30b-instruct (Ollama), escalation to claude-opus-4-8
- **Provider:** Ollama (local) / Anthropic (escalation)
- **Data processed:** Internal business data, code, email metadata; no client Restricted data sent to third parties
- **API endpoint:** http://127.0.0.1:11434 (local Ollama); api.anthropic.com (escalation)
- **API key id:** ANTHROPIC_API_KEY (stored in .env, not in source)
- **Last reviewed:** [EFFECTIVE DATE YYYY-MM-DD]

## AI System 2 — Anthropic Claude (escalation)

- **AI system name:** Claude (deep-escalation tier)
- **System owner:** [RESPONSIBLE PARTY NAME]
- **Model name / id / version:** claude-opus-4-8
- **Provider:** Anthropic
- **Data processed:** Task-specific prompts for escalated reasoning; budget-capped at $25/month
- **API endpoint:** https://api.anthropic.com
- **API key id:** ANTHROPIC_API_KEY
- **Last reviewed:** [EFFECTIVE DATE YYYY-MM-DD]

## AI System 3 — Arckon / RiskRaven Arckon

- **AI system name:** Arckon (RiskRaven Arckon)
- **System owner:** [RESPONSIBLE PARTY NAME]
- **Model name / id / version:** Sentinel scan engine (rule + AI checks)
- **Provider:** [YOUR ORGANISATION] (in-house)
- **Data processed:** AI deployment configuration and compliance evidence
- **API endpoint:** internal
- **Last reviewed:** [EFFECTIVE DATE YYYY-MM-DD]
