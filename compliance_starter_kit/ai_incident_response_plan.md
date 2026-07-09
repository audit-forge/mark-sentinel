# AI Incident Response Plan

**Organisation:** [YOUR ORGANISATION]
**Version:** 1.0
**Effective date:** [EFFECTIVE DATE YYYY-MM-DD]
**Last updated:** [EFFECTIVE DATE YYYY-MM-DD]
**Responsible party:** [RESPONSIBLE PARTY NAME] ([responsible-party@example.com])

## 1. Purpose
This plan defines AI incident response and incident classification for M. F.
Dynamics AI systems, so that AI incidents are contained, escalated, and resolved.

## 2. Incident classification
AI incidents are classified as:
- **Critical** — data leakage, prompt-injection compromise, or unsafe autonomous action.
- **High** — repeated tool failures, runaway token spend, or model producing harmful output.
- **Low** — transient errors with no data or safety impact.

## 3. Kill switch (disable the AI)
Any AI system can be immediately disabled ("kill switch"):
- **HASH:** `launchctl bootout gui/501/com.keithferguson.hash` to shut down the agent,
  and stop Ollama to disable the model. This shuts down the AI within seconds.

## 4. Containment steps
1. Trigger the kill switch to shut down the affected AI system.
2. Preserve logs (`.activity.db`, `usage-tracker.json`) for investigation.
3. Rotate any credentials that may have been exposed.
4. Isolate the affected device from the network if data exfiltration is suspected.

## 5. Notification, escalation, and reporting requirements
- The responsible party is notified immediately for Critical/High incidents.
- Reportable incidents are documented with timeline, impact, and remediation.
- Regulatory reporting (e.g., EU AI Act serious-incident reporting) is assessed
  by the responsible party for any Critical incident.

## 6. Contacts
- **Security contact:** [RESPONSIBLE PARTY NAME] — [responsible-party@example.com]
- **Vendor / provider escalation:**
  - Anthropic (Claude API): support via console.anthropic.com
  - Ollama (local model): github.com/ollama/ollama issues

## 7. Review
Next scheduled review: [NEXT REVIEW DATE].
