"""
AI-GOV checks — Governance & Compliance Posture
Checks: AI-GOV-001 through AI-GOV-005
All checks are evaluable in config mode via documentation audit.
"""
import re
from . import CheckResult, PASS, FAIL, WARN
from connectors.config_connector import ScanContext

CATEGORY = "AI-GOV"

_POLICY_CONTENT_RE = [
    re.compile(r'(?i)approved\s+(?:ai\s+)?(?:tools?|services?)'),
    re.compile(r'(?i)prohibited\s+(?:uses?|ai|data)'),
    re.compile(r'(?i)data\s+classification'),
    re.compile(r'(?i)responsible\s+(?:party|person|owner|ai)'),
    re.compile(r'(?i)ai\s+(?:usage|use)\s+(?:policy|guidelines?)'),
    re.compile(r'(?i)(?:last[_\s-]?updated|effective[_\s-]?date|version)\s*[:\-]'),
]

_RETENTION_CONTENT_RE = [
    re.compile(r'(?i)ai\s+(?:interaction|conversation|log)\s+(?:data|retention|history)'),
    re.compile(r'(?i)retention\s+(?:period|policy|schedule)'),
    re.compile(r'(?i)(?:deletion|erasure|purge)\s+(?:process|procedure|policy)'),
    re.compile(r'(?i)data\s+(?:lifecycle|expiry|expiration)'),
    re.compile(r'(?i)right\s+to\s+(?:erasure|deletion|be\s+forgotten)'),
    re.compile(r'(?i)\d+\s+days?\s+(?:retention|after|maximum)'),
]

_IR_CONTENT_RE = [
    re.compile(r'(?i)(?:ai\s+)?incident\s+(?:response|handling|classification)'),
    re.compile(r'(?i)(?:kill\s+switch|disable|shut\s+down)\s+(?:the\s+)?ai'),
    re.compile(r'(?i)(?:notification|escalation|reporting)\s+(?:requirements?|process|procedure)'),
    re.compile(r'(?i)containment\s+(?:steps?|procedure|process)'),
    re.compile(r'(?i)(?:security\s+)?contact[s:]'),
    re.compile(r'(?i)(?:vendor|provider)\s+(?:contact|escalation|support)'),
]

_OVERSIGHT_CONTENT_RE = [
    re.compile(r'(?i)human\s+(?:review|oversight|in\s+the\s+loop|approval)'),
    re.compile(r'(?i)high[_-]?stakes?\s+(?:decision|use\s+case)'),
    re.compile(r'(?i)(?:override|escalation)\s+(?:mechanism|process|procedure)'),
    re.compile(r'(?i)ai\s+(?:recommendation|decision)\s+(?:review|oversight)'),
    re.compile(r'(?i)(?:human|manual)\s+(?:verification|confirmation|approval)'),
]

_INVENTORY_CONTENT_RE = [
    re.compile(r'(?i)(?:model\s+)?(?:name|id|version)\s*[:\|]'),
    re.compile(r'(?i)provider\s*[:\|]'),
    re.compile(r'(?i)(?:ai\s+)?(?:system|service|tool)\s+(?:name|owner)\s*[:\|]'),
    re.compile(r'(?i)data\s+processed\s*[:\|]'),
    re.compile(r'(?i)(?:api\s+)?(?:endpoint|key[_-]?id)\s*[:\|]'),
    re.compile(r'(?i)last\s+(?:reviewed|updated|checked)\s*[:\|]'),
]

_STALE_POLICY_RE = re.compile(
    r'(?i)(?:last[_\s-]?updated|effective|date)\s*[:\-]?\s*(\d{4})'
)


def _doc_quality(content: str, patterns: list) -> int:
    """Return count of quality indicators matched in a document."""
    return sum(1 for r in patterns if r.search(content))


def _check_staleness(content: str) -> str | None:
    """Return a staleness warning string if the doc appears outdated, else None."""
    m = _STALE_POLICY_RE.search(content)
    if m:
        year = int(m.group(1))
        if year < 2023:
            return f"Document may be stale — last updated year appears to be {year}"
    return None


def check_gov_001(ctx: ScanContext) -> CheckResult:
    """AI-GOV-001: AI Usage Policy Documented"""
    if not ctx.policy_files:
        return CheckResult(
            check_id="AI-GOV-001",
            title="AI Usage Policy Documented",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "No AI usage policy found. Without a policy, there is no basis for enforcement, "
                "no guidance for employees, and no compliance evidence."
            ),
            evidence=[
                "No AI usage policy file found (looked for: ai_usage_policy.md, ai_policy.*, usage_policy.*)",
                "Policies should define: approved tools, prohibited uses, data classification, responsible party",
            ],
            remediation=(
                "1. Draft a minimal AI policy (even one page): approved tools, prohibited data types, responsible party.\n"
                "2. Have legal/compliance review for industry-specific requirements (HIPAA, PCI, GDPR).\n"
                "3. Communicate to all employees and collect acknowledgment.\n"
                "4. Publish in your internal wiki and set a 12-month review reminder.\n"
                "5. M.A.R.K. Sentinel provides a policy template in docs/SMB_GUIDE.md."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "PL-1", "NIST AI RMF": "GOVERN 1.1", "EU AI Act": "Article 9"},
        )

    ev = []
    warnings = []
    best_quality = 0
    for path in ctx.policy_files:
        content = ctx.files.get(path, '')
        quality = _doc_quality(content, _POLICY_CONTENT_RE)
        best_quality = max(best_quality, quality)
        ev.append(f"Policy found: {path} ({quality}/{len(_POLICY_CONTENT_RE)} quality indicators)")
        stale = _check_staleness(content)
        if stale:
            warnings.append(stale)

    if best_quality < 2:
        return CheckResult(
            check_id="AI-GOV-001",
            title="AI Usage Policy Documented",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details="AI policy file found but content appears incomplete. A useful policy should define approved tools, prohibited uses, and data classification.",
            evidence=ev + warnings,
            remediation=(
                "Expand the policy to include: approved AI tools list, prohibited data types (e.g., no PII in third-party AI), "
                "responsible party, and last-updated date."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "PL-1", "NIST AI RMF": "GOVERN 1.1"},
        )

    return CheckResult(
        check_id="AI-GOV-001",
        title="AI Usage Policy Documented",
        status=PASS,
        severity="HIGH",
        category=CATEGORY,
        details="AI usage policy found with meaningful content.",
        evidence=ev + warnings,
        frameworks={"OWASP LLM": "LLM10", "FedRAMP": "PL-1", "NIST AI RMF": "GOVERN 1.1"},
    )


def check_gov_002(ctx: ScanContext) -> CheckResult:
    """AI-GOV-002: Data Retention and Deletion Policy Covers AI Interactions"""
    if not ctx.retention_policy_files:
        return CheckResult(
            check_id="AI-GOV-002",
            title="Data Retention Policy Covers AI Interactions",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "No data retention policy covering AI interactions found. "
                "GDPR, HIPAA, and CCPA all require knowing where AI interaction data is stored and how long it is kept."
            ),
            evidence=[
                "No data retention policy found (looked for: data_retention.md, retention_policy.*, ai_retention.*)",
                "Policy should cover: AI logs, conversation history, embeddings, fine-tuning datasets",
            ],
            remediation=(
                "1. Audit where AI interaction data is stored: logs, vector store embeddings, provider-side storage.\n"
                "2. Add AI data categories to your retention policy with defined retention periods.\n"
                "3. Configure technical enforcement: log rotation, vector store TTLs.\n"
                "4. Check your AI provider's data retention settings — configure minimum retention.\n"
                "5. Document the deletion process for AI data in your data subject rights procedure."
            ),
            frameworks={"OWASP LLM": "LLM02", "FedRAMP": "SI-12, AU-11", "NIST AI RMF": "GOVERN 1.1", "GDPR": "Article 5(1)(e)"},
        )

    ev = []
    best_quality = 0
    for path in ctx.retention_policy_files:
        content = ctx.files.get(path, '')
        quality = _doc_quality(content, _RETENTION_CONTENT_RE)
        best_quality = max(best_quality, quality)
        ev.append(f"Retention policy found: {path} ({quality}/{len(_RETENTION_CONTENT_RE)} quality indicators)")

    if best_quality < 2:
        return CheckResult(
            check_id="AI-GOV-002",
            title="Data Retention Policy Covers AI Interactions",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details="Data retention policy found but does not appear to explicitly cover AI interaction data.",
            evidence=ev,
            remediation="Update the policy to explicitly include AI logs, conversation history, embeddings, and fine-tuning datasets.",
            frameworks={"OWASP LLM": "LLM02", "FedRAMP": "SI-12", "NIST AI RMF": "GOVERN 1.1"},
        )

    return CheckResult(
        check_id="AI-GOV-002",
        title="Data Retention Policy Covers AI Interactions",
        status=PASS,
        severity="HIGH",
        category=CATEGORY,
        details="Data retention policy found covering AI interaction data.",
        evidence=ev,
        frameworks={"OWASP LLM": "LLM02", "FedRAMP": "SI-12", "NIST AI RMF": "GOVERN 1.1"},
    )


def check_gov_003(ctx: ScanContext) -> CheckResult:
    """AI-GOV-003: AI Incident Response Plan Exists"""
    if not ctx.ir_plan_files:
        return CheckResult(
            check_id="AI-GOV-003",
            title="AI Incident Response Plan Exists",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "No AI incident response plan found. "
                "If your AI leaks data, gets injected, or misbehaves, you need a plan ready before that happens."
            ),
            evidence=[
                "No IR plan found (looked for: incident_response.md, ir_plan.*, ai_incident.*)",
                "An AI IR plan should cover: how to disable AI quickly, who to notify, how to preserve evidence",
            ],
            remediation=(
                "Answer these 5 questions in a document:\n"
                "1. What counts as an AI incident? (data leak, injection attack, model misbehavior)\n"
                "2. Who do I call first? (internal team + AI vendor security contact)\n"
                "3. How do I disable AI quickly? (document the kill switch)\n"
                "4. How do I preserve evidence? (export logs before clearing)\n"
                "5. Who needs to be notified? (legal, affected users, regulators if required)"
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "IR-1, IR-4", "NIST AI RMF": "MANAGE 4.1"},
        )

    ev = []
    best_quality = 0
    for path in ctx.ir_plan_files:
        content = ctx.files.get(path, '')
        quality = _doc_quality(content, _IR_CONTENT_RE)
        best_quality = max(best_quality, quality)
        ev.append(f"IR plan found: {path} ({quality}/{len(_IR_CONTENT_RE)} quality indicators)")

    if best_quality < 2:
        return CheckResult(
            check_id="AI-GOV-003",
            title="AI Incident Response Plan Exists",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details="IR plan found but lacks key AI-specific elements.",
            evidence=ev,
            remediation=(
                "Ensure your IR plan covers: AI-specific incident categories, how to quickly disable AI, "
                "vendor security contacts, and regulatory notification requirements."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "IR-1", "NIST AI RMF": "MANAGE 4.1"},
        )

    return CheckResult(
        check_id="AI-GOV-003",
        title="AI Incident Response Plan Exists",
        status=PASS,
        severity="HIGH",
        category=CATEGORY,
        details="AI incident response plan found with substantive content.",
        evidence=ev,
        frameworks={"OWASP LLM": "LLM10", "FedRAMP": "IR-1", "NIST AI RMF": "MANAGE 4.1"},
    )


def check_gov_004(ctx: ScanContext) -> CheckResult:
    """AI-GOV-004: Human Oversight Mechanisms in Place for High-Stakes Decisions"""
    all_text = '\n'.join(ctx.files.values())
    oversight_in_config = any(r.search(all_text) for r in _OVERSIGHT_CONTENT_RE)
    has_oversight_doc = bool(ctx.oversight_docs)

    ev = []
    if ctx.oversight_docs:
        for path in ctx.oversight_docs:
            content = ctx.files.get(path, '')
            quality = _doc_quality(content, _OVERSIGHT_CONTENT_RE)
            ev.append(f"Oversight documentation found: {path} ({quality} indicators)")

    # Check agent config for HITL settings
    agent_text = ctx.agent_config_raw
    has_hitl_config = bool(re.search(
        r'(?i)"(?:human[_-]?in[_-]?(?:the[_-]?)?loop|hitl|require[_-]?confirmation|human[_-]?review)"\s*:\s*true',
        agent_text,
    ))

    if has_hitl_config:
        ev.append("Human-in-the-loop configuration found in agent config")

    if not oversight_in_config and not has_oversight_doc and not has_hitl_config:
        return CheckResult(
            check_id="AI-GOV-004",
            title="Human Oversight Mechanisms in Place",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "No human oversight configuration or documentation found. "
                "This check requires process review — cannot fully verify via config scan. "
                "If your AI influences high-stakes decisions, human oversight mechanisms should be documented."
            ),
            evidence=[
                "No HITL configuration in agent config",
                "No oversight documentation found",
                "Note: This check requires manual process review to fully evaluate",
            ],
            remediation=(
                "1. Identify which AI use cases constitute high-stakes decisions (hiring, credit, medical, legal).\n"
                "2. For each high-stakes use case: define who reviews, what information they see, how they override.\n"
                "3. Document the oversight mechanism for auditors.\n"
                "4. Track AI-human divergence rate: how often do humans override the AI? A 0% rate suggests rubber-stamping."
            ),
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "PL-1", "NIST AI RMF": "GOVERN 6.1", "EU AI Act": "Article 14"},
        )

    if has_hitl_config and has_oversight_doc:
        return CheckResult(
            check_id="AI-GOV-004",
            title="Human Oversight Mechanisms in Place",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="Human-in-the-loop configuration and oversight documentation both found.",
            evidence=ev,
            frameworks={"OWASP LLM": "LLM06", "FedRAMP": "PL-1", "NIST AI RMF": "GOVERN 6.1"},
        )

    return CheckResult(
        check_id="AI-GOV-004",
        title="Human Oversight Mechanisms in Place",
        status=WARN,
        severity="HIGH",
        category=CATEGORY,
        details=(
            "Some oversight indicators found, but this check requires manual process review to fully evaluate. "
            "Configuration alone cannot confirm that oversight is meaningful and functional."
        ),
        evidence=ev + ["Manual process review required to verify override mechanisms are functional"],
        frameworks={"OWASP LLM": "LLM06", "FedRAMP": "PL-1", "NIST AI RMF": "GOVERN 6.1"},
    )


def check_gov_005(ctx: ScanContext) -> CheckResult:
    """AI-GOV-005: AI System Documented in Asset Inventory"""
    if not ctx.inventory_files:
        return CheckResult(
            check_id="AI-GOV-005",
            title="AI System Documented in Asset Inventory",
            status=FAIL,
            severity="MEDIUM",
            category=CATEGORY,
            details=(
                "No AI asset inventory found. "
                "An AI system not in inventory cannot be managed, monitored, updated, or secured."
            ),
            evidence=[
                "No inventory file found (looked for: ai_inventory.md, ai_asset_inventory.md, aibom.*)",
                "Inventory should include: system name, provider, model version, purpose, owner, data processed",
            ],
            remediation=(
                "1. Start with a simple spreadsheet or Markdown table: System, Provider, Model, Version, Owner, Data Processed.\n"
                "2. Include ALL AI: externally-hosted APIs, local models, and AI features in approved software (Copilot, Gemini).\n"
                "3. Build inventory maintenance into change management: no new AI deployment without an inventory entry.\n"
                "4. Review quarterly — remove decommissioned systems, add newly discovered shadow AI."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "CM-8", "NIST AI RMF": "GOVERN 2.2", "EU AI Act": "Article 60"},
        )

    ev = []
    best_quality = 0
    for path in ctx.inventory_files:
        content = ctx.files.get(path, '')
        quality = _doc_quality(content, _INVENTORY_CONTENT_RE)
        best_quality = max(best_quality, quality)
        ev.append(f"Inventory found: {path} ({quality}/{len(_INVENTORY_CONTENT_RE)} quality indicators)")

    if best_quality < 3:
        return CheckResult(
            check_id="AI-GOV-005",
            title="AI System Documented in Asset Inventory",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details="AI inventory file found but appears incomplete. A good inventory entry should have: name, provider, model version, owner, and data processed.",
            evidence=ev,
            remediation=(
                "Expand the inventory to include for each AI system:\n"
                "| System | Provider | Model ID/Version | Purpose | Owner | Data Processed | Added | Last Reviewed |"
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "CM-8", "NIST AI RMF": "GOVERN 2.2"},
        )

    return CheckResult(
        check_id="AI-GOV-005",
        title="AI System Documented in Asset Inventory",
        status=PASS,
        severity="MEDIUM",
        category=CATEGORY,
        details="AI asset inventory found with substantive content.",
        evidence=ev,
        frameworks={"OWASP LLM": "LLM10", "FedRAMP": "CM-8", "NIST AI RMF": "GOVERN 2.2"},
    )


def run_all(ctx: ScanContext) -> list:
    return [
        check_gov_001(ctx),
        check_gov_002(ctx),
        check_gov_003(ctx),
        check_gov_004(ctx),
        check_gov_005(ctx),
    ]
