"""
M.A.R.K. Sentinel — Plain English output formatter
Produces human-readable terminal output with SMB-friendly language option.
"""
from datetime import date
from checks import CheckResult, PASS, FAIL, WARN, SKIP

_STATUS_ICON = {PASS: "✅", FAIL: "🔴", WARN: "⚠️ ", SKIP: "⏭ "}
_STATUS_LABEL = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", SKIP: "SKIP"}

_LIVE_MODES = frozenset({'api', 'openai', 'local', 'anthropic', 'gemini', 'vertex', 'hash'})

_SKIP_DESCRIPTIONS = {
    "AI-INP-003": "Tests whether malicious instructions embedded in documents (PDFs, web pages) fetched by a RAG pipeline can hijack the model's behavior.",
    "AI-AGENT-001": "Verifies that tool/function access follows least privilege — the agent only has the permissions it needs, nothing more.",
    "AI-AGENT-002": "Checks whether the agent requires human confirmation before executing irreversible actions like deleting files or sending messages.",
    "AI-AGENT-003": "Tests whether injected content in the agent's memory or context can alter its behavior across sessions.",
    "AI-AGENT-004": "Verifies that inter-agent calls are authenticated — a compromised agent cannot impersonate a trusted one.",
    "AI-AGENT-005": "Confirms that every action taken by the agent is logged with enough detail to reconstruct what happened and why.",
    "AI-AGENT-006": "Tests whether the agent can be manipulated into sending data to external endpoints not on an approved allowlist.",
}

_SMB_DETAILS = {
    "AI-DEPLOY-001": "Your AI's password (API key) was found in the wrong place — in your code files instead of in a protected file.",
    "AI-DEPLOY-002": "Other passwords your AI uses (like database passwords) were found hardcoded in configuration files.",
    "AI-DEPLOY-003": "Your AI has no activity log. Without logs, you can't investigate problems or prove what happened.",
    "AI-DEPLOY-004": "Your AI endpoint may be accessible without a password. Anyone who can reach it can use it.",
    "AI-DEPLOY-005": "Your AI connections may not be encrypted. Conversations could be read by anyone on the network.",
    "AI-DEPLOY-006": "There's no limit on how many requests one person can make. This can lead to unexpected costs.",
    "AI-INP-001": "Live test required: Can a user trick your AI into ignoring its rules?",
    "AI-INP-002": "Live test required: Can a user hide instructions in a normal question to manipulate your AI?",
    "AI-INP-003": "Live test required: Can malicious instructions hidden in documents your AI reads affect its behavior?",
    "AI-INP-004": "Live test required: Can a user use role-play or creative framing to bypass your AI's safety rules?",
    "AI-INP-005": "No limit on how long messages users can send to your AI. Very long messages can cause problems.",
    "AI-OUT-001": "Live test required: Could someone extract private data your AI was trained on?",
    "AI-OUT-002": "Live test required: Could customer personal information appear in AI responses?",
    "AI-OUT-003": "Live test required: Could users find out exactly what instructions you've given your AI?",
    "AI-OUT-004": "Live test required: Does your AI properly refuse obviously harmful requests?",
    "AI-OUT-005": "AI-generated content may be used in ways that could be exploited (e.g., displayed as raw web content).",
    "AI-AGENT-001": "Your AI assistant has access to more tools than it needs to do its job.",
    "AI-AGENT-002": "Your AI can take irreversible actions (delete files, send emails) without asking a human first.",
    "AI-AGENT-003": "Live test required: Can someone corrupt your AI's memory to change its behavior?",
    "AI-AGENT-004": "Multiple AI assistants communicate without verifying they're talking to each other.",
    "AI-AGENT-005": "No record of what actions your AI assistant has taken.",
    "AI-AGENT-006": "Your AI can send data to any website it wants, not just approved ones.",
    "AI-SUPPLY-001": "No record of which AI model you're using, who made it, or what it was trained on.",
    "AI-SUPPLY-002": "If you downloaded an AI model, no one has checked whether it was tampered with.",
    "AI-SUPPLY-003": "The software libraries your AI uses are not pinned to specific versions — updates could introduce problems.",
    "AI-SUPPLY-004": "Cannot verify whether employees are using unauthorized AI tools with business data.",
    "AI-SUPPLY-005": "Your AI is set to use 'the latest version' — it could change behavior without warning.",
    "AI-GOV-001": "No written rules for how AI should be used in your business.",
    "AI-GOV-002": "No policy for how long to keep AI conversation records or when to delete them.",
    "AI-GOV-003": "No plan for what to do if something goes wrong with your AI.",
    "AI-GOV-004": "No documented process for humans to review AI decisions on important matters.",
    "AI-GOV-005": "No list of all the AI tools and models your business uses.",
}

_MODE_LABELS = {
    'config':    'Static config scan',
    'api':       'Live probes — OpenAI-compatible API',
    'openai':    'Live probes — OpenAI API',
    'local':     'Live probes — Local Ollama model',
    'anthropic': 'Live probes — Anthropic Claude API',
    'gemini':    'Live probes — Google Gemini API',
    'vertex':    'Live probes — Google Vertex AI',
    'hash':      'Live probes — Hash-AI gateway',
}


_FW_LABELS = {
    'fedramp': 'NIST 800-53 (FedRAMP Moderate)',
    'cmmc':    'CMMC Level 2',
}


def format_report(results: list, profile: dict, target: str, mode: str = 'config', model: str = '') -> str:
    is_smb = profile.get('smb_language', False) or profile.get('name', '').lower().startswith('smb')
    is_live = mode in _LIVE_MODES

    active  = [r for r in results if r.status != SKIP]
    skipped = [r for r in results if r.status == SKIP]

    fails  = [r for r in active if r.status == FAIL]
    warns  = [r for r in active if r.status == WARN]
    passes = [r for r in active if r.status == PASS]

    critical_fails = [r for r in fails if r.severity == "CRITICAL"]
    other_fails    = [r for r in fails if r.severity != "CRITICAL"]

    probe_results = [r for r in active if r.check_id.startswith(('AI-INP', 'AI-OUT'))]
    probe_fails   = [r for r in probe_results if r.status == FAIL]
    probe_passes  = [r for r in probe_results if r.status == PASS]

    lines = []
    w   = 60
    sep = "━" * w

    mode_label = _MODE_LABELS.get(mode, mode)
    if model:
        mode_label = f"{mode_label}  [{model}]"

    lines.append("")
    lines.append("M.A.R.K. Sentinel — AI Security Audit Results")
    lines.append("=" * w)
    emphasis = profile.get('framework_emphasis')
    fw_label = _FW_LABELS.get(emphasis, '')

    lines.append(f"Target:  {target}")
    lines.append(f"Profile: {profile.get('name', 'default')}  |  Date: {date.today()}")
    if fw_label:
        lines.append(f"Framework: {fw_label}")
    lines.append(f"Mode:    {mode_label}")
    lines.append("")

    # Summary block
    total = len(active)
    lines.append("SUMMARY")
    lines.append("-" * 30)
    lines.append(f"  Evaluated:  {total} checks")
    lines.append(f"  ✅ PASS:    {len(passes)}")
    lines.append(f"  ⚠️  WARN:    {len(warns)}")
    lines.append(f"  🔴 FAIL:    {len(fails)}")
    if skipped:
        lines.append(f"  ⏭  SKIP:    {len(skipped)}  (agentic checks — require a deployed agent environment)")
    if probe_results and is_live:
        lines.append("")
        lines.append(f"  Live adversarial probe results ({len(probe_results)} probes):")
        lines.append(f"    ✅ Passed: {len(probe_passes)}   🔴 Failed: {len(probe_fails)}")
    lines.append("")

    if not fails and not warns:
        lines.append(sep)
        lines.append("  🎉 All evaluated checks passed!")
        lines.append(sep)
        lines.append("")
    else:
        if critical_fails:
            lines.append(sep)
            lines.append(f"  CRITICAL — FIX IMMEDIATELY ({len(critical_fails)} issue{'s' if len(critical_fails) > 1 else ''})")
            lines.append(sep)
            for r in critical_fails:
                lines += _format_result(r, is_smb, show_fix=True, profile=profile)

        if other_fails:
            lines.append(sep)
            lines.append(f"  FAIL ({len(other_fails)} issue{'s' if len(other_fails) > 1 else ''})")
            lines.append(sep)
            for r in other_fails:
                lines += _format_result(r, is_smb, show_fix=True, profile=profile)

        if warns:
            lines.append(sep)
            lines.append(f"  WARNINGS ({len(warns)})")
            lines.append(sep)
            for r in warns:
                lines += _format_result(r, is_smb, show_fix=True, profile=profile)

    # Skipped — with descriptions so the reader knows what wasn't tested
    if skipped:
        lines.append(sep)
        lines.append(f"  NOT EVALUATED — agentic environment required ({len(skipped)})")
        lines.append(sep)
        lines.append("  These checks require a deployed AI agent with tool access.")
        lines.append("  They cannot be evaluated against a raw API endpoint.")
        lines.append("")
        for r in skipped:
            lines.append(f"  ⏭  {r.check_id}: {r.title}")
            desc = _SKIP_DESCRIPTIONS.get(r.check_id)
            if desc:
                lines += _wrap(desc, indent="       ", width=72)
            lines.append("")

    # Next steps
    step = 1
    next_lines = []
    if critical_fails:
        next_lines.append(f"  {step}. Fix {len(critical_fails)} CRITICAL issue{'s' if len(critical_fails) > 1 else ''} immediately — these are active risks.")
        step += 1
    if other_fails:
        next_lines.append(f"  {step}. Address {len(other_fails)} remaining FAIL{'s' if len(other_fails) > 1 else ''}.")
        step += 1
    if warns:
        next_lines.append(f"  {step}. Review {len(warns)} warning{'s' if len(warns) > 1 else ''} — some may not apply to your setup.")
        step += 1
    if skipped and not is_live:
        next_lines.append(f"  {step}. Run in live mode to evaluate {len(skipped)} agentic checks:")
        next_lines.append("       python audit.py --mode api --endpoint https://api.openai.com/v1 --profile default")
        step += 1

    if next_lines:
        lines.append(sep)
        lines.append("  NEXT STEPS")
        lines.append(sep)
        lines += next_lines
        lines.append("")
        lines.append("  For JSON output:      add --output json")
        lines.append("  For compliance map:   add --output sarif")
        lines.append("  For policy-as-code:   add --output rego")
        lines.append("")

    return '\n'.join(lines)


def _wrap(text: str, indent: str = "     ", width: int = 74) -> list:
    words = text.split()
    lines = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current.rstrip())
            current = indent + word
        else:
            current = current + " " + word if len(current) > len(indent) else current + word
    if current.strip():
        lines.append(current.rstrip())
    return lines


def _format_result(r: CheckResult, is_smb: bool, show_fix: bool = True,
                   profile: dict | None = None) -> list:
    lines = []
    icon  = _STATUS_ICON[r.status]
    label = _STATUS_LABEL[r.status]

    sev_tag = f" [{r.severity}]" if r.status in (FAIL, WARN) else ""
    lines.append(f"  {icon} [{label}]{sev_tag} {r.check_id}: {r.title}")

    details = _SMB_DETAILS.get(r.check_id) if (is_smb and r.check_id in _SMB_DETAILS) else (r.details or "")
    lines += _wrap(details, indent="     ")

    if r.evidence:
        for ev in r.evidence[:4]:
            lines.append(f"       • {ev}")

    if profile:
        emphasis = profile.get('framework_emphasis')
        controls = profile.get('_controls', {}).get(r.check_id, [])
        if controls and emphasis:
            ctrl_label = 'NIST 800-53' if emphasis == 'fedramp' else 'CMMC Practices'
            lines.append(f"     {ctrl_label}: {', '.join(controls)}")

    include_rem = profile.get('include_remediation', True) if profile else True
    if show_fix and r.remediation and include_rem:
        lines.append("     How to fix:")
        for fix_line in r.remediation.splitlines():
            if fix_line.strip():
                lines.append(f"       {fix_line}")

    lines.append("")
    return lines
