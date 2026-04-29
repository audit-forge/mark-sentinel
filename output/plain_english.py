"""
M.A.R.K. Sentinel — Plain English output formatter
Produces human-readable terminal output with SMB-friendly language option.
"""
from datetime import date
from checks import CheckResult, PASS, FAIL, WARN, SKIP, STATUS_RANK, SEVERITY_RANK

_STATUS_ICON = {PASS: "✅", FAIL: "🔴", WARN: "⚠️ ", SKIP: "⏭ "}
_STATUS_LABEL = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", SKIP: "SKIP"}

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


def format_report(results: list, profile: dict, target: str) -> str:
    is_smb = profile.get('name', '').lower().startswith('smb')

    active = [r for r in results if r.status != SKIP]
    skipped = [r for r in results if r.status == SKIP]

    fails = [r for r in active if r.status == FAIL]
    warns = [r for r in active if r.status == WARN]
    passes = [r for r in active if r.status == PASS]

    critical_fails = [r for r in fails if r.severity == "CRITICAL"]
    other_fails = [r for r in fails if r.severity != "CRITICAL"]

    lines = []
    w = 56
    sep = "━" * w

    lines.append("")
    lines.append("M.A.R.K. Sentinel — AI Security Audit Results")
    lines.append("=" * w)
    lines.append(f"Target:  {target}")
    lines.append(f"Profile: {profile.get('name', 'default')}  |  Date: {date.today()}")
    lines.append(f"Mode:    config (static scan)")
    lines.append("")

    # Summary
    total = len(active)
    lines.append("SUMMARY")
    lines.append("-" * 30)
    lines.append(f"  Evaluated:  {total} checks")
    lines.append(f"  ✅ PASS:    {len(passes)}")
    lines.append(f"  ⚠️  WARN:    {len(warns)}")
    lines.append(f"  🔴 FAIL:    {len(fails)}")
    if skipped:
        lines.append(f"  ⏭  SKIP:    {len(skipped)}  (require --mode api or --mode local)")
    lines.append("")

    if not fails and not warns:
        lines.append(sep)
        lines.append("  🎉 All evaluated checks passed!")
        lines.append(sep)
        lines.append("")
    else:
        # Critical fails first
        if critical_fails:
            lines.append(sep)
            lines.append(f"  CRITICAL — FIX IMMEDIATELY ({len(critical_fails)} issue{'s' if len(critical_fails) > 1 else ''})")
            lines.append(sep)
            for r in critical_fails:
                lines += _format_result(r, is_smb, verbose=True)

        # Other fails
        if other_fails:
            lines.append(sep)
            lines.append(f"  FAIL ({len(other_fails)} issue{'s' if len(other_fails) > 1 else ''})")
            lines.append(sep)
            for r in other_fails:
                lines += _format_result(r, is_smb, verbose=True)

        # Warnings
        if warns:
            lines.append(sep)
            lines.append(f"  WARNINGS ({len(warns)})")
            lines.append(sep)
            for r in warns:
                lines += _format_result(r, is_smb, verbose=False)

    # Passes (compact)
    if passes:
        lines.append(sep)
        lines.append(f"  PASSED ({len(passes)})")
        lines.append(sep)
        for r in passes:
            lines.append(f"  ✅ {r.check_id}: {r.title}")
        lines.append("")

    # Skipped
    if skipped:
        lines.append(sep)
        lines.append(f"  SKIPPED — requires live scan ({len(skipped)})")
        lines.append(sep)
        for r in skipped:
            lines.append(f"  ⏭  {r.check_id}: {r.title}")
        lines.append("")
        lines.append("  To run live checks:")
        lines.append("    python audit.py --mode api --endpoint https://api.openai.com/v1 --profile default")
        lines.append("    python audit.py --mode local --ollama-host http://localhost:11434 --model llama3.1")
        lines.append("")

    # Next steps
    if fails:
        lines.append(sep)
        lines.append("  NEXT STEPS")
        lines.append(sep)
        lines.append(f"  1. Fix {len(critical_fails)} CRITICAL issue(s) first — these are active risks.")
        if other_fails:
            lines.append(f"  2. Address {len(other_fails)} remaining FAIL(s).")
        if warns:
            lines.append(f"  3. Review {len(warns)} warning(s) — some may not apply to your setup.")
        if skipped:
            lines.append(f"  4. Run with --mode api or --mode local to evaluate {len(skipped)} live checks.")
        lines.append("")
        lines.append("  For JSON output: add --output json")
        lines.append("  For compliance report: add --output sarif")
        lines.append("")

    return '\n'.join(lines)


def _format_result(r: CheckResult, is_smb: bool, verbose: bool) -> list:
    lines = []
    icon = _STATUS_ICON[r.status]
    label = _STATUS_LABEL[r.status]

    lines.append(f"  {icon} [{label}] [{r.severity}] {r.check_id}: {r.title}")

    # SMB-friendly details override
    if is_smb and r.check_id in _SMB_DETAILS:
        details = _SMB_DETAILS[r.check_id]
    else:
        details = r.details

    # Wrap details at ~70 chars
    words = details.split()
    current = "     "
    for word in words:
        if len(current) + len(word) + 1 > 74:
            lines.append(current)
            current = "     " + word
        else:
            current = current + " " + word if len(current) > 5 else current + word
    if current.strip():
        lines.append(current)

    if r.evidence:
        for ev in r.evidence[:3]:
            lines.append(f"       • {ev}")

    if verbose and r.remediation:
        lines.append("     Fix:")
        for fix_line in r.remediation.splitlines():
            lines.append(f"       {fix_line}")

    lines.append("")
    return lines
