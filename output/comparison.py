from typing import Dict, List


def compare_reports(before: Dict, after: Dict) -> str:
    """Compare two parsed JSON report dicts and return a plain-text summary."""
    b_summary = before.get('summary', {})
    a_summary = after.get('summary', {})
    b_findings = {f['check_id']: f for f in before.get('findings', []) if f.get('check_id')}
    a_findings = {f['check_id']: f for f in after.get('findings', []) if f.get('check_id')}

    target = after.get('target') or before.get('target') or ''
    profile = after.get('profile') or before.get('profile') or ''
    b_date = before.get('scan_date', '')
    a_date = after.get('scan_date', '')

    b_fail = b_summary.get('fail', 0)
    a_fail = a_summary.get('fail', 0)
    b_pass = b_summary.get('pass', 0)
    a_pass = a_summary.get('pass', 0)

    # Match check ids union
    all_ids = sorted(set(list(b_findings.keys()) + list(a_findings.keys())))

    resolved = []
    new = []
    unchanged = []

    for cid in all_ids:
        b = b_findings.get(cid)
        a = a_findings.get(cid)
        b_status = (b.get('status') if b else None)
        a_status = (a.get('status') if a else None)
        title = (a.get('title') if a and a.get('title') else (b.get('title') if b else ''))

        # Resolved: was FAIL or WARN in before, now PASS in after
        if b_status in ('FAIL', 'WARN') and a_status == 'PASS':
            resolved.append((cid, title))
            continue
        # New: not FAIL in before (None/ PASS/ WARN/ SKIP) and now FAIL in after
        if a_status == 'FAIL' and b_status != 'FAIL':
            new.append((cid, title))
            continue
        # Unchanged failures: FAIL in both
        if b_status == 'FAIL' and a_status == 'FAIL':
            unchanged.append((cid, title))

    # Summary line details
    resolved_count = len(resolved)
    new_count = len(new)
    unchanged_count = len(unchanged)
    net = (b_fail - a_fail)

    # Build output
    lines: List[str] = []
    lines.append(f"Target: {target}")
    lines.append(f"Profile: {profile}")
    lines.append(f"Before scan date: {b_date}")
    lines.append(f"After scan date:  {a_date}")
    lines.append("")
    lines.append(f"Score change: FAIL {b_fail} -> {a_fail}   |   PASS {b_pass} -> {a_pass}")
    lines.append("")

    def _format_list(title: str, items):
        lines.append(title)
        if not items:
            lines.append('  None')
        else:
            for cid, t in items:
                lines.append(f"  - {cid}: {t}")
        lines.append("")

    _format_list('Resolved findings (now PASS):', resolved)
    _format_list('New findings (now FAIL):', new)
    _format_list('Unchanged failures (FAIL in both):', unchanged)

    lines.append(f"Summary: {resolved_count} issues resolved, {new_count} new issues, {unchanged_count} unchanged — net change: {net:+d}")

    return '\n'.join(lines)
