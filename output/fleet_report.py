"""
M.A.R.K. Sentinel — Fleet Report Generator
Produces consolidated PDF reports across all devices in three tiers:
  executive  — 1-2 pages, fleet health score, top risks, trend
  ciso       — per-device breakdown, compliance mapping, remediation priorities
  technical  — full findings for every device with evidence
"""
from datetime import datetime, timezone
from fpdf import FPDF

_SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
_SEV_COLOR = {
    'CRITICAL': (248, 81,  73),
    'HIGH':     (210, 153,  34),
    'MEDIUM':   (88,  166, 255),
    'LOW':      (63,  185, 80),
    'INFO':     (110, 118, 129),
}
_STATUS_COLOR = {
    'FAIL': (248, 81,  73),
    'WARN': (210, 153,  34),
    'PASS': (63,  185, 80),
    'SKIP': (110, 118, 129),
}


def _safe(s) -> str:
    if s is None:
        return ''
    t = str(s).replace('—', '-').replace('–', '-').replace('’', "'")
    try:
        t.encode('latin-1')
        return t
    except UnicodeEncodeError:
        return t.encode('latin-1', errors='replace').decode('latin-1')


def _ts(epoch) -> str:
    if not epoch:
        return 'never'
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    except Exception:
        return str(epoch)


def _risk_score(fail, warn, total) -> int:
    if not total:
        return 0
    return max(0, 100 - round((fail * 3 + warn) / max(total, 1) * 100))


def _bar_ascii(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return '[' + '#' * filled + '-' * (width - filled) + f'] {score}%'


class _PDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 9)
        if getattr(self, '_demo', False):
            self.set_text_color(240, 165, 0)
            self.cell(0, 6, 'DEMO REPORT - FOR EVALUATION ONLY - NOT FOR DISTRIBUTION', align='C')
        else:
            self.set_text_color(110, 118, 129)
            self.cell(0, 6, 'M.A.R.K. Sentinel - Fleet Security Report  |  CONFIDENTIAL', align='R')
        self.ln(4)

    def footer(self):
        self.set_y(-13)
        self.set_font('Helvetica', size=8)
        if getattr(self, '_demo', False):
            self.set_text_color(240, 165, 0)
            self.cell(0, 5, 'DEMO - M.A.R.K. Sentinel Evaluation Copy - Not for distribution  |  Contact sales@markai.io', align='L')
        else:
            self.set_text_color(110, 118, 129)
            sig_text = f'  |  Report ID: {self._report_id}  |  Signed by M.A.R.K. Sentinel' if getattr(self, '_report_id', None) else ''
            self.cell(0, 5, f'Generated {datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}  |  © 2026 M.A.R.K. AI Systems. Patent Pending.{sig_text}', align='L')
        self.cell(0, 5, f'Page {self.page_no()}', align='R')


def _section_header(pdf: _PDF, title: str):
    pdf.set_fill_color(22, 27, 34)
    pdf.set_text_color(88, 166, 255)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, _safe(title), fill=True, ln=True)
    pdf.set_text_color(201, 209, 217)
    pdf.ln(1)


def _device_row(pdf: _PDF, hostname: str, platform: str, fail: int, warn: int, passed: int, score: int, last_seen):
    total = fail + warn + passed
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(201, 209, 217)
    pdf.cell(70, 6, _safe(hostname), ln=False)
    pdf.set_font('Helvetica', size=9)
    pdf.set_text_color(110, 118, 129)
    pdf.cell(25, 6, _safe(platform or 'unknown'), ln=False)

    pdf.set_text_color(*_STATUS_COLOR['FAIL'])
    pdf.cell(20, 6, f'{fail} FAIL', ln=False)
    pdf.set_text_color(*_STATUS_COLOR['WARN'])
    pdf.cell(20, 6, f'{warn} WARN', ln=False)
    pdf.set_text_color(*_STATUS_COLOR['PASS'])
    pdf.cell(20, 6, f'{passed} PASS', ln=False)

    color = (63, 185, 80) if score >= 80 else (210, 153, 34) if score >= 60 else (248, 81, 73)
    pdf.set_text_color(*color)
    pdf.set_font('Helvetica', 'B', 9)
    pdf.cell(20, 6, f'Score {score}%', ln=False)

    pdf.set_font('Helvetica', size=8)
    pdf.set_text_color(110, 118, 129)
    pdf.cell(0, 6, _safe(_ts(last_seen)), ln=True)


def generate_fleet_pdf(devices: list, tier: str = 'ciso', report_id: str = '', demo: bool = False) -> bytes:
    """
    devices: list of dicts from storage.list_devices() merged with get_latest_report()
    tier: 'executive' | 'ciso' | 'technical'
    report_id: optional signing report ID to embed in footer
    demo: True adds watermark headers/footers and a cover banner
    """
    pdf = _PDF()
    pdf._report_id = report_id or ''
    pdf._demo = demo
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(14, 14, 14)
    pdf.add_page()

    # ── Cover / Title ──────────────────────────────────────────────────────────
    pdf.set_fill_color(13, 17, 23)
    pdf.rect(0, 0, 210, 45, 'F')
    pdf.set_y(10)
    pdf.set_font('Helvetica', 'B', 20)
    pdf.set_text_color(201, 209, 217)

    tier_label = {'executive': 'Executive Summary', 'ciso': 'CISO Report', 'technical': 'Technical Findings'}.get(tier, 'Fleet Report')
    pdf.cell(0, 10, 'M.A.R.K. Sentinel', ln=True, align='C')
    pdf.set_font('Helvetica', size=12)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 7, f'Fleet {tier_label}', ln=True, align='C')
    pdf.set_font('Helvetica', size=9)
    pdf.set_text_color(110, 118, 129)
    pdf.cell(0, 6, datetime.now(tz=timezone.utc).strftime('%B %d, %Y'), ln=True, align='C')
    if demo:
        pdf.ln(4)
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(240, 165, 0)
        pdf.cell(0, 8, 'DEMO REPORT - FOR EVALUATION PURPOSES ONLY', ln=True, align='C')
        pdf.set_font('Helvetica', size=9)
        pdf.set_text_color(110, 118, 129)
        pdf.cell(0, 6, 'Not for distribution. Contact sales@markai.io to purchase a license.', ln=True, align='C')
    pdf.ln(14)

    # ── Aggregate stats ────────────────────────────────────────────────────────
    total_devices = len(devices)
    total_fail = sum(d.get('fail_count', 0) or 0 for d in devices)
    total_warn = sum(d.get('warn_count', 0) or 0 for d in devices)
    total_pass = sum(d.get('pass_count', 0) or 0 for d in devices)
    total_checks = total_fail + total_warn + total_pass
    fleet_score  = _risk_score(total_fail, total_warn, total_checks)

    devices_at_risk = sum(1 for d in devices if (d.get('fail_count') or 0) > 0)

    _section_header(pdf, 'Fleet Overview')
    pdf.set_font('Helvetica', size=10)
    pdf.set_text_color(201, 209, 217)

    overview = [
        ('Devices monitored',   str(total_devices)),
        ('Devices with failures', str(devices_at_risk)),
        ('Total failing checks', str(total_fail)),
        ('Total warnings',       str(total_warn)),
        ('Total passing checks', str(total_pass)),
        ('Fleet security score', f'{fleet_score}%'),
    ]
    for label, val in overview:
        pdf.set_font('Helvetica', size=10)
        pdf.set_text_color(110, 118, 129)
        pdf.cell(70, 6, _safe(label), ln=False)
        pdf.set_font('Helvetica', 'B', 10)
        color = (63, 185, 80) if label == 'Fleet security score' and fleet_score >= 80 \
               else (210, 153, 34) if label == 'Fleet security score' and fleet_score >= 60 \
               else (248, 81, 73) if label in ('Total failing checks', 'Devices with failures') and int(val) > 0 \
               else (201, 209, 217)
        pdf.set_text_color(*color)
        pdf.cell(0, 6, _safe(val), ln=True)
    pdf.ln(4)

    # ── Device summary table ───────────────────────────────────────────────────
    _section_header(pdf, 'Device Status')
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(110, 118, 129)
    pdf.cell(70, 5, 'HOSTNAME', ln=False)
    pdf.cell(25, 5, 'PLATFORM', ln=False)
    pdf.cell(20, 5, 'FAIL', ln=False)
    pdf.cell(20, 5, 'WARN', ln=False)
    pdf.cell(20, 5, 'PASS', ln=False)
    pdf.cell(20, 5, 'SCORE', ln=False)
    pdf.cell(0,  5, 'LAST SEEN', ln=True)
    pdf.set_draw_color(48, 54, 61)
    pdf.line(14, pdf.get_y(), 196, pdf.get_y())
    pdf.ln(1)

    for d in devices:
        fail  = d.get('fail_count', 0) or 0
        warn  = d.get('warn_count', 0) or 0
        passed = d.get('pass_count', 0) or 0
        score = _risk_score(fail, warn, fail + warn + passed)
        _device_row(pdf, d.get('hostname') or d.get('device_id') or '?',
                    d.get('platform', ''), fail, warn, passed, score,
                    d.get('last_seen') or d.get('report_time'))
    pdf.ln(4)

    # ── Executive only: stop here after top risks ──────────────────────────────
    all_findings = _collect_all_findings(devices)

    _section_header(pdf, 'Top Critical & High Findings Across Fleet')
    crit_high = [f for f in all_findings if f['severity'] in ('CRITICAL', 'HIGH') and f['status'] == 'FAIL']
    crit_high.sort(key=lambda x: (_SEV_ORDER.index(x['severity']), x.get('hostname') or ''))

    if not crit_high:
        pdf.set_font('Helvetica', size=10)
        pdf.set_text_color(63, 185, 80)
        pdf.cell(0, 6, 'No critical or high severity failures found across the fleet.', ln=True)
    else:
        for f in crit_high[:30 if tier == 'executive' else 999]:
            _finding_row(pdf, f, show_device=True, verbose=(tier == 'technical'))
    pdf.ln(3)

    if tier == 'executive':
        _exec_recommendations(pdf, crit_high, fleet_score, devices_at_risk, total_devices)
        return bytes(pdf.output())

    # ── CISO / Technical: per-device breakdown ─────────────────────────────────
    _section_header(pdf, 'Per-Device Breakdown')
    for d in devices:
        report = d.get('_report') or {}
        results = report.get('findings', report.get('results', []))
        if not results:
            continue
        fail  = d.get('fail_count', 0) or 0
        warn  = d.get('warn_count', 0) or 0
        passed = d.get('pass_count', 0) or 0
        score = _risk_score(fail, warn, fail + warn + passed)

        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(88, 166, 255)
        pdf.cell(0, 7, _safe(f"Device: {d.get('hostname') or d.get('device_id') or '?'}"), ln=True)
        pdf.set_font('Helvetica', size=9)
        pdf.set_text_color(110, 118, 129)
        pdf.cell(0, 5, _safe(
            f"Platform: {d.get('platform','?')}  |  Profile: {report.get('profile','?')}  |  "
            f"Score: {score}%  |  Last seen: {_ts(d.get('last_seen'))}"
        ), ln=True)
        pdf.ln(1)

        if tier == 'technical':
            show_all = True
            verbose  = True
        else:
            show_all = False
            verbose  = False

        findings = [r for r in results if r.get('status') in ('FAIL', 'WARN')] if not show_all else results
        findings.sort(key=lambda x: (_SEV_ORDER.index(x.get('severity', 'INFO')) if x.get('severity') in _SEV_ORDER else 99,))
        for r in findings:
            f = dict(r)
            f['hostname'] = d.get('hostname', '')
            _finding_row(pdf, f, show_device=False, verbose=verbose)

        if tier == 'ciso':
            _compliance_summary(pdf, results)

        pdf.line(14, pdf.get_y(), 196, pdf.get_y())
        pdf.ln(4)

    if tier == 'ciso':
        _ciso_remediation_plan(pdf, crit_high)

    return bytes(pdf.output())


def _collect_all_findings(devices: list) -> list:
    out = []
    for d in devices:
        report = d.get('_report') or {}
        for r in report.get('findings', report.get('results', [])):
            f = dict(r)
            f['hostname'] = d.get('hostname') or d.get('device_id') or '?'
            out.append(f)
    return out


def _finding_row(pdf: _PDF, f: dict, show_device: bool, verbose: bool):
    status = f.get('status', '')
    sev    = f.get('severity', 'INFO')
    title  = f.get('title', f.get('check_id', '?'))
    details = f.get('details', '') or ''
    remediation = f.get('remediation', '') or ''

    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_text_color(*_STATUS_COLOR.get(status, (201, 209, 217)))
    label = f'[{status}]'
    pdf.cell(14, 5, _safe(label), ln=False)

    if status in ('FAIL', 'WARN'):
        pdf.set_text_color(*_SEV_COLOR.get(sev, (110, 118, 129)))
        pdf.cell(20, 5, _safe(f'[{sev}]'), ln=False)
    else:
        pdf.cell(20, 5, '', ln=False)

    if show_device:
        pdf.set_text_color(110, 118, 129)
        pdf.set_font('Helvetica', size=9)
        pdf.cell(35, 5, _safe((f.get('hostname') or f.get('device_id') or '?')[:20]), ln=False)

    pdf.set_text_color(201, 209, 217)
    pdf.set_font('Helvetica', size=9)
    w = 110 if show_device else 145
    pdf.multi_cell(w, 5, _safe(title))

    if verbose and details:
        pdf.set_font('Helvetica', size=8)
        pdf.set_text_color(110, 118, 129)
        pdf.set_x(14)
        pdf.multi_cell(0, 4, _safe(details[:300]))

    if verbose and remediation:
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(63, 185, 80)
        pdf.set_x(14)
        pdf.multi_cell(0, 4, _safe('Fix: ' + remediation[:250]))
        pdf.ln(1)


def _compliance_summary(pdf: _PDF, results: list):
    fw_counts = {}
    for r in results:
        if r.get('status') != 'FAIL':
            continue
        fw = r.get('frameworks') or {}
        if isinstance(fw, dict):
            for k in fw:
                fw_counts[k] = fw_counts.get(k, 0) + 1
    if not fw_counts:
        return
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 5, 'Compliance impact:', ln=True)
    pdf.set_font('Helvetica', size=8)
    pdf.set_text_color(110, 118, 129)
    for fw, count in sorted(fw_counts.items(), key=lambda x: -x[1]):
        pdf.cell(0, 4, _safe(f'  {fw}: {count} failing control(s)'), ln=True)
    pdf.ln(1)


def _exec_recommendations(pdf: _PDF, crit_high: list, score: int, at_risk: int, total: int):
    pdf.add_page()
    _section_header(pdf, 'Executive Recommendations')
    pdf.set_font('Helvetica', size=10)
    pdf.set_text_color(201, 209, 217)

    if score >= 90:
        posture = 'Strong. The fleet is operating with a healthy AI security posture.'
    elif score >= 70:
        posture = 'Moderate. Several issues require attention but no critical systemic risk.'
    elif score >= 50:
        posture = 'Elevated risk. Critical findings exist that should be remediated within 30 days.'
    else:
        posture = 'High risk. Immediate action required on critical findings.'

    pdf.multi_cell(0, 6, _safe(f'Overall posture: {posture}'))
    pdf.ln(2)

    if at_risk > 0:
        pdf.set_text_color(248, 81, 73)
        pdf.multi_cell(0, 6, _safe(f'{at_risk} of {total} device(s) have active failures requiring remediation.'))
        pdf.ln(2)

    pdf.set_text_color(201, 209, 217)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 6, 'Immediate actions (Critical/High):', ln=True)
    pdf.set_font('Helvetica', size=9)

    seen = set()
    for f in crit_high[:10]:
        key = f.get('check_id', f.get('title', ''))
        if key in seen:
            continue
        seen.add(key)
        rem = (f.get('remediation') or '').split('\n')[0][:120]
        pdf.set_text_color(248, 81, 73)
        pdf.cell(5, 5, '-', ln=False)
        pdf.set_text_color(201, 209, 217)
        pdf.multi_cell(0, 5, _safe(f"{f.get('title', '')} ({f.get('hostname') or f.get('device_id') or '?'})"
                                   + (f'  ->  {rem}' if rem else '')))
    pdf.ln(3)
    pdf.set_font('Helvetica', 'I', 9)
    pdf.set_text_color(110, 118, 129)
    pdf.multi_cell(0, 5, 'For full technical details and per-device findings, request the CISO or Technical report.')


def _ciso_remediation_plan(pdf: _PDF, crit_high: list):
    if not crit_high:
        return
    pdf.add_page()
    _section_header(pdf, 'Remediation Priority Plan')
    pdf.set_font('Helvetica', size=9)

    priority = 1
    seen = set()
    for f in crit_high:
        key = f.get('check_id', '')
        if key in seen:
            continue
        seen.add(key)
        devices_affected = [x.get('hostname') or x.get('device_id') or '?' for x in crit_high if x.get('check_id') == key]

        pdf.set_text_color(88, 166, 255)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, _safe(f'{priority}. [{f.get("severity")}] {f.get("title", "")}'), ln=True)
        priority += 1

        pdf.set_font('Helvetica', size=8)
        pdf.set_text_color(110, 118, 129)
        pdf.cell(0, 4, _safe(f'Affected: {", ".join(devices_affected[:5])}'), ln=True)

        rem = f.get('remediation', '')
        if rem:
            pdf.set_text_color(63, 185, 80)
            pdf.multi_cell(0, 4, _safe(rem[:400]))
        pdf.ln(2)


_MCP_REMEDIATION_PDF = {
    'fastmcp':              'Add auth=BearerAuth(token=os.environ["MCP_TOKEN"]) to your FastMCP server constructor.',
    'uvx':                  'Pass --api-key flag or configure authentication in the MCP server settings file.',
    'modelcontextprotocol': 'Add OAuth 2.1 or API-key middleware to the MCP server before deploying to a shared network.',
    'default':              'Configure an API key or OAuth 2.1 bearer token on this MCP server. Restrict allowed origins to trusted hosts only.',
}

_OWASP_MAP_PDF = {
    'none':    ['A02 Tool/Plugin Hijacking - unauthenticated server allows arbitrary tool invocation',
                'A08 Excessive Agency - AI can call any exposed tool without authorization check',
                'A07 Data Exfiltration - tools like read_file or query_database accessible with no credentials'],
    'unknown': ['A09 Audit Bypass - authentication status unverified, logging compliance uncertain'],
}

_EU_AI_ACT_MAP_PDF = {
    'none':     'Article 12 (Logging) - unauthenticated MCP servers produce no attributable audit trail; '
                'Article 14 (Human Oversight) - no gate between AI agent and tool execution.',
    'unknown':  'Article 12 (Logging) - authentication status unverified; audit trail completeness cannot be confirmed.',
    'required': 'Compliant with Article 12 and Article 14 access controls.',
}


class _MCPPDF(_PDF):
    def header(self):
        self.set_font('Helvetica', 'B', 9)
        if getattr(self, '_demo', False):
            self.set_text_color(240, 165, 0)
            self.cell(0, 6, 'DEMO REPORT - FOR EVALUATION ONLY - NOT FOR DISTRIBUTION', align='C')
        else:
            self.set_text_color(110, 118, 129)
            self.cell(0, 6, 'M.A.R.K. Sentinel - MCP & Agent Governance Report  |  CONFIDENTIAL', align='R')
        self.ln(4)


def generate_mcp_pdf(servers: list, tier: str = 'ciso', demo: bool = False) -> bytes:
    """
    servers: list of dicts from storage.list_mcp_servers()
    tier: 'executive' | 'ciso' | 'technical'
    """
    pdf = _MCPPDF()
    pdf._report_id = ''
    pdf._demo = demo
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(14, 14, 14)
    pdf.add_page()

    tier_label = {'executive': 'Executive Summary', 'ciso': 'CISO Report', 'technical': 'Technical Findings'}.get(tier, 'MCP Report')

    no_auth      = [s for s in servers if s.get('auth_status') == 'none']
    unknown_auth = [s for s in servers if s.get('auth_status') == 'unknown']
    auth_ok      = [s for s in servers if s.get('auth_status') == 'required']

    risk_level = 'CRITICAL' if no_auth else 'MEDIUM' if unknown_auth else 'LOW'
    risk_color = (248, 81, 73) if risk_level == 'CRITICAL' else (210, 153, 34) if risk_level == 'MEDIUM' else (63, 185, 80)

    # ── Cover ──────────────────────────────────────────────────────────────────
    pdf.set_fill_color(13, 17, 23)
    pdf.rect(0, 0, 210, 45, 'F')
    pdf.set_y(10)
    pdf.set_font('Helvetica', 'B', 20)
    pdf.set_text_color(201, 209, 217)
    pdf.cell(0, 10, 'M.A.R.K. Sentinel', ln=True, align='C')
    pdf.set_font('Helvetica', size=12)
    pdf.set_text_color(79, 70, 229)
    pdf.cell(0, 7, f'MCP & Agent Governance - {tier_label}', ln=True, align='C')
    pdf.set_font('Helvetica', size=9)
    pdf.set_text_color(110, 118, 129)
    pdf.cell(0, 6, datetime.now(tz=timezone.utc).strftime('%B %d, %Y'), ln=True, align='C')
    if demo:
        pdf.ln(4)
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(240, 165, 0)
        pdf.cell(0, 8, 'DEMO REPORT - FOR EVALUATION PURPOSES ONLY', ln=True, align='C')
    pdf.ln(14)

    # ── Risk banner ────────────────────────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(*risk_color)
    if no_auth:
        pdf.cell(0, 7, _safe(f'HIGH RISK - {len(no_auth)} unauthenticated MCP server(s) detected'), ln=True)
    elif unknown_auth:
        pdf.cell(0, 7, _safe(f'REVIEW REQUIRED - {len(unknown_auth)} MCP server(s) with unverified authentication'), ln=True)
    else:
        pdf.cell(0, 7, 'All MCP servers require authentication', ln=True)
    pdf.ln(2)

    # ── Stats ──────────────────────────────────────────────────────────────────
    _section_header(pdf, 'Overview')
    stats = [
        ('Total MCP servers',         str(len(servers))),
        ('Unauthenticated',            str(len(no_auth))),
        ('Authentication unverified',  str(len(unknown_auth))),
        ('Authentication confirmed',   str(len(auth_ok))),
        ('Discovered via network scan', str(len([s for s in servers if s.get('source') == 'network']))),
        ('Discovered via process scan', str(len([s for s in servers if s.get('source') == 'process']))),
    ]
    for label, val in stats:
        pdf.set_font('Helvetica', size=10)
        pdf.set_text_color(110, 118, 129)
        pdf.cell(80, 6, _safe(label), ln=False)
        pdf.set_font('Helvetica', 'B', 10)
        color = (248, 81, 73) if label == 'Unauthenticated' and int(val) > 0 \
               else (210, 153, 34) if label == 'Authentication unverified' and int(val) > 0 \
               else (63, 185, 80) if label == 'Authentication confirmed' \
               else (201, 209, 217)
        pdf.set_text_color(*color)
        pdf.cell(0, 6, _safe(val), ln=True)
    pdf.ln(4)

    if not servers:
        pdf.set_font('Helvetica', size=10)
        pdf.set_text_color(110, 118, 129)
        pdf.cell(0, 6, 'No MCP servers discovered. Run a scan from the Sentinel dashboard.', ln=True)
        return bytes(pdf.output())

    # ── Executive: narrative only ──────────────────────────────────────────────
    if tier == 'executive':
        _section_header(pdf, 'Business Risk Summary')
        pdf.set_font('Helvetica', size=10)
        pdf.set_text_color(201, 209, 217)
        if no_auth:
            pdf.multi_cell(0, 6, _safe(
                f'{len(no_auth)} MCP server(s) are operating without any authentication. '
                'These servers allow any AI agent or user on the network to invoke tool calls - '
                'including file access, database queries, and code execution - without credentials. '
                'This represents a direct path for data exfiltration and unauthorized AI actions.'
            ))
            pdf.ln(3)
        if unknown_auth:
            pdf.multi_cell(0, 6, _safe(
                f'{len(unknown_auth)} MCP server(s) have unverified authentication status. '
                'These should be audited to confirm access controls are in place.'
            ))
            pdf.ln(3)
        if auth_ok and not no_auth and not unknown_auth:
            pdf.multi_cell(0, 6, _safe(
                'All discovered MCP servers require authentication. '
                'AI agent tool call exposure is within acceptable risk tolerance. '
                'Continue monitoring as new servers may be deployed by business units.'
            ))
            pdf.ln(3)

        _section_header(pdf, 'Recommended Actions')
        pdf.set_font('Helvetica', size=10)
        pdf.set_text_color(201, 209, 217)
        actions = []
        if no_auth:
            actions.append('Require authentication on all unauthenticated MCP servers immediately')
            actions.append('Conduct emergency review of tool access logs for unauthorized invocations')
        if unknown_auth:
            actions.append('Audit MCP servers with unverified authentication within 48 hours')
        actions.append('Establish a register of approved MCP servers and responsible teams')
        actions.append('Implement network segmentation to restrict MCP server access to authorized agents only')
        for i, a in enumerate(actions, 1):
            pdf.set_text_color(88, 166, 255)
            pdf.cell(6, 6, f'{i}.', ln=False)
            pdf.set_text_color(201, 209, 217)
            pdf.multi_cell(0, 6, _safe(a))
        return bytes(pdf.output())

    # ── CISO / Technical: server inventory ────────────────────────────────────
    _section_header(pdf, 'MCP Server Inventory')
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(110, 118, 129)
    pdf.cell(50, 5, 'HOST', ln=False)
    pdf.cell(12, 5, 'PORT', ln=False)
    pdf.cell(25, 5, 'AUTH', ln=False)
    pdf.cell(20, 5, 'SOURCE', ln=False)
    pdf.cell(35, 5, 'REPORTER', ln=False)
    pdf.cell(0,  5, 'LAST SEEN', ln=True)
    pdf.set_draw_color(48, 54, 61)
    pdf.line(14, pdf.get_y(), 196, pdf.get_y())
    pdf.ln(1)

    for s in servers:
        auth = s.get('auth_status', 'unknown')
        auth_color = (248, 81, 73) if auth == 'none' else (210, 153, 34) if auth == 'unknown' else (63, 185, 80)
        auth_label = {'none': 'NONE', 'unknown': 'UNKNOWN', 'required': 'OK'}.get(auth, auth.upper())
        pdf.set_font('Helvetica', size=9)
        pdf.set_text_color(201, 209, 217)
        pdf.cell(50, 5, _safe((s.get('host') or '')[:28]), ln=False)
        pdf.set_text_color(110, 118, 129)
        pdf.cell(12, 5, _safe(str(s.get('port') or '')), ln=False)
        pdf.set_text_color(*auth_color)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(25, 5, _safe(auth_label), ln=False)
        pdf.set_font('Helvetica', size=9)
        pdf.set_text_color(110, 118, 129)
        pdf.cell(20, 5, _safe((s.get('source') or '')[:10]), ln=False)
        pdf.cell(35, 5, _safe((s.get('reporter_hostname') or '')[:20]), ln=False)
        pdf.cell(0,  5, _safe(_ts(s.get('last_seen'))), ln=True)
    pdf.ln(4)

    # ── OWASP + EU AI Act mapping ──────────────────────────────────────────────
    if no_auth or unknown_auth:
        _section_header(pdf, 'Risk Framework Mapping')
        for s in (no_auth + unknown_auth):
            auth = s.get('auth_status', 'unknown')
            owasp_risks = _OWASP_MAP_PDF.get(auth, [])
            eu_text = _EU_AI_ACT_MAP_PDF.get(auth, '')
            if not owasp_risks and not eu_text:
                continue
            pdf.set_font('Helvetica', 'B', 9)
            pdf.set_text_color(88, 166, 255)
            pdf.cell(0, 5, _safe(f"{s.get('host') or '?'}:{s.get('port') or ''}"), ln=True)
            if owasp_risks:
                pdf.set_font('Helvetica', 'B', 8)
                pdf.set_text_color(110, 118, 129)
                pdf.cell(0, 4, 'OWASP Agentic AI Top 10:', ln=True)
                pdf.set_font('Helvetica', size=8)
                pdf.set_text_color(210, 153, 34)
                for risk in owasp_risks:
                    pdf.set_x(18)
                    pdf.multi_cell(0, 4, _safe(f'- {risk}'))
            if eu_text:
                pdf.set_font('Helvetica', 'B', 8)
                pdf.set_text_color(110, 118, 129)
                pdf.cell(0, 4, 'EU AI Act:', ln=True)
                pdf.set_font('Helvetica', size=8)
                pdf.set_text_color(248, 81, 73)
                pdf.set_x(18)
                pdf.multi_cell(0, 4, _safe(eu_text))
            pdf.ln(2)
        pdf.ln(2)

    if tier == 'ciso':
        return bytes(pdf.output())

    # ── Technical: per-server detail with tools + remediation ─────────────────
    _section_header(pdf, 'Per-Server Technical Detail')
    for s in servers:
        auth = s.get('auth_status', 'unknown')
        auth_color = (248, 81, 73) if auth == 'none' else (210, 153, 34) if auth == 'unknown' else (63, 185, 80)
        tools = s.get('tools') or []

        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(88, 166, 255)
        pdf.cell(0, 6, _safe(f"{s.get('host') or '?'}:{s.get('port') or ''}"), ln=True)

        meta_pairs = [
            ('Auth status',  {'none': 'UNAUTHENTICATED', 'unknown': 'UNVERIFIED', 'required': 'AUTHENTICATED'}.get(auth, auth.upper())),
            ('Source',       s.get('source') or 'unknown'),
            ('Reporter',     s.get('reporter_hostname') or ''),
            ('Last seen',    _ts(s.get('last_seen'))),
        ]
        for label, val in meta_pairs:
            pdf.set_font('Helvetica', size=8)
            pdf.set_text_color(110, 118, 129)
            pdf.cell(30, 4, _safe(label), ln=False)
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_text_color(*auth_color if label == 'Auth status' else (201, 209, 217))
            pdf.cell(0, 4, _safe(val), ln=True)

        if tools:
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_text_color(110, 118, 129)
            pdf.cell(0, 4, f'Exposed tools ({len(tools)}):', ln=True)
            pdf.set_font('Helvetica', size=8)
            pdf.set_text_color(201, 209, 217)
            _HIGH_RISK_TOOLS = {'read_file', 'write_file', 'execute_code', 'run_command', 'query_database',
                                'list_files', 'delete_file', 'create_file', 'shell', 'exec'}
            tool_line = '  ' + ',  '.join(tools[:20])
            pdf.set_x(18)
            pdf.multi_cell(0, 4, _safe(tool_line))
            high_risk = [t for t in tools if t.lower() in _HIGH_RISK_TOOLS]
            if high_risk and auth == 'none':
                pdf.set_font('Helvetica', 'B', 8)
                pdf.set_text_color(248, 81, 73)
                pdf.set_x(18)
                pdf.multi_cell(0, 4, _safe(f'HIGH-RISK tools exposed without auth: {", ".join(high_risk)}'))

        if auth == 'none':
            server_name = (s.get('server_name') or '').lower()
            fix = _MCP_REMEDIATION_PDF['default']
            for key, hint in _MCP_REMEDIATION_PDF.items():
                if key != 'default' and key in server_name:
                    fix = hint
                    break
            pdf.set_font('Helvetica', 'I', 8)
            pdf.set_text_color(63, 185, 80)
            pdf.set_x(18)
            pdf.multi_cell(0, 4, _safe(f'Remediation: {fix}'))

        pdf.set_draw_color(48, 54, 61)
        pdf.line(14, pdf.get_y() + 2, 196, pdf.get_y() + 2)
        pdf.ln(5)

    return bytes(pdf.output())
