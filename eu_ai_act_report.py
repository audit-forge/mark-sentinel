"""
M.A.R.K. Sentinel — EU AI Act Readiness Report Generator
Produces a printable one-page HTML report mapping scan findings to EU AI Act articles.
"""
import html
import time

# Maps article -> (short title, obligation summary, check_ids that provide coverage)
_ARTICLES: list[tuple[str, str, str, list[str]]] = [
    ('Art. 9',  'Risk Management System',
     'Establish and maintain a risk management system throughout the AI lifecycle, including identification, analysis and evaluation of known and foreseeable risks.',
     ['AI-GOV-001', 'AI-GOV-003']),
    ('Art. 10', 'Data and Data Governance',
     'Training, validation and testing data sets shall be subject to data governance practices. Data collection, processing and retention must be documented.',
     ['AI-GOV-002', 'AI-RUNTIME-001']),
    ('Art. 11', 'Technical Documentation',
     'Technical documentation must be drawn up before the AI system is placed on the market and kept up to date throughout its lifecycle.',
     ['AI-GOV-001', 'AI-GOV-005', 'AI-RUNTIME-002']),
    ('Art. 12', 'Record-Keeping / Logging',
     'High-risk AI systems must automatically log events. Logging must be enabled with adequate retention to allow post-hoc investigation.',
     ['AI-RUNTIME-001', 'AI-RUNTIME-002', 'AI-RUNTIME-003']),
    ('Art. 13', 'Transparency & Information Provision',
     'AI systems must be designed to ensure their operation is sufficiently transparent for deployers and users to understand their outputs.',
     ['AI-AGENT-002', 'AI-OUT-001', 'AI-OUT-002']),
    ('Art. 14', 'Human Oversight',
     'High-risk AI systems must be designed to allow effective human oversight, including the ability to monitor, understand, and override automated decisions.',
     ['AI-GOV-004', 'AI-AGENT-001', 'AI-AGENT-003']),
    ('Art. 15', 'Accuracy, Robustness & Cybersecurity',
     'High-risk AI systems must achieve appropriate accuracy and be resilient to errors, faults, and adversarial inputs. Credentials and secrets must be protected.',
     ['AI-DEPLOY-001', 'AI-DEPLOY-002', 'AI-DEPLOY-003', 'AI-DEPLOY-004']),
    ('Art. 26', 'Obligations of Deployers',
     'Deployers must use AI systems in accordance with instructions for use, maintain human oversight, and ensure staff have adequate AI literacy.',
     ['AI-GOV-005', 'AI-RUNTIME-003', 'AI-RUNTIME-004']),
    ('Art. 50', 'Transparency Obligations (GPAI / Chatbots)',
     'AI systems interacting with people must disclose they are AI. AI-generated content must be labeled. Applies to all GPAI model deployments.',
     ['AI-AGENT-002', 'AI-OUT-003', 'AI-INP-001']),
    ('Art. 53', 'GPAI Model Provider Obligations',
     'Providers of general-purpose AI models must maintain technical documentation, establish copyright policies, and publish summaries of training data.',
     ['AI-SUPPLY-001', 'AI-SUPPLY-002', 'AI-DEPLOY-004', 'AI-DEPLOY-005']),
]


def generate_eu_ai_act_report(devices: list[dict], org_name: str = '') -> str:
    """
    Generate an EU AI Act readiness HTML report.

    devices: list of dicts with keys: hostname, _report (the parsed report dict)
    org_name: optional org name for the report header
    """
    # Collect all FAIL findings across all devices, keyed by check_id
    fail_checks: dict[str, list[dict]] = {}
    warn_checks: dict[str, list[dict]] = {}
    all_check_ids: set[str] = set()

    for dev in devices:
        report = dev.get('_report') or {}
        hostname = dev.get('hostname', 'Unknown')
        for f in report.get('findings', []):
            cid    = f.get('check_id', '')
            status = f.get('status', '')
            if not cid:
                continue
            all_check_ids.add(cid)
            if status == 'FAIL':
                fail_checks.setdefault(cid, []).append({**f, 'hostname': hostname})
            elif status == 'WARN':
                warn_checks.setdefault(cid, []).append({**f, 'hostname': hostname})

    # Score each article
    article_rows = []
    total_articles = len(_ARTICLES)
    compliant_count = 0
    gap_count = 0
    atrisk_count = 0

    for art_id, art_title, art_desc, check_ids in _ARTICLES:
        relevant_checks = [c for c in check_ids if c in all_check_ids]
        if not relevant_checks:
            status = 'NOT SCANNED'
            status_color = '#6B7280'
            status_bg = '#F9FAFB'
        else:
            failing = [c for c in relevant_checks if c in fail_checks]
            warning = [c for c in relevant_checks if c in warn_checks]
            if failing:
                status = 'GAP'
                status_color = '#DC2626'
                status_bg = '#FEF2F2'
                gap_count += 1
            elif warning:
                status = 'AT RISK'
                status_color = '#CA8A04'
                status_bg = '#FFFBEB'
                atrisk_count += 1
            else:
                status = 'COMPLIANT'
                status_color = '#16A34A'
                status_bg = '#F0FDF4'
                compliant_count += 1

        # Build finding detail rows
        finding_rows = []
        for cid in check_ids:
            for f in fail_checks.get(cid, []):
                finding_rows.append((cid, f.get('title', ''), f.get('hostname', ''), 'FAIL', '#DC2626'))
            for f in warn_checks.get(cid, []):
                finding_rows.append((cid, f.get('title', ''), f.get('hostname', ''), 'WARN', '#CA8A04'))

        article_rows.append((art_id, art_title, art_desc, status, status_color, status_bg, finding_rows))

    scored = compliant_count + gap_count + atrisk_count
    score_pct = int(100 * compliant_count / scored) if scored else 0

    date_str = time.strftime('%B %d, %Y')
    esc = html.escape

    rows_html = ''
    for art_id, art_title, art_desc, status, sc, sbg, findings in article_rows:
        finding_detail = ''
        if findings:
            finding_detail = '<div style="margin-top:8px;border-top:1px solid #F3F4F6;padding-top:8px">'
            for cid, ftitle, hostname, fstatus, fc in findings:
                finding_detail += (
                    f'<div style="display:flex;gap:8px;align-items:baseline;font-size:11px;margin-bottom:3px">'
                    f'<span style="color:{fc};font-weight:700;min-width:36px">{esc(fstatus)}</span>'
                    f'<span style="color:#6B7280;font-family:monospace">{esc(cid)}</span>'
                    f'<span style="color:#374151">{esc(ftitle)}</span>'
                    f'<span style="color:#9CA3AF;margin-left:auto">on {esc(hostname)}</span>'
                    f'</div>'
                )
            finding_detail += '</div>'

        rows_html += f'''
        <tr>
          <td style="padding:10px 12px;vertical-align:top;white-space:nowrap;font-weight:600;font-size:13px;color:#374151;border-bottom:1px solid #F3F4F6">{esc(art_id)}</td>
          <td style="padding:10px 12px;vertical-align:top;border-bottom:1px solid #F3F4F6">
            <div style="font-size:13px;font-weight:600;color:#111827;margin-bottom:3px">{esc(art_title)}</div>
            <div style="font-size:11px;color:#6B7280;line-height:1.5">{esc(art_desc)}</div>
            {finding_detail}
          </td>
          <td style="padding:10px 12px;vertical-align:top;text-align:center;border-bottom:1px solid #F3F4F6">
            <span style="display:inline-block;padding:3px 8px;border-radius:4px;font-size:10px;font-weight:700;color:{sc};background:{sbg};white-space:nowrap">{esc(status)}</span>
          </td>
        </tr>'''

    score_color = '#16A34A' if score_pct >= 80 else ('#CA8A04' if score_pct >= 50 else '#DC2626')
    org_display = esc(org_name) if org_name else 'Your Organisation'
    device_count = len(devices)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EU AI Act Readiness Report — {org_display}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
         background: #fff; color: #111827; font-size: 13px; }}
  @media print {{
    body {{ font-size: 11px; }}
    .no-print {{ display: none !important; }}
    @page {{ margin: 1.5cm; }}
  }}
  .page {{ max-width: 900px; margin: 0 auto; padding: 32px 24px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #F9FAFB; font-size: 10px; font-weight: 700; text-transform: uppercase;
        letter-spacing: .06em; color: #6B7280; padding: 8px 12px; text-align: left;
        border-bottom: 2px solid #E5E7EB; }}
</style>
</head>
<body>
<div class="page">

  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:28px">
    <div>
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#6B7280;margin-bottom:4px">Confidential — Generated by Arckon</div>
      <h1 style="font-size:22px;font-weight:800;color:#111827;margin-bottom:4px">EU AI Act Readiness Report</h1>
      <div style="font-size:14px;color:#6B7280">{org_display} &nbsp;·&nbsp; {date_str} &nbsp;·&nbsp; {device_count} device{'' if device_count == 1 else 's'} scanned</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:36px;font-weight:800;color:{score_color}">{score_pct}%</div>
      <div style="font-size:11px;color:#6B7280">Compliance score</div>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:28px">
    <div style="background:#F0FDF4;border:1px solid #BBF7D0;border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:26px;font-weight:800;color:#16A34A">{compliant_count}</div>
      <div style="font-size:11px;color:#16A34A;font-weight:600">Articles Compliant</div>
    </div>
    <div style="background:#FFFBEB;border:1px solid #FDE68A;border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:26px;font-weight:800;color:#CA8A04">{atrisk_count}</div>
      <div style="font-size:11px;color:#CA8A04;font-weight:600">At Risk</div>
    </div>
    <div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;padding:14px;text-align:center">
      <div style="font-size:26px;font-weight:800;color:#DC2626">{gap_count}</div>
      <div style="font-size:11px;color:#DC2626;font-weight:600">Compliance Gaps</div>
    </div>
  </div>

  <div style="background:#F0F9FF;border:1px solid #BAE6FD;border-radius:8px;padding:14px 16px;margin-bottom:24px;font-size:12px;color:#0369A1;line-height:1.6">
    <strong>About this report:</strong> The EU AI Act (Regulation 2024/1689) applies to all organisations placing or using AI systems in the EU market.
    General-purpose AI model (GPAI) obligations have been in force since August 2025.
    High-risk AI system requirements (Title III) apply from August 2026.
    This report maps Arckon scan findings to the relevant articles.
    <strong>GAP</strong> means a failing check was found. <strong>AT RISK</strong> means a warning. <strong>COMPLIANT</strong> means all relevant checks passed.
  </div>

  <table>
    <thead>
      <tr>
        <th style="width:90px">Article</th>
        <th>Obligation &amp; Findings</th>
        <th style="width:110px;text-align:center">Status</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <div style="margin-top:24px;padding-top:16px;border-top:1px solid #F3F4F6;display:flex;justify-content:space-between;align-items:center">
    <div style="font-size:10px;color:#9CA3AF">
      Generated by Arckon AI Security &nbsp;·&nbsp; {date_str} &nbsp;·&nbsp;
      This report covers deployer obligations. Provider and importer obligations may apply separately.
    </div>
    <button class="no-print" onclick="window.print()"
      style="background:#111827;color:#fff;border:none;border-radius:6px;padding:7px 16px;font-size:12px;cursor:pointer;font-weight:600">
      &#8659; Print / Save PDF
    </button>
  </div>

</div>
</body>
</html>'''
