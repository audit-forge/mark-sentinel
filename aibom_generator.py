"""
M.A.R.K. Sentinel — AI-BOM (AI Bill of Materials) Generator
Produces a structured inventory of all AI components detected across the fleet.
Output: CycloneDX-AI-inspired JSON + printable HTML report.
"""
import html
import csv
import io
import re
import time
import uuid

# ── Evidence parsers ──────────────────────────────────────────────────────────

# Matches AI-SUPPLY-006 tool_summary entries:  "Display Name (Vendor): file1.md, file2.json"
_TOOL_SUMMARY_RE = re.compile(r'^(.+?):\s+(.+)$')

# Matches AI-SUPPLY-003 unpinned AI package lists:  "Unpinned AI packages: openai, langchain"
_UNPINNED_PKGS_RE = re.compile(r'(?i)unpinned ai packages?:\s*(.+)')
# Matches the PASS evidence:  "AI packages detected: openai, langchain"
_PINNED_PKGS_RE   = re.compile(r'(?i)ai packages detected:\s*(.+)')
# Total pinned count:  "42 pinned packages found"
_TOTAL_PINNED_RE  = re.compile(r'(\d+) pinned packages')

# Matches AI-SUPPLY-005 / model evidence. Handles several forms:
#   config.json — "model": "gpt-4o"
#   app.py — model = "glm-4"
#   .env — MODEL=glm-4
#   script.sh — ollama run kimi-k2.7-code:cloud
# Also parses the inventory line: "Models detected: name1 (floating), name2 (pinned)"
_MODEL_VER_RE = re.compile(
    r'(?i)'
    r'(?:'
    r'"model"\s*[:=]\s*["\x27]|model\s*=\s*["\x27]|model_name\s*[:=]\s*["\x27]|'
    r'--model\s+|[\s=]MODEL[\s=]|OLLAMA_MODEL\s*=|from\s+|ollama\s+(?:run|pull|list)\s+|'
    r'Models detected:\s*'
    r')'
    r'["\x27]?'
    r'([a-zA-Z0-9][a-zA-Z0-9._:-]*[a-zA-Z0-9])'
)

# Extracts (model_name, kind) from the new inventory evidence line.
_MODEL_INVENTORY_RE = re.compile(
    r'(?i)Models detected:\s*(.+)'
)

# Matches AI-TOOL evidence:  "openai pip package installed"  /  "@org/pkg npm package installed"
_TOOL_PKG_RE = re.compile(r'^([^\s]+)\s+(pip|npm)\s+package\s+installed', re.IGNORECASE)

_AI_TOOL_NAMES = {
    'AI-TOOL-001': 'Gemini CLI / Google GenAI SDK',
    'AI-TOOL-002': 'Claude / Claude Code (Anthropic)',
    'AI-TOOL-003': 'OpenAI CLI / SDK',
    'AI-TOOL-004': 'Aider',
    'AI-TOOL-005': 'GitHub Copilot CLI',
    'AI-TOOL-006': 'Cursor IDE',
}

# Shadow AI service names that map to known providers (for dedup/normalisation)
_SAAS_PROVIDER_MAP: dict[str, str] = {
    'ChatGPT':             'OpenAI',
    'OpenAI API':          'OpenAI',
    'OpenAI':              'OpenAI',
    'Claude (Anthropic)':  'Anthropic',
    'Anthropic API':       'Anthropic',
    'Anthropic':           'Anthropic',
    'Google Gemini':       'Google',
    'Google AI API':       'Google',
    'Google AI Studio':    'Google',
    'Microsoft Copilot':   'Microsoft',
    'GitHub Copilot':      'GitHub / Microsoft',
    'GitHub Copilot API':  'GitHub / Microsoft',
    'Hugging Face':        'Hugging Face',
    'HuggingFace API':     'Hugging Face',
    'Perplexity AI':       'Perplexity',
    'Perplexity API':      'Perplexity',
    'Mistral AI':          'Mistral',
    'Mistral API':         'Mistral',
    'Groq':                'Groq',
    'Groq API':            'Groq',
    'Cohere':              'Cohere',
    'Cohere API':          'Cohere',
    'Replicate':           'Replicate',
    'Replicate API':       'Replicate',
    'Together AI':         'Together AI',
    'Together API':        'Together AI',
    'Grok (xAI)':          'xAI',
    'xAI':                 'xAI',
    'Cursor AI':           'Cursor',
    'Vercel v0':           'Vercel',
    'StackBlitz Bolt':     'StackBlitz',
    'GLM':                 'Zhipu AI',
    'GLM API':             'Zhipu AI',
    'Kimi':                'Moonshot AI',
    'Kimi API':            'Moonshot AI',
    'Moonshot AI':         'Moonshot AI',
    'Moonshot API':        'Moonshot AI',
    'DeepSeek':            'DeepSeek',
    'DeepSeek API':        'DeepSeek',
    'Qwen':                'Alibaba',
    'Qwen API':            'Alibaba',
    'Alibaba':             'Alibaba',
}

# Country of origin by provider (ISO 3166-1 alpha-2 code). Defaults to 'Unknown'.
_PROVIDER_COUNTRY_MAP: dict[str, str] = {
    'OpenAI':              'US',
    'Anthropic':           'US',
    'Google':              'US',
    'Meta':                'US',
    'Microsoft':           'US',
    'GitHub / Microsoft':  'US',
    'xAI':                 'US',
    'Groq':                'US',
    'Cohere':              'US',
    'Perplexity':          'US',
    'Replicate':           'US',
    'Together AI':         'US',
    'Hugging Face':        'US',
    'Cursor':              'US',
    'Vercel':              'US',
    'StackBlitz':          'US',
    'Mistral':             'FR',
    'Zhipu AI':            'CN',
    'Moonshot AI':         'CN',
    'DeepSeek':            'CN',
    'Alibaba':             'CN',
}
_DEFAULT_ORIGIN_COUNTRY = 'US'


def _provider_country(provider: str) -> str:
    return _PROVIDER_COUNTRY_MAP.get(provider, 'Unknown')


def _origin_label(country: str) -> str:
    return 'domestic' if country == _DEFAULT_ORIGIN_COUNTRY else ('foreign' if country and country != 'Unknown' else 'unknown')


def _guess_provider(model_name: str) -> str:
    """Guess provider from a model name or tag."""
    vl = model_name.lower()
    if 'glm' in vl or 'zhipu' in vl or 'chatglm' in vl:
        return 'Zhipu AI'
    if 'kimi' in vl or 'moonshot' in vl:
        return 'Moonshot AI'
    if 'deepseek' in vl or 'deep-seek' in vl:
        return 'DeepSeek'
    if 'qwen' in vl:
        return 'Alibaba'
    if 'gpt-oss' in vl:
        return 'OpenAI'
    if 'gpt' in vl or 'openai' in vl:
        return 'OpenAI'
    if 'claude' in vl or 'anthropic' in vl:
        return 'Anthropic'
    if 'gemini' in vl:
        return 'Google'
    if 'llama' in vl or 'llama-' in vl:
        return 'Meta'
    if 'mistral' in vl or 'mixtral' in vl:
        return 'Mistral'
    if 'command' in vl:
        return 'Cohere'
    return 'Unknown'


def _split_csv(s: str) -> list[str]:
    return [x.strip() for x in s.split(',') if x.strip() and x.strip().lower() != 'none']


def _is_pip_directive(value: str) -> bool:
    """Never render pip options such as -e or -r as software components."""
    return value.lstrip().startswith('-')


def _report_findings(report: dict) -> list[dict]:
    """Combine posture and profile-independent inventory findings once."""
    combined = list(report.get('findings', report.get('results', [])) or [])
    combined.extend(report.get('inventory_findings', []) or [])
    unique = []
    seen = set()
    for finding in combined:
        key = (
            finding.get('check_id', ''),
            finding.get('status', ''),
            finding.get('details', ''),
            tuple(finding.get('evidence') or []),
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


# ── Component extraction ──────────────────────────────────────────────────────

def _extract_components(
    devices: list[dict],
    shadow_devices: list[dict] | None = None,
) -> dict:
    """
    Walk every device's findings and shadow_devices, returning structured
    component dicts keyed for deduplication.

    Returns {
      models:   {key: {name, version, pinned, provider, devices: [], risks: []}},
      packages: {name: {name, pinned, devices: [], risks: []}},
      tools:    {key: {name, files: [], devices: [], risks: []}},
      services: {name: {name, provider, source, devices: []}},
      risks:    [{check_id, title, severity, status, hostname, details}],
    }
    """
    models:   dict[str, dict] = {}
    packages: dict[str, dict] = {}
    tools:    dict[str, dict] = {}
    services: dict[str, dict] = {}
    risks:    list[dict] = []

    def _add_model(name: str, version: str, pinned: bool, provider: str, hostname: str, risk: bool = False):
        key = name.lower()
        if key not in models:
            country = _provider_country(provider)
            models[key] = {'name': name, 'version': version, 'pinned': pinned,
                           'provider': provider, 'country': country,
                           'origin': _origin_label(country),
                           'devices': [], 'risks': []}
        m = models[key]
        if hostname not in m['devices']:
            m['devices'].append(hostname)
        if not pinned and risk and 'floating version' not in m['risks']:
            m['risks'].append('floating version')

    def _add_package(name: str, pinned: bool, hostname: str):
        if _is_pip_directive(name):
            return
        key = name.lower()
        if key not in packages:
            packages[key] = {'name': name, 'pinned': pinned, 'devices': []}
        p = packages[key]
        if not pinned:
            p['pinned'] = False
        if hostname not in p['devices']:
            p['devices'].append(hostname)

    def _add_tool(display: str, files: list[str], hostname: str):
        key = display.lower()
        if key not in tools:
            tools[key] = {'name': display, 'files': [], 'devices': []}
        t = tools[key]
        for f in files:
            if f and f not in t['files']:
                t['files'].append(f)
        if hostname not in t['devices']:
            t['devices'].append(hostname)

    def _add_service(name: str, source: str, hostname: str):
        key = name.lower()
        provider = _SAAS_PROVIDER_MAP.get(name, name)
        country = _provider_country(provider)
        if key not in services:
            services[key] = {'name': name, 'provider': provider,
                             'country': country, 'origin': _origin_label(country),
                             'source': source, 'devices': []}
        s = services[key]
        if hostname not in s['devices']:
            s['devices'].append(hostname)

    for dev in devices:
        hostname = dev.get('hostname', 'Unknown')
        report   = dev.get('_report') or {}
        findings = _report_findings(report)

        for f in findings:
            cid      = f.get('check_id', '')
            status   = f.get('status', '')
            evidence = f.get('evidence') or []
            title    = f.get('title', '')
            details  = f.get('details', '')

            # Collect supply-chain risks
            if status in ('FAIL', 'WARN') and (
                cid.startswith('AI-SUPPLY') or cid.startswith('AI-TOOL')
            ):
                risks.append({
                    'check_id': cid,
                    'title':    title,
                    'severity': f.get('severity', ''),
                    'status':   status,
                    'hostname': hostname,
                    'details':  details,
                })

            # ── AI-SUPPLY-001: model provenance ───────────────────────────────
            if cid == 'AI-SUPPLY-001':
                for ev in evidence:
                    if 'inventory found:' in ev.lower():
                        path = ev.split(':', 1)[-1].strip()
                        _add_model('AI Inventory', path, True, 'documented', hostname)
                    elif 'provenance fields' in ev.lower():
                        _add_model('Model Config', 'documented', True, 'documented', hostname)

            # ── AI-SUPPLY-002: model checksums ────────────────────────────────
            elif cid == 'AI-SUPPLY-002':
                for ev in evidence:
                    if 'checksum file found:' in ev.lower():
                        path = ev.split(':', 1)[-1].strip()
                        _add_model('Local Model', path, True, 'local', hostname)
                    elif 'local model file references' in ev.lower():
                        _add_model('Local Model', 'unverified', False, 'local', hostname)

            # ── AI-SUPPLY-003: dependencies ───────────────────────────────────
            elif cid == 'AI-SUPPLY-003':
                for ev in evidence:
                    m = _UNPINNED_PKGS_RE.search(ev)
                    if m:
                        for pkg in _split_csv(m.group(1)):
                            _add_package(pkg, False, hostname)
                    m = _PINNED_PKGS_RE.search(ev)
                    if m:
                        for pkg in _split_csv(m.group(1)):
                            _add_package(pkg, True, hostname)

            # ── AI-SUPPLY-005: model version pinning ──────────────────────────
            elif cid == 'AI-SUPPLY-005':
                # Parse the consolidated inventory line if present.
                inventory_match = None
                for ev in evidence:
                    inventory_match = _MODEL_INVENTORY_RE.search(ev)
                    if inventory_match:
                        break
                if inventory_match:
                    for part in inventory_match.group(1).split(','):
                        part = part.strip()
                        if not part:
                            continue
                        # Each part looks like "name (floating)" or "name (pinned)"
                        name_kind = re.split(r'\s*\(\s*(floating|pinned)\s*\)', part)
                        if len(name_kind) >= 2:
                            ver = name_kind[0].strip()
                            kind = name_kind[1].strip()
                        else:
                            ver = part
                            kind = 'pinned'
                        if ver.lower() in ('version', 'model', 'latest', 'current'):
                            continue
                        is_floating = kind == 'floating'
                        provider = _guess_provider(ver)
                        _add_model(ver, 'config-detected', not is_floating, provider, hostname,
                                   risk=is_floating)
                else:
                    # Legacy: extract individual model strings from evidence snippets
                    for ev in evidence:
                        for m in _MODEL_VER_RE.finditer(ev):
                            ver = m.group(1)
                            if ver.lower() in ('version', 'model', 'latest', 'current'):
                                continue
                            is_floating = ':latest' in ver or not re.search(r'\d{8}|\d{4}-\d{2}-\d{2}|:\w{4,}', ver)
                            provider = _guess_provider(ver)
                            _add_model(ver, 'config-detected', not is_floating, provider, hostname,
                                       risk=is_floating)

            # ── AI-SUPPLY-006: agent instruction files ────────────────────────
            elif cid == 'AI-SUPPLY-006':
                for ev in evidence:
                    m = _TOOL_SUMMARY_RE.match(ev)
                    if m:
                        display = m.group(1).strip()
                        files   = [fp.strip() for fp in m.group(2).split(',')]
                        _add_tool(display, files, hostname)

            # ── AI-TOOL-00X: installed AI tools ──────────────────────────────
            elif cid.startswith('AI-TOOL-'):
                tool_name = _AI_TOOL_NAMES.get(cid)
                if tool_name and status != 'SKIP':
                    _add_tool(tool_name, [], hostname)
                if not tool_name:
                    for ev in evidence + ([details] if details else []):
                        m = _TOOL_PKG_RE.match(ev)
                        if m:
                            _add_tool(m.group(1), [], hostname)

    # ── Shadow devices → services ─────────────────────────────────────────────
    for sd in (shadow_devices or []):
        svc = sd.get('service') or sd.get('host', 'Unknown')
        src = sd.get('source', 'network')
        reporter = sd.get('reporter_hostname') or sd.get('hostname', 'Unknown')
        _add_service(svc, src, reporter)

    return {
        'models':   models,
        'packages': packages,
        'tools':    tools,
        'services': services,
        'risks':    risks,
    }


# ── JSON output ───────────────────────────────────────────────────────────────

def generate_aibom_json(
    devices: list[dict],
    org_name: str = '',
    shadow_devices: list[dict] | None = None,
) -> dict:
    """Return a CycloneDX-AI-inspired dict suitable for JSON serialisation."""
    extracted = _extract_components(devices, shadow_devices)

    components = []

    for m in extracted['models'].values():
        if m['name'] in ('AI Inventory', 'Model Config'):
            continue
        components.append({
            'type':     'machine-learning-model',
            'bom-ref':  f"model-{m['name'].replace(' ', '-').lower()}",
            'name':     m['name'],
            'version':  m['version'],
            'supplier': {'name': m['provider']},
            'properties': [
                {'name': 'arckon:pinned',  'value': str(m['pinned']).lower()},
                {'name': 'arckon:devices', 'value': ', '.join(m['devices'])},
                {'name': 'arckon:country', 'value': m['country']},
                {'name': 'arckon:origin',  'value': m['origin']},
            ] + [
                {'name': 'arckon:risk', 'value': r} for r in m['risks']
            ],
        })

    for p in extracted['packages'].values():
        components.append({
            'type':    'library',
            'bom-ref': f"pkg-{p['name'].replace(' ', '-').lower()}",
            'name':    p['name'],
            'properties': [
                {'name': 'arckon:pinned',  'value': str(p['pinned']).lower()},
                {'name': 'arckon:devices', 'value': ', '.join(p['devices'])},
            ],
        })

    for t in extracted['tools'].values():
        components.append({
            'type':    'platform',
            'bom-ref': f"tool-{t['name'].replace(' ', '-').lower()[:40]}",
            'name':    t['name'],
            'properties': [
                {'name': 'arckon:files',   'value': ', '.join(t['files'][:5])},
                {'name': 'arckon:devices', 'value': ', '.join(t['devices'])},
            ],
        })

    for s in extracted['services'].values():
        components.append({
            'type':     'service',
            'bom-ref':  f"svc-{s['name'].replace(' ', '-').lower()[:40]}",
            'name':     s['name'],
            'supplier': {'name': s['provider']},
            'properties': [
                {'name': 'arckon:source',  'value': s['source']},
                {'name': 'arckon:devices', 'value': ', '.join(s['devices'])},
                {'name': 'arckon:country', 'value': s['country']},
                {'name': 'arckon:origin',  'value': s['origin']},
            ],
        })

    vulnerabilities = []
    for r in extracted['risks']:
        vulnerabilities.append({
            'id':          r['check_id'],
            'description': r['title'],
            'severity':    r['severity'].lower(),
            'affects': [{'ref': r['hostname']}],
        })

    return {
        'bomFormat':    'CycloneDX-AI',
        'specVersion':  '1.6',
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'version':      1,
        'metadata': {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'tools': [{'vendor': 'Arckon', 'name': 'Arckon AI Security', 'version': '1.0'}],
            'component': {'type': 'organization', 'name': org_name or 'Unknown'},
        },
        'components':       components,
        'vulnerabilities':  vulnerabilities,
    }


def _component_properties(component: dict) -> dict[str, str]:
    return {prop.get('name', ''): prop.get('value', '') for prop in component.get('properties', [])}


def generate_aibom_csv(
    devices: list[dict],
    org_name: str = '',
    shadow_devices: list[dict] | None = None,
) -> bytes:
    """Return a spreadsheet-friendly AI-BOM inventory and risk register."""
    bom = generate_aibom_json(devices, org_name, shadow_devices)
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=[
        'record_type', 'component_type', 'name', 'version', 'supplier', 'pinned',
        'devices', 'country', 'origin', 'source', 'risk', 'check_id', 'severity',
        'description', 'affected_device',
    ])
    writer.writeheader()
    for component in bom['components']:
        props = _component_properties(component)
        writer.writerow({
            'record_type': 'component',
            'component_type': component.get('type', ''),
            'name': component.get('name', ''),
            'version': component.get('version', ''),
            'supplier': component.get('supplier', {}).get('name', ''),
            'pinned': props.get('arckon:pinned', ''),
            'devices': props.get('arckon:devices', ''),
            'country': props.get('arckon:country', ''),
            'origin': props.get('arckon:origin', ''),
            'source': props.get('arckon:source', ''),
            'risk': '; '.join(
                prop.get('value', '') for prop in component.get('properties', [])
                if prop.get('name') == 'arckon:risk'
            ),
        })
    for vulnerability in bom['vulnerabilities']:
        writer.writerow({
            'record_type': 'risk',
            'check_id': vulnerability.get('id', ''),
            'severity': vulnerability.get('severity', ''),
            'description': vulnerability.get('description', ''),
            'affected_device': ', '.join(
                item.get('ref', '') for item in vulnerability.get('affects', [])
            ),
        })
    return output.getvalue().encode('utf-8-sig')


def generate_aibom_pdf(
    devices: list[dict],
    org_name: str = '',
    shadow_devices: list[dict] | None = None,
) -> bytes:
    """Return a concise, printable AI-BOM report for non-technical readers."""
    from fpdf import FPDF

    bom = generate_aibom_json(devices, org_name, shadow_devices)
    pdf = FPDF()
    pdf.set_compression(False)
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    def text(value: object) -> str:
        return str(value).encode('latin-1', 'replace').decode('latin-1')

    pdf.set_font('Helvetica', 'B', 18)
    pdf.cell(0, 10, text('AI Bill of Materials'), new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, text(f"Organization: {org_name or 'Fleet'}"), new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 6, text(f"Generated: {bom['metadata']['timestamp']}"), new_x='LMARGIN', new_y='NEXT')
    component_count = len(bom['components'])
    risk_count = len(bom['vulnerabilities'])
    pdf.set_fill_color(239, 246, 255)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(pdf.epw, 8, text(f'Summary: {component_count} AI components | {risk_count} supply-chain risks'),
             fill=True, new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)

    def field(label: str, value: str) -> None:
        if value:
            pdf.set_font('Helvetica', 'B', 8)
            pdf.write(4, text(f'{label}: '))
            pdf.set_font('Helvetica', '', 8)
            pdf.multi_cell(pdf.epw - pdf.get_string_width(f'{label}: '), 4, text(value))

    def component_card(component: dict) -> None:
        props = _component_properties(component)
        pdf.set_draw_color(209, 213, 219)
        pdf.set_fill_color(249, 250, 251)
        pdf.set_font('Helvetica', 'B', 10)
        pdf.multi_cell(pdf.epw, 6, text(component.get('name', 'Unknown component')), border=1,
                       fill=True, new_x='LMARGIN', new_y='NEXT')
        pdf.set_font('Helvetica', '', 8)
        details = []
        if component.get('version'):
            details.append(f"Version: {component['version']}")
        supplier = component.get('supplier', {}).get('name', '')
        if supplier:
            details.append(f'Provider: {supplier}')
        if props.get('arckon:pinned'):
            details.append(f"Pinned: {props['arckon:pinned']}")
        if props.get('arckon:country'):
            details.append(f"Country: {props['arckon:country']}")
        if details:
            pdf.multi_cell(pdf.epw, 4, text(' | '.join(details)), border='LR', new_x='LMARGIN', new_y='NEXT')
        field('Devices', props.get('arckon:devices', ''))
        field('Source', props.get('arckon:source', ''))
        field('Risk', props.get('arckon:risk', ''))
        pdf.cell(pdf.epw, 2, '', border='LBR', new_x='LMARGIN', new_y='NEXT')
        pdf.ln(2)

    for title, component_type in (
        ('AI Models', 'machine-learning-model'),
        ('AI Packages', 'library'),
        ('AI Developer Tools', 'platform'),
        ('AI Services', 'service'),
    ):
        components = [item for item in bom['components'] if item.get('type') == component_type]
        if not components:
            continue
        pdf.set_font('Helvetica', 'B', 13)
        pdf.cell(0, 8, title, new_x='LMARGIN', new_y='NEXT')
        for component in components:
            component_card(component)
        pdf.ln(2)

    if bom['vulnerabilities']:
        pdf.set_font('Helvetica', 'B', 13)
        pdf.cell(0, 8, 'Supply Chain Risks', new_x='LMARGIN', new_y='NEXT')
        for risk in bom['vulnerabilities']:
            affected = ', '.join(item.get('ref', '') for item in risk.get('affects', []))
            pdf.set_fill_color(254, 242, 242)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.multi_cell(pdf.epw, 5, text(
                f"[{risk.get('severity', '').upper()}] {risk.get('id', '')} - {risk.get('description', '')}"
            ), border=1, fill=True, new_x='LMARGIN', new_y='NEXT')
            pdf.set_font('Helvetica', '', 8)
            field('Affected device', affected)
            pdf.cell(pdf.epw, 2, '', border='LBR', new_x='LMARGIN', new_y='NEXT')
            pdf.ln(2)

    return bytes(pdf.output())


# ── HTML output ───────────────────────────────────────────────────────────────

_RISK_COLORS = {
    'CRITICAL': ('#7C3AED', '#F5F3FF'),
    'HIGH':     ('#DC2626', '#FEF2F2'),
    'MEDIUM':   ('#CA8A04', '#FFFBEB'),
    'LOW':      ('#16A34A', '#F0FDF4'),
}


def _risk_badge(severity: str, status: str) -> str:
    if status == 'FAIL':
        color, bg = _RISK_COLORS.get(severity, ('#6B7280', '#F9FAFB'))
    else:
        color, bg = '#CA8A04', '#FFFBEB'
    label = status if status == 'FAIL' else 'WARN'
    return (f'<span style="display:inline-block;padding:2px 7px;border-radius:4px;'
            f'font-size:10px;font-weight:700;color:{color};background:{bg};'
            f'white-space:nowrap">{html.escape(label)}</span>')


def generate_aibom_report(
    devices: list[dict],
    org_name: str = '',
    branding: dict | None = None,
    shadow_devices: list[dict] | None = None,
) -> str:
    """Generate a printable HTML AI-BOM report."""
    branding = branding or {}
    esc       = html.escape
    ex        = _extract_components(devices, shadow_devices)

    models_list   = sorted(
        [m for m in ex['models'].values() if m['name'] not in ('AI Inventory', 'Model Config')],
        key=lambda m: m['name'],
    )
    packages_list = sorted(ex['packages'].values(), key=lambda p: p['name'])
    tools_list    = sorted(ex['tools'].values(),    key=lambda t: t['name'])
    services_list = sorted(ex['services'].values(), key=lambda s: s['name'])
    risks_list    = ex['risks']

    total_components = len(models_list) + len(packages_list) + len(tools_list) + len(services_list)
    unpinned_count   = sum(1 for p in packages_list if not p['pinned'])
    floating_models  = sum(1 for m in models_list if not m['pinned'])
    risk_count       = len(risks_list)
    date_str         = time.strftime('%B %d, %Y')
    device_count     = len(devices)
    org_display      = esc(org_name) if org_name else 'Your Organisation'

    msp_name    = esc(branding.get('msp_name', ''))
    logo_url    = esc(branding.get('logo_url', ''))
    footer_text = esc(branding.get('footer_text', ''))

    brand_line = (
        f'<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;'
        f'color:#6B7280;margin-bottom:4px">Confidential — Prepared by {msp_name}</div>'
        if msp_name else
        '<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;'
        'color:#6B7280;margin-bottom:4px">Confidential — Generated by Arckon</div>'
    )
    logo_html = (
        f'<img src="{logo_url}" alt="{msp_name}" '
        f'style="max-height:40px;max-width:160px;object-fit:contain;margin-bottom:6px"><br>'
        if logo_url else ''
    )
    footer_left = (
        f'<span style="color:#374151">{footer_text}</span>'
        if footer_text else
        '<span style="color:#9CA3AF">Generated by Arckon AI Security Platform</span>'
    )

    # ── models table ──────────────────────────────────────────────────────────
    def _origin_badge(origin: str) -> str:
        if origin == 'domestic':
            return '<span style="color:#16A34A;font-size:10px;font-weight:700">US</span>'
        if origin == 'foreign':
            return '<span style="color:#DC2626;font-size:10px;font-weight:700">FOREIGN</span>'
        return '<span style="color:#6B7280;font-size:10px;font-weight:700">UNKNOWN</span>'

    def models_rows() -> str:
        if not models_list:
            return '<tr><td colspan="6" style="padding:12px;color:#6B7280;text-align:center;font-size:12px">No model version data detected — run a supply chain scan with model config files present.</td></tr>'
        rows = ''
        for m in models_list:
            pin_badge = (
                '<span style="color:#16A34A;font-size:10px;font-weight:700">&#10003; PINNED</span>'
                if m['pinned'] else
                '<span style="color:#DC2626;font-size:10px;font-weight:700">&#9888; FLOATING</span>'
            )
            rows += f'''
            <tr>
              <td style="{_td}">{esc(m["name"])}</td>
              <td style="{_td}"><span style="font-family:monospace;font-size:11px">{esc(m["version"])}</span></td>
              <td style="{_td}">{esc(m["provider"])}</td>
              <td style="{_td}">{_origin_badge(m['origin'])} <span style="color:#6B7280;font-size:11px">({esc(m['country'])})</span></td>
              <td style="{_td}">{pin_badge}</td>
              <td style="{_td};color:#6B7280;font-size:11px">{esc(', '.join(m["devices"][:3]))}</td>
            </tr>'''
        return rows

    # ── packages table ────────────────────────────────────────────────────────
    def packages_rows() -> str:
        if not packages_list:
            return '<tr><td colspan="3" style="padding:12px;color:#6B7280;text-align:center;font-size:12px">No AI packages detected — supply chain checks require a requirements.txt file in the scanned directory.</td></tr>'
        rows = ''
        for p in packages_list:
            pin_badge = (
                '<span style="color:#16A34A;font-size:10px;font-weight:700">&#10003; PINNED</span>'
                if p['pinned'] else
                '<span style="color:#DC2626;font-size:10px;font-weight:700">&#9888; UNPINNED</span>'
            )
            rows += f'''
            <tr>
              <td style="{_td}"><span style="font-family:monospace">{esc(p["name"])}</span></td>
              <td style="{_td}">{pin_badge}</td>
              <td style="{_td};color:#6B7280;font-size:11px">{esc(', '.join(p["devices"][:3]))}</td>
            </tr>'''
        return rows

    # ── tools table ───────────────────────────────────────────────────────────
    def tools_rows() -> str:
        if not tools_list:
            return '<tr><td colspan="3" style="padding:12px;color:#6B7280;text-align:center;font-size:12px">No AI developer tools detected in scanned devices.</td></tr>'
        rows = ''
        for t in tools_list:
            files_text = esc(', '.join(t['files'][:3])) if t['files'] else '<span style="color:#6B7280">detected via package</span>'
            rows += f'''
            <tr>
              <td style="{_td}">{esc(t["name"])}</td>
              <td style="{_td};font-size:11px;color:#374151">{files_text}</td>
              <td style="{_td};color:#6B7280;font-size:11px">{esc(', '.join(t["devices"][:3]))}</td>
            </tr>'''
        return rows

    # ── services table ────────────────────────────────────────────────────────
    def services_rows() -> str:
        if not services_list:
            return '<tr><td colspan="4" style="padding:12px;color:#6B7280;text-align:center;font-size:12px">No active SaaS AI connections detected.</td></tr>'
        rows = ''
        for s in services_list:
            rows += f'''
            <tr>
              <td style="{_td}">{esc(s["name"])}</td>
              <td style="{_td};color:#6B7280;font-size:11px">{esc(s["provider"])}</td>
              <td style="{_td}">{_origin_badge(s['origin'])} <span style="color:#6B7280;font-size:11px">({esc(s['country'])})</span></td>
              <td style="{_td};color:#6B7280;font-size:11px">{esc(', '.join(s["devices"][:3]))}</td>
            </tr>'''
        return rows

    # ── risks table ───────────────────────────────────────────────────────────
    def risks_rows() -> str:
        if not risks_list:
            return '<tr><td colspan="4" style="padding:12px;color:#16A34A;text-align:center;font-size:12px;font-weight:600">&#10003; No supply chain risks detected</td></tr>'
        rows = ''
        for r in risks_list:
            sev = r['severity']
            sc, sbg = _RISK_COLORS.get(sev, ('#6B7280', '#F9FAFB'))
            rows += f'''
            <tr>
              <td style="{_td}">{_risk_badge(r["severity"], r["status"])}</td>
              <td style="{_td};font-family:monospace;font-size:11px;color:#6B7280">{esc(r["check_id"])}</td>
              <td style="{_td}">{esc(r["title"])}</td>
              <td style="{_td};color:#6B7280;font-size:11px">{esc(r["hostname"])}</td>
            </tr>'''
        return rows

    _th = ('padding:8px 12px;background:#F3F4F6;font-size:11px;font-weight:700;'
           'text-transform:uppercase;letter-spacing:.05em;color:#374151;'
           'text-align:left;white-space:nowrap;border-bottom:2px solid #E5E7EB')
    _td  = 'padding:9px 12px;border-bottom:1px solid #F3F4F6;font-size:12px;vertical-align:top'

    score_color = '#DC2626' if risk_count > 5 else ('#CA8A04' if risk_count > 0 else '#16A34A')

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI-BOM — {esc(org_name or "Fleet")}</title>
<style>
  @media print {{
    body {{ margin: 0; padding: 0; }}
    .no-print {{ display: none !important; }}
    @page {{ margin: 1cm 1.5cm; size: A4; }}
  }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: #111827; margin: 0; padding: 24px; background: #fff; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 28px; }}
  h2 {{ font-size: 14px; font-weight: 700; color: #111827; margin: 28px 0 8px;
        padding-bottom: 6px; border-bottom: 2px solid #E5E7EB; }}
  .stat-box {{ display: inline-block; text-align: center; padding: 12px 20px;
               border-radius: 8px; background: #F9FAFB; border: 1px solid #E5E7EB;
               margin-right: 12px; min-width: 90px; }}
  .stat-num  {{ font-size: 26px; font-weight: 800; line-height: 1; }}
  .stat-lbl  {{ font-size: 10px; font-weight: 600; text-transform: uppercase;
                letter-spacing: .05em; color: #6B7280; margin-top: 4px; }}
</style>
</head>
<body>

<!-- Header -->
<div style="border-bottom:2px solid #E5E7EB;padding-bottom:16px;margin-bottom:20px">
  {logo_html}{brand_line}
  <div style="display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:8px">
    <div>
      <div style="font-size:22px;font-weight:800;color:#111827;margin-bottom:2px">AI Bill of Materials</div>
      <div style="font-size:14px;color:#374151;font-weight:600">{org_display}</div>
      <div style="font-size:11px;color:#6B7280;margin-top:2px">{date_str} &nbsp;|&nbsp; {device_count} device(s) scanned</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:11px;color:#6B7280;margin-bottom:2px">Supply Chain Risks</div>
      <div style="font-size:28px;font-weight:800;color:{score_color};line-height:1">{risk_count}</div>
      <div style="font-size:10px;color:#6B7280">finding(s)</div>
    </div>
  </div>
</div>

<!-- Summary stats -->
<div style="margin-bottom:24px">
  <div class="stat-box">
    <div class="stat-num" style="color:#4F46E5">{total_components}</div>
    <div class="stat-lbl">Total Components</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" style="color:#374151">{len(models_list)}</div>
    <div class="stat-lbl">AI Models</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" style="color:#374151">{len(packages_list)}</div>
    <div class="stat-lbl">AI Packages</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" style="color:#374151">{len(tools_list)}</div>
    <div class="stat-lbl">AI Tools</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" style="color:#374151">{len(services_list)}</div>
    <div class="stat-lbl">SaaS AI</div>
  </div>
  {f'<div class="stat-box"><div class="stat-num" style="color:#DC2626">{unpinned_count}</div><div class="stat-lbl">Unpinned Pkgs</div></div>' if unpinned_count else ''}
  {f'<div class="stat-box"><div class="stat-num" style="color:#CA8A04">{floating_models}</div><div class="stat-lbl">Floating Models</div></div>' if floating_models else ''}
</div>

<!-- Models -->
<h2>&#129302; AI Models</h2>
<table>
  <thead><tr>
    <th style="{_th}">Model Name</th>
    <th style="{_th}">Version / Ref</th>
    <th style="{_th}">Provider</th>
    <th style="{_th}">Origin</th>
    <th style="{_th}">Version Pinning</th>
    <th style="{_th}">Devices</th>
  </tr></thead>
  <tbody>{models_rows()}</tbody>
</table>

<!-- AI Packages -->
<h2>&#128230; AI Packages</h2>
<table>
  <thead><tr>
    <th style="{_th}">Package</th>
    <th style="{_th}">Version Pinning</th>
    <th style="{_th}">Devices</th>
  </tr></thead>
  <tbody>{packages_rows()}</tbody>
</table>

<!-- Developer AI Tools -->
<h2>&#9881; AI Developer Tools &amp; Agents</h2>
<table>
  <thead><tr>
    <th style="{_th}">Tool / Platform</th>
    <th style="{_th}">Detected Files</th>
    <th style="{_th}">Devices</th>
  </tr></thead>
  <tbody>{tools_rows()}</tbody>
</table>

<!-- SaaS AI Services -->
<h2>&#127760; SaaS AI Services</h2>
<table>
  <thead><tr>
    <th style="{_th}">Service</th>
    <th style="{_th}">Provider</th>
    <th style="{_th}">Origin</th>
    <th style="{_th}">Detected On</th>
  </tr></thead>
  <tbody>{services_rows()}</tbody>
</table>

<!-- Supply Chain Risks -->
<h2>&#9888; Supply Chain Risks</h2>
<table>
  <thead><tr>
    <th style="{_th}">Status</th>
    <th style="{_th}">Check ID</th>
    <th style="{_th}">Finding</th>
    <th style="{_th}">Device</th>
  </tr></thead>
  <tbody>{risks_rows()}</tbody>
</table>

<!-- Footer -->
<div style="margin-top:32px;padding-top:12px;border-top:1px solid #E5E7EB;
            display:flex;justify-content:space-between;font-size:10px;color:#9CA3AF">
  {footer_left}
  <span>AI-BOM format based on CycloneDX-AI 1.6 &nbsp;|&nbsp; Arckon AI Security</span>
</div>

</body>
</html>'''
