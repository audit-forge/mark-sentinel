"""
Academy site builder for RiskRaven Arckon

Public API:
    def build(root: pathlib.Path) -> bytes

Returns a self-contained HTML page (bytes) with no external dependencies.
"""
from __future__ import annotations
import html
import pathlib
import re
from typing import Dict, List

SECTIONS = [
    ("overview", "Overview"),
    ("prereqs", "Prerequisites"),
    ("macos", "macOS"),
    ("windows", "Windows"),
    ("linux", "Linux"),
    ("docker", "Docker"),
    ("first-scan", "First Scan"),
    ("profiles", "Profiles"),
    ("severity", "Severity Levels"),
    ("status", "Finding Status"),
    ("tabs", "Dashboard Tabs"),
    ("command", "Command Center"),
    ("settings", "Settings"),
    ("alerts", "Alerts & Notifications"),
    ("protected-files", "Protected Files Monitoring"),
    ("siem-tools", "SIEM & Tool Integrations"),
    ("ai-spend", "AI Spend"),
    ("catalog", "Check Catalog"),
    ("troubleshoot", "Troubleshooting"),
]


def _escape(s: str) -> str:
    return html.escape(s, quote=False)


def _read_checks(root: pathlib.Path) -> Dict[str, List[Dict[str, str]]]:
    checks_dir = root / 'checks'
    out: Dict[str, List[Dict[str, str]]] = {}
    if not checks_dir.exists():
        return out

    md_files = sorted(checks_dir.glob('AI-*.md'))
    header_re = re.compile(r"^##\s*(AI-[A-Z]+-\d{3})\s*:\s*(.+)", re.IGNORECASE)
    severity_re = re.compile(r"\*\*Severity:\*\*\s*(\w+)", re.IGNORECASE)
    section_re = re.compile(r"^###\s*(.+)$")

    for p in md_files:
        text = p.read_text(encoding='utf-8')
        lines = text.splitlines()
        check_id = None
        title = None
        severity = ''
        sections = {}
        cur = None
        buf = []
        for ln in lines:
            if not check_id:
                m = header_re.match(ln)
                if m:
                    check_id = m.group(1).strip()
                    title = m.group(2).strip()
                    continue
            m2 = severity_re.search(ln)
            if m2:
                severity = m2.group(1).strip().upper()
            m3 = section_re.match(ln)
            if m3:
                if cur and buf:
                    sections[cur] = "\n".join(buf).strip()
                cur = m3.group(1).strip()
                buf = []
                continue
            if cur:
                buf.append(ln)
        if cur and buf:
            sections[cur] = "\n".join(buf).strip()

        if not check_id:
            # fallback: use filename
            check_id = p.stem
            title = p.stem
        # category is the middle token AI-DEPLOY-001 -> AI-DEPLOY
        cat = check_id.split('-')[1] if '-' in check_id else 'MISC'
        out.setdefault(cat, []).append({
            'id': check_id,
            'title': title or '',
            'severity': severity or 'UNKNOWN',
            'description': sections.get('Description', ''),
            'smb': sections.get('SMB Explanation', ''),
            'pass': sections.get('PASS Criteria', ''),
            'fail': sections.get('FAIL Criteria', ''),
            'remediation': sections.get('Remediation', ''),
        })
    # ensure ordered categories by requested order
    return out


def build(root: pathlib.Path) -> bytes:
    """Return full HTML bytes for the academy page."""
    root = pathlib.Path(root)
    checks = _read_checks(root)

    # build nav links (static sections + dynamic catalog group links)
    nav_items = []
    for sid, title in SECTIONS:
        nav_items.append((sid, title))
    # add category anchors for checks
    cat_order = [
        'AI-DEPLOY', 'AI-RUNTIME', 'AI-AGENT', 'AI-GOV', 'AI-INP', 'AI-OUT', 'AI-SUPPLY'
    ]
    # append categories present in checks in desired order, then any extras
    for c in cat_order:
        if c in checks:
            nav_items.append((f'cat-{c}', f'Catalog: {c}'))
    for c in sorted(checks.keys()):
        if c not in cat_order:
            nav_items.append((f'cat-{c}', f'Catalog: {c}'))

    def badge_for(sev: str) -> str:
        sev_u = (sev or '').upper()
        if 'CRIT' in sev_u:
            return '<span class="sev critical">CRITICAL</span>'
        if 'HIGH' in sev_u:
            return '<span class="sev high">HIGH</span>'
        if 'MED' in sev_u:
            return '<span class="sev medium">MEDIUM</span>'
        if 'LOW' in sev_u:
            return '<span class="sev low">LOW</span>'
        return '<span class="sev unknown">UNKNOWN</span>'

    # Sections content (static parts pulled from spec)
    def section_html(id_, title, content):
        return f'<section id="{_escape(id_)}" class="doc-section"><h2>{_escape(title)}</h2>{content}</section>'

    # Static content blocks
    overview = ("<p>RiskRaven Arckon is an AI security audit platform. It scans AI deployments for STIG/NIST/OWASP compliance. "
                "Two components: server (dashboard) and agent (installed on each device).</p>"
                "<p>Arckon now supports NIST AI RMF 1.0 and SR 26-2 (April 2026 model risk guidance) for financial sector deployments.</p>")

    prereqs = ("<ul>"
               "<li>Python 3.11 or later (required on every machine)</li>"
               "<li>Git (required on the server machine for initial install)</li>"
               "<li>GitHub access — SSH key or Personal Access Token (PAT). "
               "GitHub does not accept passwords for git operations. "
               "To create a PAT: GitHub → Settings → Developer settings → "
               "Personal access tokens → Generate new token (classic) → select <b>repo</b> scope.</li>"
               "<li>Network access between agents and the server machine</li>"
               "<li>Admin/root privileges for service installation</li>"
               "</ul>")

    macos = ("<h4>Server setup (run once)</h4>"
             "<p>Use SSH (recommended) or a Personal Access Token — GitHub does not accept passwords. "
             "To create a PAT: GitHub → Settings → Developer settings → Personal access tokens → Fine-grained → "
             "set resource owner to <b>audit-forge</b>, select <b>mark-sentinel</b> repo, set Contents to <b>Read-only</b>.</p>"
             "<pre><code># Option A — SSH (recommended)\n"
             "sudo git clone git@github.com:audit-forge/mark-sentinel.git /opt/sentinel\n\n"
             "# Option B — Personal Access Token (use credential helper; avoids token in URL)\n"
             "git config --global credential.helper store\n"
             "sudo git clone https://github.com/audit-forge/mark-sentinel.git /opt/sentinel\n"
             "# Git will prompt for username + PAT on first clone; credential.helper stores it\n\n"
             "# Check out the active branch (git clones the default branch — switch to get latest)\n"
             "cd /opt/sentinel && sudo git checkout main\n\n"
             "# Create a virtual environment (required — macOS blocks pip3 on system Python)\n"
             "python3 -m venv /opt/sentinel/venv\n"
             "/opt/sentinel/venv/bin/pip install -r /opt/sentinel/requirements.txt</code></pre>"
             "<h4>Start the server</h4>"
             "<pre><code># Create a symlink so logs appear in /var/log (run once)\n"
             "sudo ln -sf /tmp/sentinel-server.log /var/log/sentinel-server.log\n\n"
             "# Run in background (terminal stays free, survives terminal close)\n"
             "nohup /opt/sentinel/venv/bin/python /opt/sentinel/server.py --no-browser > /tmp/sentinel-server.log 2>&1 &\n\n"
             "# Dashboard:      http://localhost:7331\n"
             "# Command Center: http://localhost:7331/command\n"
             "# Academy:        http://localhost:7331/academy\n\n"
             "# View logs\n"
             "cat /var/log/sentinel-server.log\n\n"
             "# Stop the server\n"
             "pkill -f server.py</code></pre>"
             "<p><b>Note:</b> /tmp is cleared on reboot. The symlink in /var/log will dangle until the server is started again — this is harmless.</p>"
             "<h4>Agent install</h4>"
             "<p>Run on each Mac you want to monitor (server must be running first):</p>"
             "<pre><code>curl -s http://SERVER_IP:7331/bundle.tar.gz | tar -xz -C /tmp\n"
             "sudo bash /tmp/sentinel/install.sh --server http://SERVER_IP:7331 --token YOUR_TOKEN</code></pre>"
             "<h4>Service management</h4>"
             "<pre><code>sudo launchctl list | grep sentinel     # check status\n"
             "sudo launchctl stop io.riskraven.arckon-agent\n"
             "sudo launchctl start io.riskraven.arckon-agent\n"
             "# Logs: /var/log/sentinel-agent.log</code></pre>")

    windows = ("<h4>Server setup (run once — PowerShell as Administrator)</h4>"
               "<p>Use SSH (recommended) or a Personal Access Token — GitHub does not accept passwords. "
               "To create a PAT: GitHub → Settings → Developer settings → Personal access tokens → Fine-grained → "
               "set resource owner to <b>audit-forge</b>, select <b>mark-sentinel</b> repo, set Contents to <b>Read-only</b>.</p>"
               "<pre><code># Option A — SSH (recommended)\n"
               "git clone git@github.com:audit-forge/mark-sentinel.git C:\\Sentinel\n\n"
               "# Option B — Personal Access Token (use credential helper; avoids token in URL)\n"
               "git config --global credential.helper manager\n"
               "git clone https://github.com/audit-forge/mark-sentinel.git C:\\Sentinel\n"
               "# Windows Credential Manager will prompt once and store the PAT securely\n\n"
               "# Check out the active branch (git clones the default branch — switch to get latest)\n"
               "cd C:\\Sentinel; git checkout main\n\n"
               "# Create a virtual environment\n"
               "python -m venv C:\\Sentinel\\venv\n"
               "C:\\Sentinel\\venv\\Scripts\\pip install -r C:\\Sentinel\\requirements.txt</code></pre>"
               "<h4>Start the server</h4>"
               "<pre><code># Run in background (PowerShell — terminal stays free)\n"
               "Start-Process -NoNewWindow -FilePath C:\\Sentinel\\venv\\Scripts\\python `\n"
               "  -ArgumentList 'C:\\Sentinel\\server.py --no-browser' `\n"
               "  -RedirectStandardOutput C:\\Sentinel\\server.log `\n"
               "  -RedirectStandardError C:\\Sentinel\\server.log\n\n"
               "# Dashboard:      http://localhost:7331\n"
               "# Command Center: http://localhost:7331/command\n"
               "# Academy:        http://localhost:7331/academy\n\n"
               "# Stop the server\n"
               "Stop-Process -Name python</code></pre>"
               "<h4>Open the firewall (run once)</h4>"
               "<p>Windows Firewall blocks inbound connections by default. Run this once so agents and "
               "LAN browsers can reach the dashboard on port 7331:</p>"
              "<pre><code>New-NetFirewallRule -DisplayName \"Arckon Dashboard\" `\n"
              "  -Direction Inbound -Protocol TCP -LocalPort 7331 -Action Allow</code></pre>"
              "<p>Verify the rule was created: <code>Get-NetFirewallRule -DisplayName \"Arckon Dashboard\"</code></p>"
               "<h4>Agent install</h4>"
               "<p>Run in PowerShell as Administrator on each Windows machine to monitor:</p>"
               "<pre><code>Invoke-WebRequest http://SERVER_IP:7331/bundle.tar.gz -OutFile \"$env:TEMP\\sentinel.tar.gz\"\n"
               "tar -xz -f \"$env:TEMP\\sentinel.tar.gz\" -C \"$env:TEMP\"\n"
               "Set-Location \"$env:TEMP\\sentinel\"\n"
               ".\\install.ps1 -Server http://SERVER_IP:7331 -Token YOUR_TOKEN</code></pre>"
               "<h4>Service management</h4>"
               "<pre><code>Get-Service ArckonAgent           # check status\n"
               "Restart-Service ArckonAgent\n"
               "# Logs: C:\\ProgramData\\Arckon\\arckon-agent.log</code></pre>"
               "<p>For best results install NSSM first (https://nssm.cc). The installer falls back to sc.exe if NSSM is not found.</p>")

    linux = ("<h4>Server setup (run once)</h4>"
             "<p>Use SSH (recommended) or a Personal Access Token — GitHub does not accept passwords. "
             "To create a PAT: GitHub → Settings → Developer settings → Personal access tokens → Fine-grained → "
             "set resource owner to <b>audit-forge</b>, select <b>mark-sentinel</b> repo, set Contents to <b>Read-only</b>.</p>"
             "<pre><code># Option A — SSH (recommended)\n"
             "sudo git clone git@github.com:audit-forge/mark-sentinel.git /opt/sentinel\n\n"
             "# Option B — Personal Access Token (use credential helper; avoids token in URL)\n"
             "git config --global credential.helper store\n"
             "sudo git clone https://github.com/audit-forge/mark-sentinel.git /opt/sentinel\n"
             "# Git will prompt for username + PAT on first clone; credential.helper stores it\n\n"
             "# Check out the active branch (git clones the default branch — switch to get latest)\n"
             "cd /opt/sentinel && sudo git checkout main\n\n"
             "# Create a virtual environment (required on systems with externally-managed Python)\n"
             "python3 -m venv /opt/sentinel/venv\n"
             "/opt/sentinel/venv/bin/pip install -r /opt/sentinel/requirements.txt</code></pre>"
             "<h4>Start the server</h4>"
             "<pre><code># Create a symlink so logs appear in /var/log (run once)\n"
             "sudo ln -sf /tmp/sentinel-server.log /var/log/sentinel-server.log\n\n"
             "# Run in background (terminal stays free, survives terminal close)\n"
             "nohup /opt/sentinel/venv/bin/python /opt/sentinel/server.py --no-browser > /tmp/sentinel-server.log 2>&1 &\n\n"
             "# Dashboard:      http://localhost:7331\n"
             "# Command Center: http://localhost:7331/command\n"
             "# Academy:        http://localhost:7331/academy\n\n"
             "# View logs\n"
             "cat /var/log/sentinel-server.log\n\n"
             "# Stop the server\n"
             "pkill -f server.py</code></pre>"
             "<h4>Agent install</h4>"
             "<p>Run on each Linux machine to monitor (server must be running first):</p>"
             "<pre><code>curl -s http://SERVER_IP:7331/bundle.tar.gz | tar -xz -C /tmp\n"
             "sudo bash /tmp/sentinel/install.sh --server http://SERVER_IP:7331 --token YOUR_TOKEN\n"
             "# Installs to: /opt/sentinel/ | Config: /etc/arckon/agent_config.json</code></pre>"
             "<h4>Service management</h4>"
             "<pre><code>sudo systemctl status sentinel-agent\n"
             "sudo systemctl restart sentinel-agent\n"
             "sudo journalctl -u sentinel-agent -f    # live logs</code></pre>")

    docker = (
        "<p>Use Docker to run the Arckon agent (or server) in an isolated container — "
        "no Python install required on the host.</p>"
        "<h4>Prerequisites</h4>"
        "<ul>"
        "<li>Docker Engine 20.10+ (or Docker Desktop)</li>"
        "<li>The Sentinel source repo cloned on the build machine</li>"
        "</ul>"
        "<h4>Create Dockerfile.agent</h4>"
        "<p>Create this file in the project root (next to the existing <code>Dockerfile</code>):</p>"
        "<pre><code>FROM python:3.12-slim\n\n"
        "WORKDIR /app\n"
        "ENV PYTHONUNBUFFERED=1\n\n"
        "RUN groupadd -r sentinel &amp;&amp; useradd -r -g sentinel -m sentinel\n\n"
        "COPY requirements.txt ./\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n\n"
        "COPY . .\n"
        "RUN chown -R sentinel:sentinel /app\n\n"
        "USER sentinel\n\n"
        "CMD [\"python\", \"agent.py\", \"--daemon\"]</code></pre>"
        "<h4>Build and run the agent</h4>"
        "<pre><code># Build\n"
        "docker build -f Dockerfile.agent -t sentinel-agent .\n\n"
        "# Run — pass server URL and token via environment variables\n"
        "docker run -d \\\n"
        "  --name sentinel-agent \\\n"
        "  --hostname my-container-name \\\n"
        "  --restart unless-stopped \\\n"
        "  -e SENTINEL_SERVER=http://SERVER_IP:7331 \\\n"
        "  -e SENTINEL_AGENT_TOKEN=your-token-here \\\n"
        "  sentinel-agent\n\n"
        "# View logs\n"
        "docker logs -f sentinel-agent\n\n"
        "# Stop\n"
        "docker stop sentinel-agent</code></pre>"
        "<p><b>Note:</b> The container hostname becomes the device name in the Command Center. "
        "Set <code>--hostname</code> to something meaningful. "
        "The agent scans the container filesystem; mount host paths with <code>-v</code> if you need host scanning.</p>"
        "<h4>Docker Compose (server + agent on the same host)</h4>"
        "<pre><code>services:\n"
        "  server:\n"
        "    build: .\n"
        "    ports:\n"
        "      - \"7331:7331\"\n"
        "    volumes:\n"
        "      - sentinel-data:/app/output\n\n"
        "  agent:\n"
        "    build:\n"
        "      context: .\n"
        "      dockerfile: Dockerfile.agent\n"
        "    environment:\n"
        "      SENTINEL_SERVER: http://server:7331\n"
        "      SENTINEL_AGENT_TOKEN: ${SENTINEL_AGENT_TOKEN}\n"
        "    depends_on:\n"
        "      - server\n\n"
        "volumes:\n"
        "  sentinel-data:</code></pre>"
        "<pre><code># Start both\n"
        "SENTINEL_AGENT_TOKEN=your-token docker compose up -d\n\n"
        "# Dashboard: http://localhost:7331\n"
        "# Command Center: http://localhost:7331/command</code></pre>"
        "<h4>Environment variables</h4>"
        "<ul>"
        "<li><b>SENTINEL_SERVER</b> — URL of the Arckon server (required)</li>"
        "<li><b>SENTINEL_AGENT_TOKEN</b> — auth token (must match server's <code>agent_token.txt</code>)</li>"
        "</ul>"
    )

    first_scan = ("<ol>"
                  "<li>Open http://localhost:7331 in your browser</li>"
                  "<li>Click \"Run Scan\" — demo scan runs in ~10 seconds</li>"
                  "<li>View findings by severity in the dashboard</li>"
                  "<li>Click any finding to expand remediation steps</li>"
                  "<li>For fleet: open the Command Center from the top nav link</li>"
                  "</ol>")

    profiles = (
        "<p>Arckon ships with several built-in profiles to tailor checks for different environments.</p>"
        "<table class=\"sev-table\">"
        "<tr><th>default</th><td>General-purpose AI security checks. Good starting point for any organization.</td></tr>"
        "<tr><th>fedramp</th><td>Controls mapped to NIST 800-53 for U.S. federal cloud deployments.</td></tr>"
        "<tr><th>cmmc</th><td>Controlled environment mapping for DoD supply chain (CMMC Level 2).</td></tr>"
        "<tr><th>financial</th><td>Full suite mapped to NIST AI RMF 1.0, SR 11-7, and SR 26-2. For banks and financial institutions.</td></tr>"
        "<tr><th>smb</th><td>Lightweight checks in plain language for small/medium businesses with no compliance team.</td></tr>"
        "</table>"

        "<h3>Scan All and Profile Checkboxes</h3>"
        "<p>The profile checkboxes on the Command Center toolbar drive two things at once: "
        "which devices appear in the executive report <i>and</i> which profile the <b>Scan All</b> button uses.</p>"
        "<table class=\"sev-table\">"
        "<tr><th>No boxes checked</th><td>Scan All sends <code>scan_now</code> — each agent uses whatever profile "
        "it was configured with (its saved default). Most devices will scan with the default profile.</td></tr>"
        "<tr><th>One box checked (e.g. FedRAMP)</th><td>Scan All sends <code>scan_profile:fedramp</code> to every "
        "device. All devices run a FedRAMP scan regardless of their saved default.</td></tr>"
        "<tr><th>Multiple boxes checked</th><td>Each device gets one scan command per checked profile. A device "
        "receiving FedRAMP + CMMC will run two scans back-to-back as the agent polls (every 5 minutes). "
        "Both results appear under their respective profiles in the exec report.</td></tr>"
        "</table>"
        "<p><b>Stagger options</b> prevent all agents from hitting the network simultaneously:</p>"
        "<table class=\"sev-table\">"
        "<tr><th>Normal (25 / 30s)</th><td>Dispatch 25 devices, wait 30 seconds, repeat. Default for most fleets.</td></tr>"
        "<tr><th>Slow (10 / 60s)</th><td>10 devices per minute. Use for large fleets on shared or constrained networks.</td></tr>"
        "<tr><th>Instant</th><td>All devices queued at once. Only use for small fleets or lab environments.</td></tr>"
        "</table>"

        "<h3>Changing an Agent's Default Profile</h3>"
        "<p>Each agent has a saved default profile in its config file. This is the profile used when "
        "<b>no override is sent</b> (i.e., when Scan All has no boxes checked, or when the agent runs its "
        "automatic scheduled scan). To change it permanently, edit the config file on the device and restart the agent.</p>"

        "<h4>Linux</h4>"
        "<pre><code>sudo nano /etc/arckon/agent_config.json</code></pre>"

        "<h4>macOS</h4>"
        "<pre><code>sudo nano /opt/arckon/agent_config.json</code></pre>"

        "<h4>Windows (PowerShell as Administrator)</h4>"
        "<pre><code>notepad C:\\ProgramData\\Arckon\\agent_config.json</code></pre>"

        "<p>The file looks like this — change the <code>\"profile\"</code> value to one of the slugs in the table above:</p>"
        "<pre><code>{\n"
        "  \"server\": \"http://SERVER_IP:7331\",\n"
        "  \"token\": \"YOUR_TOKEN\",\n"
        "  \"target\": \"/\",\n"
        "  \"profile\": \"fedramp\",\n"
        "  \"interval\": 7200\n"
        "}</code></pre>"

        "<p>Valid values for <code>\"profile\"</code>: "
        "<code>default</code>, <code>fedramp</code>, <code>cmmc</code>, <code>financial</code>, <code>smb</code></p>"

        "<p>After saving, restart the agent:</p>"
        "<pre><code># Linux\n"
        "sudo systemctl restart sentinel-agent\n\n"
        "# macOS\n"
        "sudo launchctl stop io.riskraven.arckon-agent &amp;&amp; sudo launchctl start io.riskraven.arckon-agent\n\n"
        "# Windows (PowerShell as Administrator)\n"
        "Restart-Service ArckonAgent</code></pre>"

        "<p><b>Tip:</b> You can also push a profile change to individual devices without editing files — "
        "use the <b>Scan ▾</b> dropdown on a device row in the Command Center and select a profile. "
        "That queues a one-time override scan. To make a profile permanent, edit the config file as above.</p>"
    )

    severity = ("<table class=\"sev-table\">"
                "<tr><th>CRITICAL</th><td>system is actively exposed; fix immediately</td></tr>"
                "<tr><th>HIGH</th><td>significant risk; fix within 24 hours</td></tr>"
                "<tr><th>MEDIUM</th><td>moderate risk; fix within 7 days</td></tr>"
                "<tr><th>LOW</th><td>best practice; fix in next sprint</td></tr>"
                "</table>")

    status = ("<ul>"
              "<li><b>FAIL</b> — check did not pass; remediation required</li>"
              "<li><b>WARN</b> — partial compliance or configuration gap</li>"
              "<li><b>PASS</b> — check passed</li>"
              "<li><b>SKIP</b> — check not applicable to this environment</li>"
              "</ul>")

    tabs = ("<ul>"
            "<li><b>Findings</b> — all checks grouped by severity</li>"
            "<li><b>Remediation</b> — only failed/warned checks with fix steps</li>"
            "<li><b>Heatmap</b> — visual risk matrix by category</li>"
            "<li><b>Timeline</b> — historical scan trend (fleet mode)</li>"
            "</ul>")

    command_center = ("<p>The Command Center shows all connected devices in one view.</p>"
                      "<ul>"
                      "<li>Devices appear automatically within 5 minutes of agent install</li>"
                      "<li>Click any device row to load its full dashboard inline</li>"
                      "<li>\"Scan Now\" button queues an immediate scan on that device</li>"
                      "<li>\"Full Report\" opens the device dashboard in a new tab</li>"
                      "<li>Network Discovery scans the local subnet for AI services</li>"
                      "<li>Device list auto-refreshes every 60 seconds without a page reload</li>"
                      "</ul>"
                      "<h4>Command examples</h4>"
                      "<pre><code># Generate a PDF report for compliance handoff\n"
                      "python3 audit.py --mode config --profile financial --output pdf --out-file pnc_audit\n\n"
                      "# Scan a large enterprise repository (increase file limit)\n"
                      "python3 audit.py --mode config --profile financial --max-files 5000 --output plain\n\n"
                      "# Compare two previous scans (before/after remediation)\n"
                      "python3 audit.py --compare before.json after.json\n\n"
                      "# Run financial profile (NIST AI RMF + SR 26-2)\n"
                      "python3 audit.py --mode config --profile financial --output plain\n"
                      "</code></pre>")

    settings = (
        "<p>The <b>Settings</b> panel is at the bottom of the Command Center sidebar. "
        "Everything that needs a human decision after install is exposed here so you do not need a terminal.</p>"

        "<h3>Configuration</h3>"
        "<h4>1. Default Device Scan</h4>"
        "<ol>"
        "<li>Open the Command Center and click <b>Settings</b> in the sidebar.</li>"
        "<li>Find the <b>Default Device Scan</b> dropdown under Configuration.</li>"
        "<li>Choose the compliance profile that matches your environment (e.g., <b>Base Scan</b>, "
        "<b>Financial Services</b>, <b>FedRAMP / NIST 800-53</b>, <b>CMMC 2.0</b>, etc.).</li>"
        "<li>Click <b>Save</b>. The change applies to new agents, scheduled scans, and Scan All.</li>"
        "</ol>"

        "<h4>2. Scan Interval</h4>"
        "<ol>"
        "<li>In the same Configuration section, locate <b>Scan Interval</b>.</li>"
        "<li>Enter a value in seconds. Common values:</li>"
        "</ol>"
        "<table class=\"sev-table\">"
        "<tr><th>3600</th><td>Hourly — use during active remediation.</td></tr>"
        "<tr><th>86400</th><td>Daily — good default for ongoing monitoring.</td></tr>"
        "<tr><th>604800</th><td>Weekly — low-overhead monitoring for stable environments.</td></tr>"
        "</table>"
        "<p>Click <b>Save</b>. The new interval takes effect on the agent's next check-in.</p>"

        "<h4>3. Extra Subnets</h4>"
        "<ol>"
        "<li>Find the <b>Extra Subnets</b> field under Configuration.</li>"
        "<li>Enter additional CIDR ranges for Shadow AI discovery, separated by commas:<br>"
        "<code>192.168.50.0/24, 10.0.2.0/24</code></li>"
        "<li>Click <b>Save</b>. These ranges are included the next time you run Find Shadow AI.</li>"
        "</ol>"

        "<h3>Report Branding</h3>"
        "<ol>"
        "<li>In Settings, scroll to <b>Report Branding</b>.</li>"
        "<li>Enter your <b>Company Name</b> as you want it to appear on the EU AI Act Readiness Report.</li>"
        "<li>Enter a public <b>Logo URL</b> (PNG or SVG, ideally 160×40 px).</li>"
        "<li>Enter a <b>Report Footer</b> line such as <code>Prepared by Acme MSP · acme.com</code>.</li>"
        "<li>Click <b>Save Branding</b>.</li>"
        "<li>Click <b>Preview Report</b> to verify the branding before sharing with clients.</li>"
        "</ol>"

        "<h3>Alert Notifications</h3>"
        "<p>Arckon can notify your team when new CRITICAL findings, HIGH findings, or Shadow AI assets are detected. "
        "The dashboard writes the configuration to <code>data/alerts_config.json</code> automatically.</p>"

        "<h4>Slack alerts</h4>"
        "<ol>"
        "<li>In Slack, open your workspace and go to <b>Apps → Incoming Webhooks</b> (or visit <code>https://api.slack.com/apps</code>).</li>"
        "<li>Create an incoming webhook and copy the URL (looks like <code>https://hooks.slack.com/services/T.../B.../...</code>).</li>"
        "<li>In Arckon Settings → Alert Notifications, paste the URL into <b>Slack Webhook</b>.</li>"
        "<li>Click <b>Test</b> to confirm the message arrives in Slack.</li>"
        "<li>Click <b>Save Alert Settings</b>.</li>"
        "</ol>"

        "<h4>Microsoft Teams alerts</h4>"
        "<ol>"
        "<li>In Teams, open the target channel, click the <b>⋯</b> menu, and choose <b>Connectors</b>.</li>"
        "<li>Select <b>Incoming Webhook</b>, give it a name, and copy the URL.</li>"
        "<li>In Arckon Settings, paste the URL into <b>Teams Webhook</b>, then <b>Test</b> and <b>Save</b>.</li>"
        "</ol>"

        "<h4>Google Chat alerts</h4>"
        "<ol>"
        "<li>Open the Google Chat space, click the space name, then <b>Apps & integrations → Webhooks</b>.</li>"
        "<li>Click <b>Add webhook</b>, name it, and copy the URL.</li>"
        "<li>In Arckon Settings, paste the URL into <b>Google Chat Webhook</b>, then <b>Test</b> and <b>Save</b>.</li>"
        "</ol>"

        "<h4>Generic webhook alerts</h4>"
        "<ol>"
        "<li>Enter any HTTPS endpoint that accepts POST requests in the <b>Webhook URL</b> field.</li>"
        "<li>Click <b>Test</b> to send a sample payload.</li>"
        "<li>Click <b>Save Alert Settings</b>.</li>"
        "</ol>"

        "<h4>Email (SMTP) alerts</h4>"
        "<ol>"
        "<li>Enter your SMTP host (e.g., <code>smtp.gmail.com</code>) and port (usually <code>587</code>).</li>"
        "<li>Enter the SMTP username and password. For Gmail you must create an <b>App Password</b> at "
        "<code>myaccount.google.com/apppasswords</code> (Gmail account passwords do not work with SMTP).</li>"
        "<li>Enter the <b>From Address</b> and <b>Send Alerts To</b> address.</li>"
        "<li>Click <b>Test</b> to send a test email, then <b>Save Alert Settings</b>.</li>"
        "</ol>"

        "<h4>Trigger Events</h4>"
        "<ol>"
        "<li>Under <b>Alert when</b>, check the events you want notifications for:</li>"
        "</ol>"
        "<ul>"
        "<li><b>New CRITICAL finding</b> — fires whenever any device reports a CRITICAL result.</li>"
        "<li><b>New HIGH finding</b> — fires whenever any device reports a HIGH result.</li>"
        "<li><b>New Shadow AI asset</b> — fires when network discovery finds a new unmanaged AI service.</li>"
        "<li><b>Only alert on unapproved services</b> — suppresses Shadow AI alerts for assets you have already marked approved.</li>"
        "</ul>"
        "<p>Click <b>Save Alert Settings</b> after changing any trigger.</p>"

        "<h3>Desktop Shortcut</h3>"
        "<ol>"
        "<li>In Settings, click the <b>Desktop Shortcut</b> button in the top-right.</li>"
        "<li>Save the downloaded file to your desktop.</li>"
        "<li>Double-click it anytime to open the Command Center. Windows creates a <code>.url</code> file; "
        "macOS creates a <code>.webloc</code> file.</li>"
        "</ol>"
        "<p>The Windows installer creates this shortcut automatically during setup.</p>"

        "<h3>What Settings does NOT do</h3>"
        "<ul>"
        "<li>Server URL and authentication token — set at install time.</li>"
        "<li>Scan target directory — set at install time.</li>"
        "</ul>"
        "<p>If those need to change, re-run the installer or use the <b>Update</b> button on a device row.</p>"
    )

    alerts = (
        "<p>The recommended way to configure alerts is through the <b>Settings → Alert Notifications</b> panel. "
        "The dashboard saves your choices to <code>data/alerts_config.json</code> automatically.</p>"
        "<p>If you prefer to edit the file manually, it lives next to the server code and uses this schema:</p>"
        "<pre><code>{\n"
        "  \"slack_webhook\": \"https://hooks.slack.com/services/...\",\n"
        "  \"teams_webhook\": \"https://yourorg.webhook.office.com/...\",\n"
        "  \"gchat_webhook\": \"https://chat.googleapis.com/v1/spaces/...\",\n"
        "  \"webhook_url\": \"https://your-endpoint.com/alerts\",\n"
        "  \"email\": {\n"
        "    \"smtp_host\": \"smtp.gmail.com\",\n"
        "    \"smtp_port\": 587,\n"
        "    \"smtp_user\": \"you@gmail.com\",\n"
        "    \"smtp_pass\": \"app-password\",\n"
        "    \"from\": \"sentinel@yourdomain.com\",\n"
        "    \"to\": \"security-team@yourdomain.com\"\n"
        "  },\n"
        "  \"triggers\": {\n"
        "    \"new_critical\": true,\n"
        "    \"new_high\": true,\n"
        "    \"new_shadow_ai\": true,\n"
        "    \"alert_unapproved_only\": false\n"
        "  }\n"
        "}</code></pre>"
        "<p><b>Gmail users:</b> use an App Password from <code>myaccount.google.com/apppasswords</code>, not your normal password.</p>"
    )

    protected_files = (
        "<p><b>Protected Files Monitoring</b> detects when an AI tool (Claude, Cursor, Copilot, "
        "Ollama, Aider, etc.) accesses a file or directory you've designated as protected. "
        "It also monitors server access (SSH/RDP logins) correlated with AI processes. "
        "When an AI process touches a protected resource, an alert fires through your configured "
        "channels (Slack, Teams, email, webhook, PSA, etc.) and the event appears in the "
        "<b>Protected Files</b> dashboard tab.</p>"

        "<p>This feature is built to <b>FedRAMP</b> security controls including "
        "SC-13 (encryption at rest), AU-2 (tamper-evident audit log), SI-4 (system monitoring), "
        "AC-3 (access enforcement), and CM-6 (configuration management).</p>"

        "<h3>How It Works</h3>"
        "<ol>"
        "<li>You designate protected paths (files or directories) in the dashboard.</li>"
        "<li>The server pushes the protected-paths policy to each agent via the existing "
        "command poll (signed, authenticated).</li>"
        "<li>The agent starts a platform-specific collector that monitors file access at the "
        "OS level (see below).</li>"
        "<li>When an AI process accesses a protected path, the collector emits an event.</li>"
        "<li>The agent reports the event to the server, which stores it in a tamper-evident "
        "hash chain and fires an alert.</li>"
        "</ol>"

        "<h3>Platform Collectors</h3>"
        "<table style='width:100%;border-collapse:collapse;font-size:13px'>"
        "<tr style='background:#f3f4f6'>"
        "<th style='padding:8px;text-align:left;border:1px solid #e5e7eb'>Platform</th>"
        "<th style='padding:8px;text-align:left;border:1px solid #e5e7eb'>Mechanism</th>"
        "<th style='padding:8px;text-align:left;border:1px solid #e5e7eb'>Requirement</th>"
        "</tr>"
        "<tr><td style='padding:8px;border:1px solid #e5e7eb'><b>macOS</b></td>"
        "<td style='padding:8px;border:1px solid #e5e7eb'>Endpoint Security framework (kernel-level, signed Swift helper)</td>"
        "<td style='padding:8px;border:1px solid #e5e7eb'>ArckonESCollector.app installed + Full Disk Access + root LaunchDaemon</td></tr>"
        "<tr><td style='padding:8px;border:1px solid #e5e7eb'><b>Linux</b></td>"
        "<td style='padding:8px;border:1px solid #e5e7eb'>auditd rules + ausearch parsing + /var/log/auth.log</td>"
        "<td style='padding:8px;border:1px solid #e5e7eb'>auditd installed, agent running as root</td></tr>"
        "<tr><td style='padding:8px;border:1px solid #e5e7eb'><b>Windows</b></td>"
        "<td style='padding:8px;border:1px solid #e5e7eb'>Event Log (4663 file access, 4624 login) + auditpol</td>"
        "<td style='padding:8px;border:1px solid #e5e7eb'>Agent running with admin privileges</td></tr>"
        "</table>"

        "<h3>Setting Up Protected Files (Step by Step)</h3>"
        "<ol>"
        "<li>In the Arckon dashboard, click <b>Protected Files</b> in the left sidebar (Security section).</li>"
        "<li>Click the <b>+ Add Path</b> button.</li>"
        "<li>Enter the absolute path of the file or directory to protect "
        "(e.g. <code>/etc/secrets</code>, <code>/Users/keith/.ssh</code>, <code>C:\\\\Company\\\\Payroll</code>).</li>"
        "<li>Select which <b>device</b> the path applies to, or choose <b>All devices</b> for a global policy.</li>"
        "<li>Choose which <b>actions</b> to monitor: Read+Write+Open (default), Read only, Write only, or All.</li>"
        "<li>Check <b>Recursive</b> if you want to monitor all files under a directory (default: on).</li>"
        "<li>Click <b>Add</b>. The policy is pushed to the agent on the next command poll (within 15 seconds).</li>"
        "</ol>"

        "<h3>Reviewing Access Events</h3>"
        "<p>The <b>Access Events</b> panel shows every time an AI process accessed a protected resource:</p>"
        "<ul>"
        "<li><b>Process</b> — the AI tool that triggered the event (e.g. <code>claude</code>, <code>cursor</code>)</li>"
        "<li><b>Action</b> — read, write, open, rename, unlink, or login</li>"
        "<li><b>Path</b> — the protected file that was accessed</li>"
        "<li><b>Device</b> — which endpoint the access occurred on</li>"
        "<li><b>Source</b> — which collector detected it (esf, auditd, etw)</li>"
        "<li><b>Timestamp</b> — when the access occurred</li>"
        "</ul>"
        "<p>Click <b>Review</b> on any event to mark it as reviewed. Use <b>Mark all reviewed</b> "
        "to clear the unreviewed badge.</p>"

        "<h3>Chain Integrity Verification</h3>"
        "<p>All access events are stored in a <b>SHA-256 hash chain</b> — each event's hash includes "
        "the previous event's hash. This makes retroactive tampering detectable: if any event is "
        "modified, the chain breaks for all subsequent events. The <b>Chain Integrity</b> indicator "
        "on the dashboard shows whether the chain is intact (✓) or broken (⚠).</p>"

        "<h3>Policy Change Audit Log</h3>"
        "<p>Every change to the protected-paths policy (add, update, remove) is recorded in the "
        "<b>Policy Change Audit Log</b> with the user who made the change, the timestamp, and the "
        "action taken. This satisfies FedRAMP CM-6 (configuration management) requirements.</p>"

        "<h3>Alert Configuration</h3>"
        "<p>Protected file access alerts use the same alert channels as other Arckon alerts. "
        "To enable or configure notifications:</p>"
        "<ol>"
        "<li>Go to <b>Settings</b> → <b>Alerts &amp; Notifications</b>.</li>"
        "<li>Configure your channels (Slack, Teams, Google Chat, webhook, email, PSA, Notion).</li>"
        "<li>The <b>AI accessed protected file</b> trigger is enabled by default.</li>"
        "<li>Alerts are deduplicated per (device, path, process) with a 24-hour cooldown — "
        "repeated access by the same AI tool to the same file only alerts once per day.</li>"
        "</ol>"

        "<h3>Security &amp; Privacy</h3>"
        "<ul>"
        "<li><b>No file contents are ever stored</b> — only the path, process name, PID, and action.</li>"
        "<li><b>Protected-path policy is encrypted at rest</b> with AES-256-GCM.</li>"
        "<li><b>Access events form a tamper-evident hash chain</b> (SHA-256).</li>"
        "<li><b>All communication is over HTTPS</b> with agent-bearer token authentication.</li>"
        "<li><b>Collectors read audit events only</b> — no write or modify capability (least privilege).</li>"
        "<li><b>Rate limited</b> — max 100 events per batch, max 1 batch per 30 seconds per agent.</li>"
        "</ul>"

        "<h3>macOS: Installing the ES Collector</h3>"
        "<p>The macOS collector requires a signed, notarized helper binary "
        "(<code>ArckonESCollector.app</code>) that uses Apple's Endpoint Security framework. "
        "This binary is built with your Developer ID and the "
        "<code>com.apple.developer.endpoint-security.client</code> entitlement.</p>"

        "<h4>Option A: MDM Deployment (Recommended for fleets — no user interaction)</h4>"
        "<p>For Macs managed by Jamf, Kandji, Intune, Mosyle, or Apple Business Manager, "
        "the ES helper and Full Disk Access are installed silently via MDM:</p>"
        "<ol>"
        "<li>Upload the <b>PPPC profile</b> (<code>arckon-es-collector.pppc.mobileconfig</code>) "
        "as a Custom/Configuration Profile in your MDM — this pre-grants Full Disk Access</li>"
        "<li>Deploy the <b>.pkg installer</b> (<code>Arckon-ES-Collector-1.0.34.pkg</code>) "
        "via your MDM's package deployment — this installs the helper + LaunchDaemon</li>"
        "<li>Deploy the <b>Arckon agent</b> via MDM or the standard install command</li>"
        "<li>No user interaction required — monitoring starts automatically</li>"
        "</ol>"
        "<p>See the full MDM deployment guide with exact steps for each MDM vendor in "
        "<code>docs/PROTECTED_FILES_MDM.md</code>.</p>"

        "<h4>Option B: Manual Install (Standalone Macs)</h4>"
        "<ol>"
        "<li>Install the .pkg: <code>sudo installer -pkg Arckon-ES-Collector-1.0.34.pkg -target /</code></li>"
        "<li>Open <b>System Settings → Privacy &amp; Security → Full Disk Access</b></li>"
        "<li>Click <b>+</b> and add <code>arckon-es-collector</code> from "
        "<code>/Library/Arckon/ArckonESCollector.app</code></li>"
        "<li>Install the Arckon agent</li>"
        "</ol>"
        "<p>If the ES collector is not installed, the agent continues to work normally — "
        "protected-files monitoring is simply not active on that Mac until it's installed.</p>"

        "<h3>FedRAMP Control Mapping</h3>"
        "<table style='width:100%;border-collapse:collapse;font-size:12px'>"
        "<tr style='background:#f3f4f6'>"
        "<th style='padding:6px;text-align:left;border:1px solid #e5e7eb'>Control</th>"
        "<th style='padding:6px;text-align:left;border:1px solid #e5e7eb'>Implementation</th>"
        "</tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>AC-3</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>Session auth for policy management, agent-bearer auth for event ingestion</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>AC-6</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>Collectors read audit events only — no write/modify capability</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>AU-2</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>SHA-256 hash chain for all access events — tamper-evident</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>AU-6</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>Dashboard review UI for access events; chain integrity verification</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>AU-12</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>Collectors generate events on every protected-path access by AI process</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>SC-8</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>All agent↔server communication over HTTPS (TLS)</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>SC-13</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>AES-256-GCM encryption at rest for protected-path policy</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>SI-4</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>Continuous monitoring for AI process access to protected files</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>CM-2</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>Protected-path policy is versioned; changes audit-logged</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>CM-6</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>Policy stored server-side; all changes recorded in audit log</td></tr>"
        "<tr><td style='padding:6px;border:1px solid #e5e7eb'><b>MP-3</b></td>"
        "<td style='padding:6px;border:1px solid #e5e7eb'>No file contents stored — only path, process, action metadata</td></tr>"
        "</table>"
    )

    siem_tools = (
        "<p>The <b>SIEM &amp; Tool Integrations</b> tab connects Arckon to your security stack. "
        "Each integration has its own card. Enable it, fill in the required fields, click <b>Test</b>, then click <b>Save</b>. "
        "Findings are forwarded automatically when a scan completes.</p>"

        "<h3>PSA &amp; Ticketing</h3>"
        "<p>Auto-create tickets when CRITICAL or HIGH findings are detected. Only one PSA can be active at a time. "
        "MSP admins can also choose a <b>Client Org</b> to override settings per client.</p>"

        "<h4>ConnectWise Manage</h4>"
        "<ol>"
        "<li>Open the <b>SIEM &amp; Tool Integrations</b> tab and find the ConnectWise card.</li>"
        "<li>Toggle <b>Enabled</b> on.</li>"
        "<li>Enter your ConnectWise site (e.g., <code>na.myconnectwise.net</code>), <b>Company ID</b>, <b>Public Key</b>, <b>Private Key</b>, and <b>Client ID</b>.</li>"
        "<li>Enter the <b>Service Board</b> name (must exist in ConnectWise) and the <b>Company Name</b> for the target client.</li>"
        "<li>Click <b>Test</b> to verify credentials.</li>"
        "<li>Click <b>Save</b>.</li>"
        "</ol>"

        "<h4>Autotask PSA</h4>"
        "<ol>"
        "<li>Toggle the Autotask card to Enabled.</li>"
        "<li>Enter your zone (usually <code>webservices2</code>), API <b>Username</b>, <b>API Key</b>, and <b>Account ID</b>.</li>"
        "<li>Set the <b>Queue ID</b> and <b>Priority ID</b> for new tickets.</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"

        "<h4>HaloPSA</h4>"
        "<ol>"
        "<li>Toggle the HaloPSA card to Enabled.</li>"
        "<li>Enter your <b>Tenant</b> name, <b>Client ID</b>, and <b>Client Secret</b>.</li>"
        "<li>Set the <b>Ticket Type ID</b> and <b>Priority ID</b>.</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"

        "<h4>Jira (optional PSA connector)</h4>"
        "<ol>"
        "<li>Choose Jira as the PSA provider.</li>"
        "<li>Enter the Jira base URL, project key, issue type, and an API token.</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"

        "<h3>Wiki &amp; Docs</h3>"
        "<p>Create a documentation page for every CRITICAL or HIGH finding. The only wiki connector currently shipped is Notion.</p>"

        "<h4>Notion</h4>"
        "<ol>"
        "<li>Go to <a href=\"https://www.notion.so/my-integrations\" target=\"_blank\">notion.so/my-integrations</a> and create a new integration.</li>"
        "<li>Copy the <b>Internal Integration Secret</b> (starts with <code>secret_</code>).</li>"
        "<li>In Arckon, paste it into the Notion <b>Token</b> field.</li>"
        "<li>Choose whether pages are created under a <b>Page</b> or a <b>Database</b>, then paste the corresponding Page ID or Database ID.</li>"
        "<li>For databases, enter the title column name (usually <code>Name</code>).</li>"
        "<li>Share the target page/database with your integration (⋮⋮⋮ menu → Connections → your integration).</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"

        "<h3>SIEM &amp; Log Management</h3>"
        "<p>Forward findings to a SIEM in real time. Configuration is stored in <code>siem_config.json</code>.</p>"

        "<h4>Splunk (HTTP Event Collector)</h4>"
        "<ol>"
        "<li>In Splunk, enable the HTTP Event Collector and create a new token.</li>"
        "<li>Copy the HEC URL (e.g., <code>https://splunk.example.com:8088</code>) and token.</li>"
        "<li>In Arckon, open the Splunk card, enable it, and paste the URL and token.</li>"
        "<li>Enter the target index (default <code>arckon</code>) and sourcetype (default <code>arckon:finding</code>).</li>"
        "<li>Choose which severities to send (default: <code>critical</code>, <code>high</code>).</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"

        "<h4>Microsoft Sentinel</h4>"
        "<ol>"
        "<li>Open your Log Analytics workspace in Azure and copy the <b>Workspace ID</b>.</li>"
        "<li>Generate or copy the <b>Primary Key</b> (shared key).</li>"
        "<li>In Arckon, open the Sentinel card, enable it, and paste both values.</li>"
        "<li>Set the <b>Log Type</b> (default <code>ArckonFindings</code>).</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"

        "<h4>Elastic Security</h4>"
        "<ol>"
        "<li>Get your Elasticsearch endpoint (e.g., <code>https://elasticsearch.example.com:9200</code>) and an API key.</li>"
        "<li>In Arckon, open the Elastic card, enable it, and paste both values.</li>"
        "<li>Enter the target index (default <code>arckon-findings</code>).</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"

        "<h4>IBM QRadar / Exabeam (syslog)</h4>"
        "<ol>"
        "<li>Enter the syslog host IP or hostname and port.</li>"
        "<li>Select the protocol: <code>tcp</code> for QRadar, <code>udp</code> for Exabeam.</li>"
        "<li>Choose which severities to send.</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"

        "<h4>Kaseya VSA / BMS / IT Glue</h4>"
        "<ol>"
        "<li>Enter your Kaseya VSA URL and API key to create tickets in VSA.</li>"
        "<li>Optionally enter BMS URL/API key and IT Glue API key + organization ID to sync documentation.</li>"
        "<li>Set the <b>Ticket Queue</b> name.</li>"
        "<li>Click <b>Test</b>, then <b>Save</b>.</li>"
        "</ol>"
    )

    ai_spend = (
        "<p>The <b>AI Spend</b> tab shows token usage and estimated cost across OpenAI, Anthropic, and Google Gemini. "
        "Add read-only provider API keys, then click <b>Fetch Latest</b> to pull usage data into the dashboard.</p>"

        "<h3>Before you start</h3>"
        "<ul>"
        "<li>Provider admin keys are required. Project keys and normal Claude API keys cannot read organization spend.</li>"
        "<li>Arckon stores only the last four characters of each key. The full key is encrypted at rest.</li>"
        "<li>Fetch is rate-limited to once per day per provider unless you use <b>force</b>.</li>"
        "</ul>"

        "<h3>Add an OpenAI spend key</h3>"
        "<ol>"
        "<li>Sign in at <a href=\"https://platform.openai.com/\" target=\"_blank\">platform.openai.com</a>.</li>"
        "<li>Go to <b>Organization Settings → Admin keys</b>.</li>"
        "<li>Create a <b>Read only</b> admin key (starts with <code>sk-admin-...</code>).</li>"
        "<li>In Arckon AI Spend, click <b>Add / Rotate Key</b>.</li>"
        "<li>Select <b>OpenAI</b>, paste the key, add a label, then click <b>Save Key</b>.</li>"
        "<li>Click <b>Fetch Latest</b> to pull the last 7 days of usage.</li>"
        "</ol>"

        "<h3>Add an Anthropic spend key</h3>"
        "<ol>"
        "<li>Sign in at <a href=\"https://console.anthropic.com/\" target=\"_blank\">console.anthropic.com</a>.</li>"
        "<li>Open <b>Settings → Organization</b>.</li>"
        "<li>Create an <b>Admin API key</b> with Usage and Cost access (starts with <code>sk-ant-admin01-...</code>).</li>"
        "<li>In Arckon, add the key under <b>Anthropic</b> and fetch.</li>"
        "</ol>"

        "<h3>Add a Google Gemini spend key</h3>"
        "<ol>"
        "<li>Go to <a href=\"https://aistudio.google.com/app/apikey\" target=\"_blank\">aistudio.google.com/app/apikey</a>.</li>"
        "<li>Create an API key with access to usage/cost data.</li>"
        "<li>In Arckon, add the key under <b>Gemini</b> and fetch.</li>"
        "</ol>"

        "<h3>Reading the dashboard</h3>"
        "<ul>"
        "<li><b>Total cost</b> — billed USD across all configured providers for the selected period.</li>"
        "<li><b>By provider</b> — relative spend bar chart.</li>"
        "<li><b>By model</b> — input, output, and total tokens per model.</li>"
        "<li><b>Daily trend</b> — cost per day over the selected range.</li>"
        "<li><b>By API key / client org</b> — MSP-only breakdowns appear for scoped users.</li>"
        "</ul>"

        "<h3>Troubleshooting</h3>"
        "<ul>"
        "<li><b>“Already fetched today”</b> — Arckon limits fetches to once per day. Click <b>Fetch Latest</b> again and confirm force if you need fresh data.</li>"
        "<li><b>“No spend data yet”</b> — verify the key has admin/read usage permissions, not just model inference permissions.</li>"
        "<li><b>Cost does not match invoice</b> — Arckon shows the usage and cost returned by the provider API at fetch time. Taxes, credits, and tiered pricing may differ from your invoice.</li>"
        "</ul>"
    )

    troubleshoot = (
                    "<h3>Linux install: \"set: illegal option\" or \"set pipefall\" error</h3>"
                    "<p>The install.sh script was created on Windows and has CRLF line endings. "
                    "Bash on Linux sees <code>pipefail\\r</code> as an unknown option and exits immediately. "
                    "Strip the carriage returns before running the script:</p>"
                    "<pre><code>sed -i 's/\\r$//' /tmp/sentinel/install.sh\n"
                    "sudo bash /tmp/sentinel/install.sh --server http://SERVER_IP:7331 --token YOUR_TOKEN</code></pre>"

                    "<h3>Linux install: PEP 668 \"externally managed environment\" error</h3>"
                    "<p>Ubuntu 23.04+ and Debian 12+ block system-wide pip installs by default. "
                    "Add the <code>--break-system-packages</code> flag to bypass this protection, "
                    "or skip pip entirely if the packages are already installed by the system package manager:</p>"
                    "<pre><code># Option A — override the PEP 668 block\n"
                    "sed -i 's/pip install --quiet/pip install --quiet --break-system-packages/g' /tmp/sentinel/install.sh\n\n"
                    "# Option B — skip pip install entirely (use already-installed system packages)\n"
                    "sed -i 's/\"$PYTHON\" -m pip install.*/echo \"skipping pip\"/' /tmp/sentinel/install.sh\n\n"
                    "# Then run the installer\n"
                    "sudo bash /tmp/sentinel/install.sh --server http://SERVER_IP:7331 --token YOUR_TOKEN</code></pre>"

                    "<h3>Linux install: finishes with no /etc/sentinel and no service created</h3>"
                    "<p>The installer exited silently mid-run (usually due to a pip error). "
                    "Skip the script and install manually:</p>"
                    "<pre><code># Copy files\n"
                    "sudo mkdir -p /opt/sentinel\n"
                    "sudo cp /tmp/sentinel/agent.py /opt/sentinel/\n"
                    "sudo cp /tmp/sentinel/storage.py /opt/sentinel/ 2>/dev/null || true\n"
                    "sudo cp -r /tmp/sentinel/checks /opt/sentinel/ 2>/dev/null || true\n"
                    "sudo cp -r /tmp/sentinel/profiles /opt/sentinel/ 2>/dev/null || true\n\n"
                    "# Create config\n"
                    "sudo mkdir -p /etc/sentinel\n"
                    "sudo tee /etc/arckon/agent_config.json &lt;&lt; 'EOF'\n"
                    "{\n"
                    "  \"server\": \"http://SERVER_IP:7331\",\n"
                    "  \"token\": \"YOUR_TOKEN\",\n"
                    "  \"target\": \"/\",\n"
                    "  \"profile\": \"default\",\n"
                    "  \"interval\": 3600\n"
                    "}\n"
                    "EOF\n\n"
                    "# Create systemd service\n"
                    "sudo tee /etc/systemd/system/arckon-agent.service &lt;&lt; 'EOF'\n"
                    "[Unit]\n"
                    "Description=RiskRaven Arckon Agent\n"
                    "After=network-online.target\n\n"
                    "[Service]\n"
                    "Type=simple\n"
                    "ExecStart=/usr/bin/python3 /opt/sentinel/agent.py --config /etc/arckon/agent_config.json --daemon\n"
                    "Restart=on-failure\n"
                    "RestartSec=30\n"
                    "Environment=PYTHONUNBUFFERED=1\n\n"
                    "[Install]\n"
                    "WantedBy=multi-user.target\n"
                    "EOF\n\n"
                    "# Enable and start\n"
                    "sudo systemctl daemon-reload\n"
                    "sudo systemctl enable sentinel-agent\n"
                    "sudo systemctl start sentinel-agent\n"
                    "sudo systemctl status sentinel-agent</code></pre>"

                    "<h3>Agent not connecting</h3>"
                    "<ul>"
                    "<li>Check the server is reachable: <code>curl http://SERVER_IP:7331/health</code> — should return status ok</li>"
                    "<li>Verify the token matches: agent uses --token, server reads agent_token.txt or SENTINEL_AGENT_TOKEN env var. If agent_token.txt does not exist, all tokens are accepted.</li>"
                    "<li>Check agent logs: <code>sudo journalctl -u sentinel-agent -n 50</code> (Linux) or <code>/var/log/sentinel-agent.log</code> (macOS)</li>"
                    "<li>Agent retries every 5 minutes on failure — wait one retry cycle after fixing</li>"
                    "</ul>"

                    "<h3>Device not appearing in Command Center</h3>"
                    "<ul>"
                    "<li>Agent must successfully complete one scan and POST to /api/agent/report</li>"
                    "<li>Check logs for \"Delivered report\" message</li>"
                    "<li>Confirm device registered: <code>curl http://SERVER_IP:7331/api/agents</code> — device should appear in this list</li>"
                    "<li>Trigger manual retry: <code>sudo systemctl restart sentinel-agent</code> (Linux) or restart the service</li>"
                    "</ul>"

                    "<h3>Command Center shows \"Device not found\" when clicking a device</h3>"
                    "<p>Usually caused by a stale server instance running old code in another terminal tab. "
                    "Check for multiple Python processes serving on port 7331:</p>"
                    "<pre><code># Linux / macOS\n"
                    "lsof -i :7331\n\n"
                    "# Windows (PowerShell)\n"
                    "Get-NetTCPConnection -LocalPort 7331</code></pre>"
                    "<p>Kill all instances and start a fresh one. Only one server process should be running at a time.</p>"

                    "<h3>Windows: server only reachable on localhost (not on network IP)</h3>"
                    "<p>Windows Firewall blocks inbound connections on port 7331 by default. "
                    "Run this once in PowerShell as Administrator:</p>"
                    "<pre><code>New-NetFirewallRule -DisplayName \"Sentinel Server\" -Direction Inbound -Protocol TCP -LocalPort 7331 -Action Allow</code></pre>"
                    "<p>After adding the rule, the dashboard will be accessible at <code>http://YOUR_IP:7331</code> from any device on the network.</p>"

                    "<h3>Devices not appearing — \"attempt to write a readonly database\"</h3>"
                    "<p>This happens when the server was installed with <code>sudo git clone</code> but is running "
                    "as a normal user. The <code>output/</code> directory is owned by root so the server cannot "
                    "write the device database. Fix:</p>"
                    "<pre><code>sudo chown -R $(whoami) /opt/sentinel/output\n\n"
                    "# Then restart the server\n"
                    "pkill -f server.py\n"
                    "nohup /opt/sentinel/venv/bin/python /opt/sentinel/server.py --no-browser > /tmp/sentinel-server.log 2>&1 &</code></pre>"
                    "<p>Devices will appear within 5 minutes as agents complete their next retry cycle.</p>"

                    "<h3>\"sudo git pull\" gives permission denied</h3>"
                    "<p>If the repo was cloned with <code>sudo git clone</code>, files are owned by root. "
                    "Running <code>git pull</code> as your regular user fails. Fix by taking ownership:</p>"
                    "<pre><code>sudo chown -R $(whoami) /opt/sentinel\n"
                    "git -C /opt/sentinel pull</code></pre>"

                    "<h3>Windows: \"git pull\" says already up to date but changes are missing</h3>"
                    "<p>The Windows machine is likely cloned from a different remote than where updates are pushed. "
                    "Check which remote it is tracking:</p>"
                    "<pre><code>cd C:\\Sentinel\n"
                    "git remote -v</code></pre>"
                    "<p>If it shows <code>audit-forge/mark-sentinel.git</code> but your updates go to "
                    "<code>keithferg2018/hash-ai-remediation.git</code>, add the correct remote and pull from it:</p>"
                    "<pre><code>git config --global credential.helper store\n"
                    "git remote add private https://github.com/keithferg2018/hash-ai-remediation.git\n"
                    "git fetch private\n"
                    "# Git will prompt for your PAT on first fetch and store it via credential.helper\n"
                    "git merge private/main</code></pre>"

                    "<h3>Windows: \"error: unknown switch C\" when running git</h3>"
                    "<p>Windows Git does not support the <code>-C</code> flag used to run git in another directory. "
                    "Use <code>cd</code> to enter the directory first, then run git commands:</p>"
                    "<pre><code>cd C:\\Sentinel\n"
                    "git remote -v\n"
                    "git pull</code></pre>"

                    "<h3>Windows: \"your local changes would be overwritten by merge\"</h3>"
                    "<p>The Windows machine has uncommitted local changes that conflict with the incoming merge. "
                    "Stash the changes first, then merge:</p>"
                    "<pre><code>cd C:\\Sentinel\n"
                    "git stash\n"
                    "git merge private/main</code></pre>"
                    "<p>The stash saves your local changes aside. After the merge the updated files are live. "
                    "Run <code>git stash pop</code> only if you need to recover the local edits — "
                    "in most cases the merged version is what you want.</p>"

                    "<h3>Bundle download fails</h3>"
                    "<ul>"
                    "<li>macOS: do not use --overwrite flag, BSD tar does not support it</li>"
                    "<li>Python version error: ensure <code>python3 --version</code> is 3.11 or later</li>"
                    "<li>Permission denied: use sudo for install.sh; use \"Run as Administrator\" for install.ps1</li>"
                    "</ul>"
                    )

    # build check catalog HTML
    def render_catalog():
        if not checks:
            return '<p class="muted">No checks found in checks/ (AI-*.md)</p>'
        parts = []
        # order categories
        cats = []
        for c in cat_order:
            if c in checks:
                cats.append(c)
        for c in sorted(checks.keys()):
            if c not in cats:
                cats.append(c)
        for c in cats:
            items = checks.get(c, [])
            parts.append(f'<div class="cat" id="cat-{_escape(c)}"><h3>{_escape(c)}</h3>')
            for itm in items:
                cid = _escape(itm['id'])
                title = _escape(itm['title'])
                sev = itm.get('severity','')
                parts.append(f'<div class="check-card" data-check="{cid}">')
                parts.append('<div class="check-hdr" onclick="toggleCard(this)">')
                parts.append(f'<div class="check-id">{cid}</div>')
                parts.append(f'<div class="check-title">{title}</div>')
                parts.append(badge_for(sev))
                parts.append('<div style="flex:1"></div>')
                parts.append('<div class="chev">▶</div>')
                parts.append('</div>')
                parts.append('<div class="check-body">')
                parts.append('<div class="plain"><strong>Plain English</strong><div class="plain-body">')
                parts.append(f'{_escape(itm.get("smb",""))}</div></div>')
                # pass / fail lists
                def _make_list(md_text: str):
                    if not md_text:
                        return '<div class="muted">No criteria provided.</div>'
                    # simple split on lines that look like list items
                    lines = [ln.strip('-* ').strip() for ln in md_text.splitlines() if ln.strip()]
                    if not lines:
                        return '<div class="muted">No criteria provided.</div>'
                    return '<ul>' + ''.join(f'<li>{_escape(line)}</li>' for line in lines) + '</ul>'
                parts.append('<div class="pf-grid">')
                parts.append('<div><strong>PASS Criteria</strong>' + _make_list(itm.get('pass','')) + '</div>')
                parts.append('<div><strong>FAIL Criteria</strong>' + _make_list(itm.get('fail','')) + '</div>')
                parts.append('</div>')
                rem = itm.get('remediation','')
                if rem:
                    parts.append('<div class="rem"><strong>Remediation</strong>')
                    parts.append(f'<pre><code>{_escape(rem)}</code></pre>')
                    parts.append('<button class="copy-btn" onclick="copySiblingCode(this)">Copy</button>')
                    parts.append('</div>')
                parts.append('</div>')  # body
                parts.append('</div>')  # card
            parts.append('</div>')
        return '\n'.join(parts)

    catalog_html = render_catalog()

    # assemble main HTML
    html_parts = [
        '<!doctype html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<title>RiskRaven Arckon — Academy</title>',
        '<style>',
        '/* Sentinel dark theme (self-contained) */',
        'html,body{height:100%;}',
        'body{margin:0;background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif}',
        '.container{display:flex;height:100vh;overflow:hidden}',
        '.sidebar{width:260px;background:#161b22;border-right:1px solid #21262d;padding:20px;overflow:auto}',
        '.brand{font-weight:800;color:#e6edf3;letter-spacing:1px}',
        '.brand-sub{font-size:12px;color:#8b949e;margin-top:4px}',
        '.search{margin-top:16px}',
        '.search input{width:100%;padding:8px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9}',
        '.nav{margin-top:18px}',
        '.nav a{display:block;padding:8px 6px;color:#8b949e;text-decoration:none;border-radius:6px}',
        '.nav a.active{background:#0b1116;color:#58a6ff}',
        '.nav a:hover{background:#0b1116;color:#58a6ff}',
        '.main{flex:1;overflow:auto;padding:36px 48px}',
        '.content{max-width:860px;margin:0 auto}',
        '.doc-section{margin-bottom:40px}',
        '.doc-section h2{color:#e6edf3;margin-bottom:12px}',
        '.muted{color:#8b949e}',
        'pre{background:#0d1117;border:1px solid #21262d;padding:12px;border-radius:6px;color:#c9d1d9;overflow:auto}',
        '.pf-grid{display:flex;gap:20px}',
        '.check-card{border:1px solid #21262d;background:#0d1117;border-radius:8px;margin:10px 0;overflow:hidden}',
        '.check-hdr{display:flex;align-items:center;gap:12px;padding:10px 14px;cursor:pointer}',
        '.check-id{font-family:monospace;color:#8b949e;font-size:12px}',
        '.check-title{font-weight:600;color:#c9d1d9}',
        '.check-body{display:none;padding:12px 14px;border-top:1px solid #21262d;color:#8b949e}',
        '.check-body .plain{background:#161b22;padding:10px;border-radius:6px;margin-bottom:10px}',
        '.sev{font-size:11px;font-weight:700;padding:4px 8px;border-radius:6px}',
        '.sev.critical{background:#3d1212;color:#f85149;border:1px solid #f85149}',
        '.sev.high{background:#3d1f00;color:#f0883e;border:1px solid #f0883e}',
        '.sev.medium{background:#2d2000;color:#d29922;border:1px solid #d29922}',
        '.sev.low{background:#0d1f3d;color:#58a6ff;border:1px solid #58a6ff}',
        '.copy-btn{margin-top:8px;background:#161b22;border:1px solid #30363d;color:#58a6ff;padding:6px 10px;border-radius:6px;cursor:pointer}',
        '.plain-body{margin-top:8px}',
        '.toc-legend{font-size:12px;color:#8b949e;margin-top:6px}',
        '.search-empty{color:#484f58;padding:12px;text-align:center}',
        '/* responsive */',
        '@media (max-width:900px){.sidebar{display:none}.container{padding:0}}',
        '</style>',
        '</head>',
        '<body>',
        '<div class="container">',
        '<aside class="sidebar">',
        '<div class="brand">RISKRAVEN ARCKON</div>',
        '<div class="brand-sub">Academy</div>',
        '<div class="search"><input id="search" placeholder="Search sections or checks…" /></div>',
        '<nav class="nav" id="nav">'
    ]

    for sid, title in nav_items:
        html_parts.append(f'<a href="#{_escape(sid)}" data-target="{_escape(sid)}">{_escape(title)}</a>')

    html_parts.extend([
        '</nav>',
        '<div class="toc-legend">Tip: start typing to filter the left nav</div>',
        '</aside>',
        '<main class="main">',
        '<div class="content">',
        section_html('overview', 'Overview', overview),
        section_html('prereqs', 'Prerequisites', prereqs),
        section_html('macos', 'macOS', macos),
        section_html('windows', 'Windows', windows),
        section_html('linux', 'Linux', linux),
        section_html('docker', 'Docker', docker),
        section_html('first-scan', 'First Scan', first_scan),
        section_html('profiles', 'Profiles', profiles),
        section_html('severity', 'Severity Levels', severity),
        section_html('status', 'Finding Status', status),
        section_html('tabs', 'Dashboard Tabs', tabs),
        section_html('command', 'Command Center', command_center),
        section_html('settings', 'Settings', settings),
        section_html('alerts', 'Alerts & Notifications', alerts),
        section_html('protected-files', 'Protected Files Monitoring', protected_files),
        section_html('siem-tools', 'SIEM & Tool Integrations', siem_tools),
        section_html('ai-spend', 'AI Spend', ai_spend),
        '<section id="catalog" class="doc-section">',
        '<h2>Check Catalog</h2>',
        '<p class="muted">This section parses checks/* files matching AI-*.md and renders them as collapsible cards.</p>',
        catalog_html,
        '</section>',
        section_html('troubleshoot', 'Troubleshooting', troubleshoot),
        '<hr style="border:none;border-top:1px solid #21262d;margin:30px 0">',
        '<footer class="muted">Generated by RiskRaven Arckon — Academy</footer>',
        '</div>',
        '</main>',
        '</div>',
        '<script>',
        '/* Client-side: search, scroll-spy, copy, toggle */',
        'const nav = document.getElementById("nav");',
        'const links = Array.from(nav.querySelectorAll("a"));',
        'const search = document.getElementById("search");',
        'search.addEventListener("input", (e)=>{',
        '  const q = e.target.value.toLowerCase().trim();',
        '  let shown=0;',
        '  links.forEach(a=>{',
        '    const t = a.textContent.toLowerCase();',
        '    if(!q || t.includes(q)) { a.style.display="block"; shown++; } else { a.style.display="none"; }',
        '  });',
        '  if(!shown) { if(!document.getElementById("empty-note")) { const el=document.createElement("div"); el.id="empty-note"; el.className="search-empty"; el.textContent="No results"; nav.appendChild(el);} } else { const ex=document.getElementById("empty-note"); if(ex) ex.remove(); }',
        '});',
        '// scroll-spy',
        'const sections = Array.from(document.querySelectorAll(".doc-section"));',
        'const obs = new IntersectionObserver((ents)=>{',
        '  ents.forEach(en=>{',
        '    const id = en.target.id; const l = nav.querySelector(`[data-target="${id}"]`);',
        '    if(en.isIntersecting){ links.forEach(x=>x.classList.remove("active")); if(l) l.classList.add("active"); }',
        '  });',
        '},{root:null,rootMargin:"-20% 0px -60% 0px",threshold:0});',
        'sections.forEach(s=>obs.observe(s));',
        '// toggle cards',
        'function toggleCard(el){const card=el.closest(".check-card"); const body=card.querySelector(".check-body"); const chev=el.querySelector(".chev"); if(body.style.display==="block"){ body.style.display="none"; if(chev) chev.textContent="▶" } else { body.style.display="block"; if(chev) chev.textContent="▼" }}',
        '// copy button',
        'function copySiblingCode(btn){ try{ const pre = btn.previousElementSibling; const code = pre && pre.textContent; if(!code) return; navigator.clipboard.writeText(code); btn.textContent="Copied"; setTimeout(()=>btn.textContent="Copy",1200);}catch(e){console.warn(e)} }',
        '// copy overlay for any <pre> (non-catalog codeblocks)',
        'document.querySelectorAll("pre").forEach(p=>{ const b=document.createElement("button"); b.className="copy-btn"; b.textContent="Copy"; b.style.cssText="float:right;margin:-6px 0 6px;"; b.onclick=()=>{ navigator.clipboard.writeText(p.textContent); b.textContent="Copied"; setTimeout(()=>b.textContent="Copy",1200); }; p.parentNode.insertBefore(b,p.nextSibling); });',
        '</script>',
        '</body>',
        '</html>'
    ])

    return '\n'.join(html_parts).encode('utf-8')
