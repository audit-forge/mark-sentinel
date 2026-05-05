"""
Academy site builder for M.A.R.K. Sentinel

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
    overview = ("<p>Sentinel is an AI security audit platform. Scans AI deployments for STIG/NIST/OWASP compliance. "
                "Two components: server (dashboard) and agent (installed on each device).</p>"
                "<p>Sentinel now supports NIST AI RMF 1.0 and SR 26-2 (April 2026 model risk guidance) for financial sector deployments.</p>")

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
             "<pre><code># Option A — SSH\n"
             "sudo git clone git@github.com:audit-forge/mark-sentinel.git /opt/sentinel\n\n"
             "# Option B — Personal Access Token\n"
             "sudo git clone https://YOUR_TOKEN@github.com/audit-forge/mark-sentinel.git /opt/sentinel\n\n"
             "# Check out the active branch (git clones the default branch — switch to get latest)\n"
             "cd /opt/sentinel && sudo git checkout feat/sentinel-distributed-agent\n\n"
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
             "sudo launchctl stop io.hash.sentinel-agent\n"
             "sudo launchctl start io.hash.sentinel-agent\n"
             "# Logs: /var/log/sentinel-agent.log</code></pre>")

    windows = ("<h4>Server setup (run once — PowerShell as Administrator)</h4>"
               "<p>Use SSH (recommended) or a Personal Access Token — GitHub does not accept passwords. "
               "To create a PAT: GitHub → Settings → Developer settings → Personal access tokens → Fine-grained → "
               "set resource owner to <b>audit-forge</b>, select <b>mark-sentinel</b> repo, set Contents to <b>Read-only</b>.</p>"
               "<pre><code># Option A — SSH\n"
               "git clone git@github.com:audit-forge/mark-sentinel.git C:\\Sentinel\n\n"
               "# Option B — Personal Access Token\n"
               "git clone https://YOUR_TOKEN@github.com/audit-forge/mark-sentinel.git C:\\Sentinel\n\n"
               "# Check out the active branch (git clones the default branch — switch to get latest)\n"
               "cd C:\\Sentinel; git checkout feat/sentinel-distributed-agent\n\n"
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
               "<h4>Agent install</h4>"
               "<p>Run in PowerShell as Administrator on each Windows machine to monitor:</p>"
               "<pre><code>Invoke-WebRequest http://SERVER_IP:7331/bundle.tar.gz -OutFile \"$env:TEMP\\sentinel.tar.gz\"\n"
               "tar -xz -f \"$env:TEMP\\sentinel.tar.gz\" -C \"$env:TEMP\"\n"
               "Set-Location \"$env:TEMP\\sentinel\"\n"
               ".\\install.ps1 -Server http://SERVER_IP:7331 -Token YOUR_TOKEN</code></pre>"
               "<h4>Service management</h4>"
               "<pre><code>Get-Service SentinelAgent           # check status\n"
               "Restart-Service SentinelAgent\n"
               "# Logs: C:\\ProgramData\\Sentinel\\sentinel-agent.log</code></pre>"
               "<p>For best results install NSSM first (https://nssm.cc). The installer falls back to sc.exe if NSSM is not found.</p>")

    linux = ("<h4>Server setup (run once)</h4>"
             "<p>Use SSH (recommended) or a Personal Access Token — GitHub does not accept passwords. "
             "To create a PAT: GitHub → Settings → Developer settings → Personal access tokens → Fine-grained → "
             "set resource owner to <b>audit-forge</b>, select <b>mark-sentinel</b> repo, set Contents to <b>Read-only</b>.</p>"
             "<pre><code># Option A — SSH\n"
             "sudo git clone git@github.com:audit-forge/mark-sentinel.git /opt/sentinel\n\n"
             "# Option B — Personal Access Token\n"
             "sudo git clone https://YOUR_TOKEN@github.com/audit-forge/mark-sentinel.git /opt/sentinel\n\n"
             "# Check out the active branch (git clones the default branch — switch to get latest)\n"
             "cd /opt/sentinel && sudo git checkout feat/sentinel-distributed-agent\n\n"
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
             "# Installs to: /opt/sentinel/ | Config: /etc/sentinel/agent_config.json</code></pre>"
             "<h4>Service management</h4>"
             "<pre><code>sudo systemctl status sentinel-agent\n"
             "sudo systemctl restart sentinel-agent\n"
             "sudo journalctl -u sentinel-agent -f    # live logs</code></pre>")

    docker = (
        "<p>Use Docker to run the Sentinel agent (or server) in an isolated container — "
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
        "<li><b>SENTINEL_SERVER</b> — URL of the Sentinel server (required)</li>"
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

    profiles = ("<p>Sentinel ships with several built-in profiles to tailor checks for different environments.</p>"
                "<ul>"
                "<li><b>SMB Basic</b> — lightweight checks suitable for small/medium businesses.</li>"
                "<li><b>FedRAMP Moderate</b> — controls mapped to NIST 800-53 for cloud deployments.</li>"
                "<li><b>CMMC Level 2</b> — controlled environment mapping for DoD supply chain.</li>"
                "<li><b>Financial Services</b> — runs all checks mapped to NIST AI RMF 1.0, SR 11-7, and SR 26-2. Designed for banks and financial institutions.</li>"
                "</ul>")

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
        "<p>The <b>Settings</b> panel lives at the bottom of the Command Center. "
        "It exists for one reason: <b>once Sentinel is installed, you should never need to open a terminal again.</b> "
        "Everything that needs a human decision after install is exposed here.</p>"

        "<h3>What is it for?</h3>"
        "<p>After you install Sentinel on a device, two things may change over time depending on your situation:</p>"
        "<ol>"
        "<li><b>Which compliance rules to run</b> — called the Compliance Profile</li>"
        "<li><b>How often to run them</b> — called the Scan Interval</li>"
        "</ol>"
        "<p>Settings lets you change both without touching a config file or opening a terminal. "
        "Everything else — server address, authentication token, what folder to scan — is set once during install "
        "and never needs to change.</p>"

        "<h3>Compliance Profile</h3>"
        "<p>The profile tells Sentinel <i>which rulebook to audit against</i>. "
        "Different industries have different requirements. You pick the one that matches your situation.</p>"
        "<table class=\"sev-table\">"
        "<tr><th>Default</th><td>General-purpose AI security checks. Good starting point for any organization.</td></tr>"
        "<tr><th>Financial Services</th><td>Full check suite mapped to NIST AI RMF 1.0, SR 11-7, and SR 26-2. "
        "Required for banks and financial institutions. Use this for PNC and similar clients.</td></tr>"
        "<tr><th>FedRAMP / NIST 800-53</th><td>Controls required for U.S. federal cloud deployments.</td></tr>"
        "<tr><th>CMMC</th><td>Defense supply chain compliance (DoD contractors).</td></tr>"
        "<tr><th>SMB</th><td>Simplified language and lightweight checks for small businesses with no compliance team.</td></tr>"
        "</table>"

        "<h3>When would you change the profile?</h3>"
        "<ul>"
        "<li>A new client has different regulatory requirements than your current setting — "
        "switch to their profile before the next scan so the report speaks their language.</li>"
        "<li>You onboard a bank — switch from Default to Financial Services so the report "
        "references SR 26-2 and NIST AI RMF instead of generic controls.</li>"
        "<li>A customer gets acquired by a government contractor — switch to CMMC.</li>"
        "<li>You want to run a quick lightweight check on a small business — switch to SMB "
        "so the report doesn't overwhelm them with regulatory language they don't need.</li>"
        "</ul>"

        "<h3>Scan Interval</h3>"
        "<p>This controls how frequently Sentinel automatically re-scans the device and sends updated results "
        "to the Command Center. The value is in seconds.</p>"
        "<table class=\"sev-table\">"
        "<tr><th>3600</th><td>Every hour — use during active remediation or when a client is fixing issues and wants to see progress quickly.</td></tr>"
        "<tr><th>86400</th><td>Once a day — good default for ongoing monitoring once things are in order.</td></tr>"
        "<tr><th>604800</th><td>Once a week — low-overhead background monitoring for stable environments.</td></tr>"
        "</table>"

        "<h3>When would you change the interval?</h3>"
        "<ul>"
        "<li>A client is actively fixing findings — drop to 3600 (hourly) so you can both watch the score improve in real time.</li>"
        "<li>An audit is coming up in two weeks — increase frequency to daily so you have a dense trend line to show auditors.</li>"
        "<li>Everything is clean and stable — set to weekly to reduce noise.</li>"
        "</ul>"

        "<h3>Desktop Shortcut</h3>"
        "<p>The <b>Desktop Shortcut</b> button (top right of the Settings section) downloads a file you can "
        "save to your desktop. Double-clicking it opens the Command Center in your browser instantly — "
        "no terminal, no remembering the URL. On Windows it creates a <code>.url</code> file; "
        "on Mac it creates a <code>.webloc</code> file. Both work by double-click.</p>"
        "<p>On Windows, the installer (<code>install.ps1</code>) creates this shortcut automatically on the desktop "
        "during setup, so most users will already have it without needing to download it manually.</p>"

        "<h3>What Settings does NOT do</h3>"
        "<p>Settings does not control:</p>"
        "<ul>"
        "<li>Which server the agent reports to — set at install time, does not change</li>"
        "<li>Which folder is scanned — set at install time, Sentinel figures this out automatically</li>"
        "<li>Authentication tokens — managed by the installer, not the UI</li>"
        "</ul>"
        "<p>Those are one-time install decisions. If they ever need to change, that is done by re-running "
        "the installer or using the Update Agent button from the Command Center.</p>"
    )

    alerts = ("<p>Create a file called <code>alerts.json</code> in the Sentinel directory:</p>"
              "<pre><code>{\n  \"webhook_url\": \"https://hooks.slack.com/services/YOUR/WEBHOOK/URL\",\n  \"min_severity\": \"HIGH\",\n  \"email_to\": \"security@yourcompany.com\",\n  \"email_from\": \"sentinel@yourcompany.com\",\n  \"smtp_host\": \"smtp.yourcompany.com\"\n}</code></pre>"
              "<p>Fields:</p>"
              "<ul>"
              "<li><b>webhook_url</b> — Slack, Teams, or any HTTP POST endpoint</li>"
              "<li><b>min_severity</b> — CRITICAL, HIGH, MEDIUM, or LOW (only alerts above this threshold fire)</li>"
              "<li><b>email_to / email_from / smtp_host</b> — optional email alerts</li>"
              "</ul>")

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
                    "sudo tee /etc/sentinel/agent_config.json &lt;&lt; 'EOF'\n"
                    "{\n"
                    "  \"server\": \"http://SERVER_IP:7331\",\n"
                    "  \"token\": \"YOUR_TOKEN\",\n"
                    "  \"target\": \"/\",\n"
                    "  \"profile\": \"default\",\n"
                    "  \"interval\": 3600\n"
                    "}\n"
                    "EOF\n\n"
                    "# Create systemd service\n"
                    "sudo tee /etc/systemd/system/sentinel-agent.service &lt;&lt; 'EOF'\n"
                    "[Unit]\n"
                    "Description=M.A.R.K. Sentinel Agent\n"
                    "After=network-online.target\n\n"
                    "[Service]\n"
                    "Type=simple\n"
                    "ExecStart=/usr/bin/python3 /opt/sentinel/agent.py --config /etc/sentinel/agent_config.json --daemon\n"
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
                    "<pre><code>git remote add private https://YOUR_TOKEN@github.com/keithferg2018/hash-ai-remediation.git\n"
                    "git fetch private\n"
                    "git merge private/feat/sentinel-distributed-agent</code></pre>"

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
                    "git merge private/feat/sentinel-distributed-agent</code></pre>"
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
        '<title>M.A.R.K. Sentinel — Academy</title>',
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
        '<div class="brand">M.A.R.K. SENTINEL</div>',
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
        '<section id="catalog" class="doc-section">',
        '<h2>Check Catalog</h2>',
        '<p class="muted">This section parses checks/* files matching AI-*.md and renders them as collapsible cards.</p>',
        catalog_html,
        '</section>',
        section_html('troubleshoot', 'Troubleshooting', troubleshoot),
        '<hr style="border:none;border-top:1px solid #21262d;margin:30px 0">',
        '<footer class="muted">Generated by M.A.R.K. Sentinel — Academy</footer>',
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
