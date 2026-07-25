"""
Active TCP connection scan — detects employees accessing known SaaS AI services.

Uses only stdlib (subprocess + socket) — no psutil required.
Returns results compatible with the existing report_discovery() format.
"""
import socket
import subprocess
import sys
import time
from typing import Optional

# Known SaaS AI service domains → display name
_AI_DOMAINS: dict[str, str] = {
    'chat.openai.com':          'ChatGPT',
    'api.openai.com':           'OpenAI API',
    'openai.com':               'OpenAI',
    'claude.ai':                'Claude (Anthropic)',
    'api.anthropic.com':        'Anthropic API',
    'anthropic.com':            'Anthropic',
    'gemini.google.com':        'Google Gemini',
    'generativelanguage.googleapis.com': 'Google AI API',
    'aistudio.google.com':      'Google AI Studio',
    'copilot.microsoft.com':    'Microsoft Copilot',
    'github.com':               'GitHub Copilot',
    'api.github.com':           'GitHub Copilot API',
    'huggingface.co':           'Hugging Face',
    'api-inference.huggingface.co': 'HuggingFace API',
    'perplexity.ai':            'Perplexity AI',
    'pplx-api.perplexity.ai':   'Perplexity API',
    'mistral.ai':               'Mistral AI',
    'api.mistral.ai':           'Mistral API',
    'groq.com':                 'Groq',
    'api.groq.com':             'Groq API',
    'cohere.com':               'Cohere',
    'api.cohere.com':           'Cohere API',
    'replicate.com':            'Replicate',
    'api.replicate.com':        'Replicate API',
    'together.ai':              'Together AI',
    'api.together.xyz':         'Together API',
    'deepmind.google':          'Google DeepMind',
    'grok.x.ai':                'Grok (xAI)',
    'x.ai':                     'xAI',
    'character.ai':             'Character.AI',
    'beta.character.ai':        'Character.AI',
    'poe.com':                  'Poe AI',
    'you.com':                  'You.com AI',
    'phind.com':                'Phind AI',
    'cursor.sh':                'Cursor AI',
    'v0.dev':                   'Vercel v0',
    'bolt.new':                 'StackBlitz Bolt',
}

# Seconds to cache a reverse-DNS result (avoid hammering DNS)
_DNS_CACHE_TTL = 300
_dns_cache: dict[str, tuple[str, float]] = {}


def _reverse_dns(ip: str) -> Optional[str]:
    """Reverse-DNS lookup with in-process TTL cache."""
    now = time.monotonic()
    cached = _dns_cache.get(ip)
    if cached and now - cached[1] < _DNS_CACHE_TTL:
        return cached[0] or None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = ''
    _dns_cache[ip] = (hostname, now)
    return hostname or None


def _match_ai_domain(hostname: str) -> Optional[str]:
    """Return service name if hostname matches a known AI domain (exact or suffix)."""
    hostname = hostname.lower().rstrip('.')
    # Exact match first
    if hostname in _AI_DOMAINS:
        return _AI_DOMAINS[hostname]
    # Suffix match: e.g. 'foo.chat.openai.com' matches 'chat.openai.com'
    for domain, service in _AI_DOMAINS.items():
        if hostname.endswith('.' + domain):
            return service
    return None


def _get_established_connections_unix() -> list[tuple[str, int]]:
    """Return list of (remote_ip, remote_port) for ESTABLISHED TCP connections."""
    results: list[tuple[str, int]] = []
    try:
        proc = subprocess.run(
            ['netstat', '-n', '-p', 'tcp'],
            capture_output=True, text=True, timeout=10,
        )
        for line in proc.stdout.splitlines():
            parts = line.split()
            # netstat -n -p tcp output varies; look for ESTABLISHED lines
            # macOS:  Proto Recv-Q Send-Q Local-Address  Foreign-Address  State
            # Linux:  tcp   0      0      local          foreign          ESTABLISHED
            if 'ESTABLISHED' not in line:
                continue
            for part in parts:
                if '.' in part or ':' in part:
                    # Try to extract foreign address (not local)
                    pass
            # Find the ESTABLISHED token and look at the field before it
            try:
                idx = parts.index('ESTABLISHED')
                foreign = parts[idx - 1]
                # macOS: 1.2.3.4.443  Linux: 1.2.3.4:443
                if '.' in foreign and foreign.count('.') == 4:
                    # macOS dot notation: last segment is port
                    segments = foreign.rsplit('.', 1)
                    ip, port_str = segments[0], segments[1]
                    ip = ip.replace('.', '.', 3)
                    results.append((ip, int(port_str)))
                elif ':' in foreign:
                    ip, port_str = foreign.rsplit(':', 1)
                    ip = ip.strip('[]')
                    results.append((ip, int(port_str)))
            except (ValueError, IndexError):
                continue
    except Exception:
        pass
    return results


def _get_established_connections_windows() -> list[tuple[str, int]]:
    """Windows: use netstat -n to get established connections."""
    results: list[tuple[str, int]] = []
    try:
        proc = subprocess.run(
            ['netstat', '-n'],
            capture_output=True, text=True, timeout=10,
        )
        for line in proc.stdout.splitlines():
            if 'ESTABLISHED' not in line:
                continue
            parts = line.split()
            try:
                idx = parts.index('ESTABLISHED')
                foreign = parts[idx - 1]
                if ':' in foreign:
                    ip, port_str = foreign.rsplit(':', 1)
                    results.append((ip.strip('[]'), int(port_str)))
            except (ValueError, IndexError):
                continue
    except Exception:
        pass
    return results


def _scan_recent_connections_macos() -> list[tuple[str, str, str]]:
    """
    macOS 12+: dscacheutil -cachedump is broken. Instead capture CLOSE_WAIT and
    TIME_WAIT TCP connections from netstat — these represent sessions closed in the
    last few minutes and give us the same signal as DNS cache (recently used services).
    Returns list of (domain_or_ip, resolved_domain, service_name).
    """
    results: list[tuple[str, str, str]] = []
    recent_states = {'CLOSE_WAIT', 'TIME_WAIT', 'FIN_WAIT_1', 'FIN_WAIT_2', 'LAST_ACK'}
    try:
        proc = subprocess.run(
            ['netstat', '-n', '-p', 'tcp'],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return results

    for line in proc.stdout.splitlines():
        state = line.split()[-1] if line.split() else ''
        if state not in recent_states:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        foreign = parts[4]  # macOS: Proto Recv-Q Send-Q Local Foreign State
        try:
            # macOS format: a.b.c.d.port (IPv4) or addr:port (IPv6 abbreviated as addr.port)
            ip, port_str = foreign.rsplit('.', 1)
            port = int(port_str)
        except (ValueError, IndexError):
            continue
        if port not in (80, 443):
            continue
        if ip.startswith('127.') or ip == '::1':
            continue
        hostname = _reverse_dns(ip)
        if not hostname:
            continue
        service = _match_ai_domain(hostname)
        if service:
            results.append((ip, hostname, service))
    return results


def _scan_dns_cache_windows() -> list[tuple[str, str, str]]:
    """
    Read Windows DNS cache via ipconfig /displaydns (works without PowerShell).
    Falls back to Get-DnsClientCache if ipconfig output is empty.
    Returns list of (domain, resolved_ip, service_name).
    """
    results: list[tuple[str, str, str]] = []

    # Primary: ipconfig /displaydns — available on all Windows versions
    try:
        proc = subprocess.run(
            ['ipconfig', '/displaydns'],
            capture_output=True, text=True, timeout=15, encoding='utf-8', errors='replace',
        )
        current_name = ''
        current_ip   = ''
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                # Blank line = end of entry block
                if current_name:
                    service = _match_ai_domain(current_name)
                    if service:
                        results.append((current_name, current_ip, service))
                current_name = ''
                current_ip   = ''
                continue
            if line.endswith('----------'):
                continue
            if ':' in line:
                key, _, val = line.partition(':')
                key = key.strip().lower()
                val = val.strip()
                if 'record name' in key:
                    current_name = val.lower().rstrip('.')
                elif 'a (host) record' in key or ('data' in key and not current_ip):
                    # Check if val looks like an IPv4 address
                    parts = val.split('.')
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        current_ip = val
        # Flush last entry
        if current_name:
            service = _match_ai_domain(current_name)
            if service:
                results.append((current_name, current_ip, service))
        if results:
            return results
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: PowerShell Get-DnsClientCache
    import json as _json
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command',
             'Get-DnsClientCache | Select-Object -Property Entry,Data | ConvertTo-Json -Compress'],
            capture_output=True, text=True, timeout=15,
        )
        raw = proc.stdout.strip()
        if raw:
            entries = _json.loads(raw)
            if isinstance(entries, dict):
                entries = [entries]
            for e in entries:
                domain  = str(e.get('Entry', '')).lower().rstrip('.')
                data    = str(e.get('Data',  ''))
                service = _match_ai_domain(domain)
                if service:
                    results.append((domain, data, service))
    except Exception:
        pass
    return results


def _scan_dns_cache_linux() -> list[tuple[str, str, str]]:
    """
    Linux: systemd-resolved has no cache-dump API and resolvectl does not support
    --cache=only on older versions, so probing domains produces fresh DNS lookups
    that look like cache hits — unreliable false positives.
    The active ESTABLISHED connection scan already catches real Linux connections.
    """
    return []


def scan_dns_cache() -> list[dict]:
    """
    Catch recently-closed AI service sessions that the active-connection scan would miss.
    macOS: netstat CLOSE_WAIT/TIME_WAIT states (dscacheutil broken on macOS 12+).
    Windows: ipconfig /displaydns + Get-DnsClientCache fallback.
    Linux: resolvectl query probing of known AI domains.
    Results use port=0 and detail suffix '(DNS cache)' or '(recently closed)'.
    """
    if sys.platform == 'darwin':
        entries = _scan_recent_connections_macos()
    elif sys.platform == 'win32':
        entries = _scan_dns_cache_windows()
    else:
        entries = _scan_dns_cache_linux()

    label = 'recently closed' if sys.platform == 'darwin' else 'DNS cache'
    seen: set[str] = set()
    results: list[dict] = []
    for domain, ip, service in entries:
        key = ip or domain
        if key in seen:
            continue
        seen.add(key)
        results.append({
            'source':  'saas_ai',
            'host':    ip if ip else domain,
            'port':    0,
            'service': service,
            'models':  [],
            'detail':  f'{ip or domain} ({label})',
        })
    return results


def scan() -> list[dict]:
    """
    Combined scan: active TCP connections + DNS cache.
    Returns results compatible with report_discovery() format.
    """
    if sys.platform == 'win32':
        connections = _get_established_connections_windows()
    else:
        connections = _get_established_connections_unix()

    seen: set[tuple[str, str]] = set()
    results: list[dict] = []

    # --- Active connections ---
    for ip, port in connections:
        if port not in (80, 443):
            continue
        if ip.startswith('127.') or ip.startswith('::1') or ip == 'localhost':
            continue

        hostname = _reverse_dns(ip)
        if not hostname:
            continue

        service = _match_ai_domain(hostname)
        if not service:
            continue

        key = (ip, hostname)
        if key in seen:
            continue
        seen.add(key)

        results.append({
            'source':  'saas_ai',
            'host':    ip,
            'port':    port,
            'service': service,
            'models':  [],
            'detail':  hostname,
        })

    # --- DNS cache (catches recently-closed sessions) ---
    active_services = {r['service'] for r in results}
    for entry in scan_dns_cache():
        # Skip if we already have an active-connection entry for this service
        # (active connection is more informative than DNS cache hit)
        if entry['service'] in active_services:
            continue
        domain = entry['detail'].replace(' (DNS cache)', '')
        key = (entry['host'], domain)
        if key in seen:
            continue
        seen.add(key)
        results.append(entry)

    return results
