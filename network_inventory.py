"""Passive local network neighbor-cache collection. No probes or DNS lookups."""
import ipaddress
import platform
import re
import shutil
import subprocess


_MAC = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
_AI_PORTS = (11434, 8000, 8001, 8080, 5000, 3000, 7860, 8501, 9000, 6333, 19530)


def _asset(ip: str, mac: str = '', interface: str = '', source: str = '') -> dict | None:
    try:
        ipaddress.ip_address(ip.split('%', 1)[0])
    except ValueError:
        return None
    mac = mac.replace('-', ':').lower()
    if ':' in mac:
        parts = mac.split(':')
        if len(parts) == 6 and all(1 <= len(part) <= 2 and re.fullmatch(r'[0-9a-f]+', part) for part in parts):
            mac = ':'.join(part.zfill(2) for part in parts)
    if mac and not _MAC.fullmatch(mac):
        mac = ''
    return {'ip_address': ip.split('%', 1)[0], 'mac_address': mac,
            'interface': interface, 'source': source}


def parse_arp(output: str, source: str = 'arp') -> list[dict]:
    """Parse macOS/Linux ``arp -an`` output without resolving hostnames."""
    assets = []
    for line in output.splitlines():
        match = re.search(r"\(([^)]+)\)\s+at\s+([^\s]+)(?:.*?\bon\s+([^\s]+))?", line, re.I)
        if match:
            asset = _asset(match.group(1), match.group(2), match.group(3) or '', source)
            if asset:
                assets.append(asset)
    return assets


def parse_ip_neighbors(output: str, source: str) -> list[dict]:
    assets = []
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        ip, interface, mac = fields[0], '', ''
        if 'dev' in fields and fields.index('dev') + 1 < len(fields):
            interface = fields[fields.index('dev') + 1]
        if 'lladdr' in fields and fields.index('lladdr') + 1 < len(fields):
            mac = fields[fields.index('lladdr') + 1]
        asset = _asset(ip, mac, interface, source)
        if asset:
            assets.append(asset)
    return assets


def parse_ndp(output: str, source: str) -> list[dict]:
    """Parse macOS ``ndp -an`` output, including BSD's non-padded MACs."""
    assets = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        interface = fields[2] if len(fields) > 2 else fields[0].split('%', 1)[-1]
        asset = _asset(fields[0], fields[1], interface, source)
        if asset:
            assets.append(asset)
    return assets


def parse_windows_neighbors(output: str, source: str) -> list[dict]:
    assets = []
    current_interface = ''
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        header = re.match(r'\s*interface\s+(\d+)\s*:', line, re.I)
        if header:
            current_interface = header.group(1)
            continue
        ip = next((f for f in fields if _asset(f)), '')
        if not ip:
            continue
        mac = next((f for f in fields if _MAC.fullmatch(f.replace('-', ':'))), '')
        interface = current_interface or (fields[0] if fields[0] != ip else '')
        asset = _asset(ip, mac, interface, source)
        if asset:
            assets.append(asset)
    return assets


def collect_passive_neighbors(run=subprocess.run, system: str | None = None) -> list[dict]:
    """Read OS neighbor caches only. Commands never generate network traffic."""
    system = system or platform.system()
    if system == 'Windows':
        commands = [(['netsh', 'interface', 'ipv4', 'show', 'neighbors'], 'windows_ipv4_neighbor'),
                    (['netsh', 'interface', 'ipv6', 'show', 'neighbors'], 'windows_ipv6_neighbor')]
        parser = parse_windows_neighbors
    elif system == 'Darwin':
        commands = [(['arp', '-an'], 'macos_arp'), (['ndp', '-an'], 'macos_ipv6_neighbor')]

        def parser(text, source):
            return parse_arp(text, source) if source == 'macos_arp' else parse_ndp(text, source)
    else:
        commands = [(['arp', '-an'], 'linux_arp'), (['ip', 'neigh', 'show'], 'linux_ipv4_neighbor'),
                    (['ip', '-6', 'neigh', 'show'], 'linux_ipv6_neighbor')]

        def parser(text, source):
            return parse_arp(text, source) if source == 'linux_arp' else parse_ip_neighbors(text, source)
    found: dict[tuple, dict] = {}
    for command, source in commands:
        try:
            result = run(command, capture_output=True, text=True, timeout=10, check=False)
            for asset in parser(result.stdout or '', source):
                found[(asset['ip_address'], asset['mac_address'], asset['interface'], asset['source'])] = asset
        except (OSError, subprocess.SubprocessError):
            continue
    return list(found.values())


def _nmap_hosts(xml_text: str, source: str) -> list[dict]:
    """Parse Nmap XML into host and AI-service observations."""
    results = []
    for host in re.findall(r'<host\b[^>]*>(.*?)</host>', xml_text, re.DOTALL):
        if not re.search(r'<status\b[^>]*\bstate="up"', host):
            continue
        addresses = {kind: address for address, kind in re.findall(
            r'<address\b[^>]*\baddr="([^"]+)"[^>]*\baddrtype="([^"]+)"', host)}
        mac = addresses.get('mac', '')
        hostname_match = re.search(r'<hostname\b[^>]*\bname="([^"]+)"', host)
        hostname = hostname_match.group(1) if hostname_match else ''
        for addrtype in ('ipv4', 'ipv6'):
            ip = addresses.get(addrtype, '')
            asset = _asset(ip, mac, '', source) if ip else None
            if not asset:
                continue
            asset['hostname'] = hostname
            asset['port'] = 0
            asset['service'] = ''
            results.append(asset)
            for port_id, port_body in re.findall(r'<port\b[^>]*\bportid="(\d+)"[^>]*>(.*?)</port>', host, re.DOTALL):
                if not re.search(r'<state\b[^>]*\bstate="open"', port_body):
                    continue
                port_asset = dict(asset)
                port_asset['port'] = int(port_id)
                port_asset['source'] = f"nmap_ai_service:{port_asset['port']}"
                service_match = re.search(r'<service\b[^>]*\bname="([^"]+)"', port_body)
                port_asset['service'] = (service_match.group(1) if service_match else '')[:64]
                results.append(port_asset)
    return results


def collect_active_ai_services(cidr: str, run=subprocess.run, which=shutil.which) -> tuple[list[dict], dict]:
    """Authorized Nmap discovery of one private CIDR and selected AI ports."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return [], {'status': 'failed', 'detail': 'invalid CIDR'}
    if not network.is_private or network.num_addresses > 1024:
        return [], {'status': 'failed', 'detail': 'CIDR must be private and contain 1,024 addresses or fewer'}
    if not which('nmap'):
        return [], {'status': 'unavailable', 'detail': 'Nmap is not installed on this agent'}
    base = ['nmap'] + (['-6'] if network.version == 6 else [])
    try:
        discovery = run(base + ['-sn', '-oX', '-', str(network)], capture_output=True, text=True, timeout=180, check=False)
        hosts = _nmap_hosts(discovery.stdout or '', 'nmap_active')
        addresses = sorted({a['ip_address'] for a in hosts})
        if not addresses:
            return [], {'status': 'complete', 'detail': 'No live hosts found'}
        ports = ','.join(str(port) for port in _AI_PORTS)
        services = run(base + ['-sT', '-sV', '--version-light', '--open', '--max-retries', '1', '--host-timeout', '15s', '-p', ports, '-oX', '-'] + addresses,
                       capture_output=True, text=True, timeout=300, check=False)
        found = _nmap_hosts(services.stdout or '', 'nmap_active')
        # Preserve host discovery rows even if no selected port is open.
        merged = {(a['ip_address'], a.get('mac_address', ''), a.get('port', 0), a['source']): a for a in hosts}
        for asset in found:
            merged[(asset['ip_address'], asset.get('mac_address', ''), asset.get('port', 0), asset['source'])] = asset
        return list(merged.values()), {'status': 'complete', 'detail': f'{len(addresses)} live host(s) discovered'}
    except (OSError, subprocess.SubprocessError) as exc:
        return [], {'status': 'failed', 'detail': f'Nmap execution failed: {exc}'}
