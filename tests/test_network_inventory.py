"""Focused coverage for passive network asset inventory boundaries."""
from network_inventory import (collect_active_ai_services, collect_passive_neighbors, parse_arp,
                               parse_ip_neighbors, parse_ndp, parse_windows_neighbors)
from storage import AgentStore


def _report():
    return {'scan_date': '2026-08-07', 'summary': {'fail': 0, 'warn': 0, 'pass': 1}}


def test_passive_parsers_handle_ipv4_ipv6_and_malformed_lines():
    assert parse_arp('? (192.0.2.5) at aa:bb:cc:dd:ee:ff on en0') == [{
        'ip_address': '192.0.2.5', 'mac_address': 'aa:bb:cc:dd:ee:ff', 'interface': 'en0', 'source': 'arp'}]
    assert parse_ip_neighbors('2001:db8::5 dev eth0 lladdr AA-BB-CC-DD-EE-FF REACHABLE', 'ipv6') == [{
        'ip_address': '2001:db8::5', 'mac_address': 'aa:bb:cc:dd:ee:ff', 'interface': 'eth0', 'source': 'ipv6'}]
    assert parse_windows_neighbors('12  192.0.2.7  aa-bb-cc-dd-ee-ff Reachable', 'windows') == [{
        'ip_address': '192.0.2.7', 'mac_address': 'aa:bb:cc:dd:ee:ff', 'interface': '12', 'source': 'windows'}]
    assert parse_windows_neighbors('Interface 12: Ethernet\n192.0.2.8 aa-bb-cc-dd-ee-ff Reachable', 'windows')[0]['interface'] == '12'
    assert parse_ndp('fe80::1%en0  1:2:3:4:5:6  en0  23h', 'ndp')[0]['mac_address'] == '01:02:03:04:05:06'
    assert parse_arp('not a neighbor') == []


def test_collector_only_runs_neighbor_cache_commands():
    commands = []
    class Result:
        stdout = '192.0.2.9 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE'
    def run(command, **kwargs):
        commands.append(command)
        return Result()
    assets = collect_passive_neighbors(run=run, system='Linux')
    assert assets
    assert commands == [['arp', '-an'], ['ip', 'neigh', 'show'], ['ip', '-6', 'neigh', 'show']]


def test_network_assets_upsert_and_scope_through_reporting_device(tmp_path):
    store = AgentStore(tmp_path / 'agents.db')
    store.upsert_report('a', 'agent-a', _report(), client_org_id='org-a')
    store.upsert_report('b', 'agent-b', _report(), client_org_id='org-b')
    store.upsert_network_asset('a', '192.0.2.10', 'aa:bb:cc:dd:ee:ff', 'eth0', 'linux_ipv4_neighbor')
    store.upsert_network_asset('a', '192.0.2.10', 'aa:bb:cc:dd:ee:ff', 'eth0', 'linux_ipv4_neighbor')
    store.upsert_network_asset('b', '192.0.2.11', '', 'eth1', 'linux_ipv4_neighbor')
    assets = store.list_network_assets(client_org_id='org-a')
    assert len(assets) == 1
    assert assets[0]['reporter_hostname'] == 'agent-a'
    assert len(store.list_network_assets(client_org_id='org-b')) == 1
    assert len(store.list_network_assets()) == 2


def test_removing_reporter_removes_its_network_assets(tmp_path):
    store = AgentStore(tmp_path / 'agents.db')
    store.upsert_report('a', 'agent-a', _report(), client_org_id='org-a')
    store.upsert_network_asset('a', '192.0.2.10', '', 'eth0', 'linux_ipv4_neighbor')
    store.delete_device('a')
    assert store.list_network_assets() == []


def test_active_scan_collects_hosts_and_selected_ai_ports_only():
    discovery_xml = '''<nmaprun><host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/><hostnames><hostname name="ollama.local"/></hostnames></host></nmaprun>'''
    services_xml = '''<nmaprun><host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/><hostnames><hostname name="ollama.local"/></hostnames><ports><port protocol="tcp" portid="11434"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'''
    commands = []
    class Result:
        def __init__(self, stdout): self.stdout = stdout
    def run(command, **kwargs):
        commands.append(command)
        return Result(discovery_xml if '-sn' in command else services_xml)
    assets, scan = collect_active_ai_services('192.168.1.0/24', run=run, which=lambda _: '/usr/bin/nmap')
    assert scan['status'] == 'complete'
    assert any(a.get('port') == 11434 and a['source'] == 'nmap_ai_service:11434' for a in assets)
    assert any(a['source'] == 'nmap_active' and a['hostname'] == 'ollama.local' for a in assets)
    assert commands[0][1:3] == ['-sn', '-oX']
    assert '-sT' in commands[1] and any('11434' in value for value in commands[1])


def test_active_scan_refuses_public_or_unavailable_scans():
    assets, scan = collect_active_ai_services('8.8.8.0/24', which=lambda _: '/usr/bin/nmap')
    assert not assets and scan['status'] == 'failed'
    assets, scan = collect_active_ai_services('192.168.1.0/24', which=lambda _: None)
    assert not assets and scan['status'] == 'unavailable'


def test_network_inventory_csv_export_uses_normalized_tenant_scoped_data():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / 'server.py').read_text()
    assert "'/api/fleet/network-assets.csv': self._api_fleet_network_assets_csv" in source
    assert 'def _normalize_network_assets(network_assets: list[dict])' in source
    assert 'Content-Disposition\', \'attachment; filename="arckon_network_inventory.csv"\'' in source
