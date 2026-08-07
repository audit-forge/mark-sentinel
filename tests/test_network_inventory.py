"""Focused coverage for passive network asset inventory boundaries."""
from network_inventory import collect_passive_neighbors, parse_arp, parse_ip_neighbors, parse_ndp, parse_windows_neighbors
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
