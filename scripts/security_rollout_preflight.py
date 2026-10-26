"""Read-only Docker-host inventory. Never prints credential values."""
import json
import subprocess
import sys


def main():
    names = subprocess.check_output(
        ['docker', 'ps', '--filter', 'label=sentinel.customer', '--format', '{{.Names}}'], text=True).split()
    for name in names:
        if '--verify' in sys.argv:
            validation = '''
from crypto import _load_master_key
from storage import AgentStore
from connectors.siem_connector import load_siem_config
from outbound_http import Request, urlopen, OutboundHTTPError
_load_master_key()
store = AgentStore('/app/data/agents.db')
paths = store.get_protected_paths()
audit = store.get_protected_paths_audit_log(limit=1000000)
config = load_siem_config()
try:
    urlopen(Request('http://169.254.169.254/'), timeout=1)
except OutboundHTTPError:
    pass
else:
    raise RuntimeError('Metadata destination was not blocked')
print('key/decryption/metadata-denial PASS; policy rows=' + str(len(paths)) + ', audit rows=' + str(len(audit)))
'''
            result = subprocess.check_output(['docker', 'exec', name, 'python3', '-c', validation], text=True)
            print(name + ': ' + result.strip())
            continue
        code = '''
import json, os
from pathlib import Path
from urllib.parse import urlsplit
p = Path('/app/siem_config.json')
c = json.loads(p.read_text()) if p.exists() else {}
destinations = []
for integration, fields in c.items():
    if not isinstance(fields, dict):
        continue
    for field in ('hec_url','endpoint','bms_url','vsa_url'):
        if fields.get(field):
            u = urlsplit(fields[field])
            destinations.append({'integration':integration,'scheme':u.scheme,'host':u.hostname,'port':u.port,
                                 'enabled':bool(fields.get('enabled')), 'verify_ssl':fields.get('verify_ssl',True)})
print(json.dumps({'key_configured':any(k in os.environ for k in ('ARCKON_MASTER_KEY','ARCKON_MASTER_KEY_FILE')),
                  'legacy_siem':p.exists(),'persistent_siem':Path('/app/data/siem_config.json').exists(),
                  'destinations':destinations}))
'''
        result = subprocess.check_output(['docker', 'exec', name, 'python3', '-c', code], text=True)
        print(name + ': ' + result.strip())


if __name__ == '__main__':
    main()
