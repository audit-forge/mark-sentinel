"""
Arckon by RiskRaven — SIEM & Tool Integration Connectors

Skeleton + dispatch layer. Each connector class defines the interface;
Hash implements the send() and test() methods per task spec in docs/HASH_SIEM_TASKS/.

Config file: siem_config.json (sits next to server.py)
See siem_config.json.example for the full schema.

Connector classes:
  SplunkHECConnector    — Splunk HTTP Event Collector
  SentinelConnector     — Microsoft Sentinel Log Analytics
  QRadarConnector       — IBM QRadar via CEF/syslog
  ElasticConnector      — Elastic Security via REST API
  ExabeamConnector      — Exabeam via CEF/syslog
  KaseyaConnector       — Kaseya VSA / BMS / IT Glue

Dispatch:
  send_finding(finding, cfg)   — route one finding to all enabled SIEMs
  send_report(report, cfg)     — route all findings in a report
  test_connection(siem, cfg)   — test a specific connector, return (ok, message)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import socket
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger('arckon.siem')

_SIEM_CONFIG_PATH = Path(__file__).parent.parent / 'siem_config.json'


# ── Config ────────────────────────────────────────────────────────────────────

def load_siem_config(path: Path | None = None) -> dict:
    p = path or _SIEM_CONFIG_PATH
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception as e:
        log.error('siem config load error: %s', e)
        return {}


def save_siem_config(data: dict, path: Path | None = None) -> None:
    p = path or _SIEM_CONFIG_PATH
    p.write_text(json.dumps(data, indent=2), encoding='utf-8')


def load_siem_config_for_ui(path: Path | None = None) -> dict:
    """Return config with secrets masked for browser display."""
    cfg = load_siem_config(path)
    _SECRETS = {'hec_token', 'shared_key', 'api_key', 'vsa_api_key',
                'bms_api_key', 'itglue_api_key', 'password'}
    def mask(obj):
        if isinstance(obj, dict):
            return {k: ('__set__' if k in _SECRETS and v else v if k not in _SECRETS else '')
                    for k, v in obj.items()}
        return obj
    return {siem: mask(vals) for siem, vals in cfg.items()}


# ── Finding normaliser ────────────────────────────────────────────────────────

@dataclass
class ArckonFinding:
    """Normalised finding passed to every connector."""
    check_id:    str = ''
    title:       str = ''
    severity:    str = ''       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    status:      str = ''       # FAIL / WARN / PASS
    category:    str = ''       # AI-DEPLOY, AI-GOV, etc.
    details:     str = ''
    remediation: str = ''
    frameworks:  dict = field(default_factory=dict)
    device_id:   str = ''
    hostname:    str = ''
    customer_id: str = ''
    scan_date:   str = ''
    profile:     str = ''
    risk_score:  int = 0

    @classmethod
    def from_result(cls, result: dict, device_id: str = '', hostname: str = '',
                    customer_id: str = '', scan_date: str = '', profile: str = '') -> 'ArckonFinding':
        sev_to_score = {'CRITICAL': 95, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25, 'INFO': 5}
        sev = result.get('severity', 'INFO').upper()
        return cls(
            check_id    = result.get('check_id', ''),
            title       = result.get('title', ''),
            severity    = sev,
            status      = result.get('status', '').upper(),
            category    = result.get('category', ''),
            details     = result.get('details', ''),
            remediation = result.get('remediation', ''),
            frameworks  = result.get('frameworks', {}),
            device_id   = device_id,
            hostname    = hostname,
            customer_id = customer_id,
            scan_date   = scan_date,
            profile     = profile,
            risk_score  = sev_to_score.get(sev, 5),
        )

    def to_cef(self) -> str:
        """Common Event Format string for syslog-based SIEMs (QRadar, Exabeam)."""
        sev_map = {'CRITICAL': 10, 'HIGH': 8, 'MEDIUM': 5, 'LOW': 3, 'INFO': 1}
        cef_sev = sev_map.get(self.severity, 1)
        fw_str  = '; '.join(f'{k}:{v}' for k, v in self.frameworks.items())
        ext = (
            f'cs1={self.customer_id} cs1Label=Customer '
            f'cs2={self.check_id} cs2Label=CheckID '
            f'cs3={self.category} cs3Label=Category '
            f'cs4={fw_str[:255]} cs4Label=Frameworks '
            f'cn1={self.risk_score} cn1Label=RiskScore '
            f'deviceHostname={self.hostname} '
            f'src={self.device_id} '
            f'msg={self.details[:500].replace("|", "-").replace("\\n", " ")}'
        )
        title_safe = self.title.replace('|', '-')
        return (
            f'CEF:0|RiskRaven|Arckon|1.0|{self.check_id}|{title_safe}|{cef_sev}|{ext}'
        )

    def to_splunk_event(self) -> dict:
        """Splunk HEC event envelope."""
        return {
            'time':       int(time.time()),
            'sourcetype': 'arckon:finding',
            'source':     'arckon',
            'host':       self.hostname or self.device_id,
            'event': {
                'check_id':    self.check_id,
                'title':       self.title,
                'severity':    self.severity,
                'status':      self.status,
                'category':    self.category,
                'details':     self.details,
                'frameworks':  self.frameworks,
                'device_id':   self.device_id,
                'hostname':    self.hostname,
                'customer_id': self.customer_id,
                'scan_date':   self.scan_date,
                'profile':     self.profile,
                'risk_score':  self.risk_score,
                'vendor':      'RiskRaven',
                'product':     'Arckon',
            },
        }

    def to_ecs(self) -> dict:
        """Elastic Common Schema document for Elasticsearch indexing."""
        return {
            '@timestamp':        self.scan_date or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'event.kind':        'alert',
            'event.category':    ['intrusion_detection'],
            'event.type':        ['info'],
            'event.dataset':     'arckon.finding',
            'event.module':      'arckon',
            'event.outcome':     'failure' if self.status == 'FAIL' else 'success',
            'rule.id':           self.check_id,
            'rule.name':         self.title,
            'rule.category':     self.category,
            'vulnerability.severity': self.severity.lower(),
            'host.name':         self.hostname,
            'host.id':           self.device_id,
            'labels.customer':   self.customer_id,
            'labels.profile':    self.profile,
            'labels.risk_score': self.risk_score,
            'message':           self.details,
            'arckon.check_id':   self.check_id,
            'arckon.category':   self.category,
            'arckon.frameworks': self.frameworks,
            'arckon.remediation':self.remediation,
        }

    def to_sentinel_record(self) -> dict:
        """Record for Azure Monitor / Microsoft Sentinel Log Analytics."""
        return {
            'TimeGenerated':    self.scan_date or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'CheckId':          self.check_id,
            'Title':            self.title,
            'Severity':         self.severity,
            'Status':           self.status,
            'Category':         self.category,
            'Details':          self.details,
            'Frameworks':       json.dumps(self.frameworks),
            'Remediation':      self.remediation,
            'DeviceId':         self.device_id,
            'Hostname':         self.hostname,
            'CustomerId':       self.customer_id,
            'ScanDate':         self.scan_date,
            'Profile':          self.profile,
            'RiskScore':        self.risk_score,
            'Vendor':           'RiskRaven',
            'Product':          'Arckon',
        }


# ── Base connector ─────────────────────────────────────────────────────────────

class BaseSiemConnector:
    siem_id:   str = ''
    siem_name: str = ''

    def __init__(self, cfg: dict):
        self.cfg     = cfg
        self.enabled = bool(cfg.get('enabled', False))

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        """Send one finding. Returns (success, message). Hash implements this."""
        raise NotImplementedError(f'{self.siem_name} send() not yet implemented — see HASH_SIEM_TASKS/')

    def test(self) -> tuple[bool, str]:
        """Test connectivity. Returns (ok, message). Hash implements this."""
        raise NotImplementedError(f'{self.siem_name} test() not yet implemented — see HASH_SIEM_TASKS/')

    def _severity_filter(self, finding: ArckonFinding) -> bool:
        """Return True if this finding's severity passes the configured filter."""
        send_on = {s.upper() for s in self.cfg.get('send_on', ['critical', 'high'])}
        return finding.severity.upper() in send_on or finding.status.upper() == 'FAIL'


# ── Splunk HEC ────────────────────────────────────────────────────────────────

class SplunkHECConnector(BaseSiemConnector):
    """
    Sends findings to Splunk via HTTP Event Collector (HEC).

    Config keys:
      hec_url     — e.g. https://splunk.example.com:8088
      hec_token   — HEC token (SPLUNK_HEC_TOKEN env fallback)
      index       — target Splunk index (default: arckon)
      sourcetype  — sourcetype label (default: arckon:finding)
      send_on     — severities to forward (default: [critical, high])
      verify_ssl  — bool, default true

    Hash task: HASH_SIEM_P01
    """
    siem_id   = 'splunk'
    siem_name = 'Splunk HEC'

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.cfg.get('verify_ssl', True):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

    def _post(self, payload: dict) -> tuple[int, str]:
        url = f"{self.cfg['hec_url'].rstrip('/')}/services/collector/event"
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Authorization', f"Splunk {self.cfg['hec_token']}")
        req.add_header('Content-Type', 'application/json')
        ctx = self._ssl_context()
        try:
            resp = urllib.request.urlopen(req, context=ctx)
            return resp.status, resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace') if e.fp else ''
            return e.code, body

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        cfg = self.cfg
        payload = finding.to_splunk_event()
        if cfg.get('index'):
            payload['index'] = cfg['index']
        if cfg.get('sourcetype'):
            payload['sourcetype'] = cfg['sourcetype']
        status, body = self._post(payload)
        if status != 200:
            return False, f"{status} {body}"
        try:
            resp_json = json.loads(body)
            if resp_json.get('code') != 0:
                return False, f"{status} {body}"
        except (json.JSONDecodeError, KeyError):
            pass
        return True, 'sent'

    def test(self) -> tuple[bool, str]:
        index = self.cfg.get('index', 'arckon')
        payload = {'event': 'arckon-test', 'sourcetype': 'arckon:finding'}
        if self.cfg.get('index'):
            payload['index'] = index
        status, body = self._post(payload)
        if status != 200:
            return False, f"HTTP {status}: {body[:200]}"
        try:
            resp_json = json.loads(body)
            if resp_json.get('code') != 0:
                return False, f"HTTP {status}: {body[:200]}"
        except (json.JSONDecodeError, KeyError):
            pass
        return True, f"Splunk HEC reachable — index: {index}"


# ── Microsoft Sentinel ────────────────────────────────────────────────────────

class SentinelConnector(BaseSiemConnector):
    """
    Sends findings to Microsoft Sentinel via Azure Monitor HTTP Data Collector API.

    Config keys:
      workspace_id  — Log Analytics workspace ID
      shared_key    — primary or secondary workspace key
      log_type      — custom log table name (default: ArckonFindings)
      send_on       — severities to forward

    Hash task: HASH_SIEM_P02
    """
    siem_id   = 'sentinel'
    siem_name = 'Microsoft Sentinel'

    def _build_signature(self, date_string: str, content_length: int) -> str:
        shared_key = self.cfg['shared_key']
        string_to_sign = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date_string}\n/api/logs"
        )
        decoded_key = base64.b64decode(shared_key)
        sig = hmac.new(decoded_key, string_to_sign.encode('utf-8'), hashlib.sha256).digest()
        return base64.b64encode(sig).decode()

    def _post(self, body: list[dict]) -> tuple[int, str]:
        workspace_id = self.cfg['workspace_id']
        log_type = self.cfg.get('log_type', 'ArckonFindings')
        data = json.dumps(body).encode('utf-8')
        date_string = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
        signature = self._build_signature(date_string, len(data))
        url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('Log-Type', log_type)
        req.add_header('x-ms-date', date_string)
        req.add_header('Authorization', f'SharedKey {workspace_id}:{signature}')
        try:
            resp = urllib.request.urlopen(req)
            return resp.status, resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode('utf-8', errors='replace') if e.fp else ''
            return e.code, resp_body

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        log_type = self.cfg.get('log_type', 'ArckonFindings')
        body = [finding.to_sentinel_record()]
        status, resp = self._post(body)
        if status == 200:
            return True, f'sent to {log_type}'
        return False, f'HTTP {status}'

    def test(self) -> tuple[bool, str]:
        log_type = self.cfg.get('log_type', 'ArckonFindings')
        body = [{
            'TimeGenerated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'CheckId': 'TEST',
            'Title': 'Arckon connectivity test',
        }]
        status, resp = self._post(body)
        if status == 200:
            return True, f'Sentinel workspace reachable — table: {log_type}'
        return False, f'HTTP {status}'


# ── Syslog Helpers ──────────────────────────────────────────────────────────

def _wrap_cef_in_syslog(cef_string: str) -> bytes:
    priority = (1 * 8) + 5  # user facility, notice severity
    ts = time.strftime('%b %d %H:%M:%S')
    host = socket.gethostname()
    return f'<{priority}>{ts} {host} Arckon: {cef_string}\n'.encode('utf-8')

def _send_syslog_message(host: str, port: int, protocol: str, message: bytes) -> tuple[bool, str]:
    try:
        if protocol == 'udp':
            msg = message[:1024]  # Truncate for UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(msg, (host, port))
            finally:
                sock.close()
        else: # tcp
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            try:
                sock.connect((host, port))
                sock.sendall(message)
            finally:
                sock.close()
        return True, f'sent via {protocol}'
    except Exception as e:
        return False, str(e)


# ── IBM QRadar ────────────────────────────────────────────────────────────────

class QRadarConnector(BaseSiemConnector):
    """
    Sends findings to IBM QRadar via CEF-formatted syslog (TCP or UDP).

    Config keys:
      syslog_host  — QRadar syslog receiver host
      syslog_port  — port (default: 514)
      protocol     — 'tcp' or 'udp' (default: tcp)
      send_on      — severities to forward

    Hash task: HASH_SIEM_P03
    """
    siem_id   = 'qradar'
    siem_name = 'IBM QRadar'

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        cef = finding.to_cef()
        message = _wrap_cef_in_syslog(cef)
        host = self.cfg['syslog_host']
        port = int(self.cfg.get('syslog_port', 514))
        protocol = self.cfg.get('protocol', 'tcp').lower()
        return _send_syslog_message(host, port, protocol, message)

    def test(self) -> tuple[bool, str]:
        cef = 'CEF:0|RiskRaven|Arckon|1.0|TEST|Arckon Connectivity Test|1|msg=test'
        message = _wrap_cef_in_syslog(cef)
        host = self.cfg['syslog_host']
        port = int(self.cfg.get('syslog_port', 514))
        protocol = self.cfg.get('protocol', 'tcp').lower()
        ok, msg = _send_syslog_message(host, port, protocol, message)
        if ok:
            return True, f'QRadar syslog reachable at {host}:{port}'
        return False, msg


# ── Elastic Security ──────────────────────────────────────────────────────────

class ElasticConnector(BaseSiemConnector):
    """
    Sends findings to Elasticsearch (Elastic Security / Elastic SIEM)
    via the REST API using ECS-mapped documents.

    Config keys:
      endpoint    — e.g. https://elasticsearch.example.com:9200
      api_key     — Elasticsearch API key (base64 encoded id:api_key)
      index       — target index (default: arckon-findings)
      send_on     — severities to forward
      verify_ssl  — bool, default true

    Hash task: HASH_SIEM_P04
    """
    siem_id   = 'elastic'
    siem_name = 'Elastic Security'

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.cfg.get('verify_ssl', True):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

    def _request(self, method: str, path: str, body: bytes | None = None) -> tuple[int, str]:
        url = f"{self.cfg['endpoint'].rstrip('/')}{path}"
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header('Content-Type', 'application/json')
        req.add_header('Authorization', f"ApiKey {self.cfg['api_key']}")
        ctx = self._ssl_context()
        try:
            resp = urllib.request.urlopen(req, context=ctx)
            return resp.status, resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode('utf-8', errors='replace') if e.fp else ''
            return e.code, resp_body

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        index = self.cfg.get('index', 'arckon-findings')
        ts = finding.scan_date or time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        doc_id = f"{finding.check_id}-{finding.device_id}-{ts}"
        data = json.dumps(finding.to_ecs()).encode('utf-8')
        status, body = self._request('PUT', f'/{index}/_doc/{doc_id}', data)
        if status in (200, 201):
            return True, f'indexed to {index}'
        return False, f'HTTP {status}'

    def test(self) -> tuple[bool, str]:
        status, body = self._request('GET', '/_cluster/health')
        if status == 200:
            try:
                info = json.loads(body)
                return True, f"Elasticsearch reachable — cluster: {info['cluster_name']}, status: {info['status']}"
            except (json.JSONDecodeError, KeyError):
                return True, 'Elasticsearch reachable'
        return False, f'HTTP {status}: {body[:200]}'


# ── Exabeam ───────────────────────────────────────────────────────────────────

class ExabeamConnector(BaseSiemConnector):
    """
    Sends findings to Exabeam via CEF-formatted syslog.
    Shares the CEF formatter with QRadar; only the target host differs.

    Config keys:
      syslog_host  — Exabeam syslog receiver host
      syslog_port  — port (default: 514)
      protocol     — 'tcp' or 'udp' (default: udp)
      send_on      — severities to forward

    Hash task: HASH_SIEM_P05
    """
    siem_id   = 'exabeam'
    siem_name = 'Exabeam'

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        cef = finding.to_cef()
        message = _wrap_cef_in_syslog(cef)
        host = self.cfg['syslog_host']
        port = int(self.cfg.get('syslog_port', 514))
        protocol = self.cfg.get('protocol', 'udp').lower()
        return _send_syslog_message(host, port, protocol, message)

    def test(self) -> tuple[bool, str]:
        cef = 'CEF:0|RiskRaven|Arckon|1.0|TEST|Arckon Connectivity Test|1|msg=test'
        message = _wrap_cef_in_syslog(cef)
        host = self.cfg['syslog_host']
        port = int(self.cfg.get('syslog_port', 514))
        protocol = self.cfg.get('protocol', 'udp').lower()
        ok, msg = _send_syslog_message(host, port, protocol, message)
        if ok:
            return True, f'Exabeam syslog reachable at {host}:{port}'
        return False, msg


# ── Kaseya ────────────────────────────────────────────────────────────────────

class KaseyaConnector(BaseSiemConnector):
    """
    Kaseya integration — three sub-integrations in one connector:
      1. VSA: deploy/monitor Arckon agents via Agent Procedures
      2. BMS: create tickets from CRITICAL/HIGH findings via BMS REST API
      3. IT Glue: sync AI inventory to Flexible Assets per client org

    Config keys:
      vsa_url         — Kaseya VSA base URL
      vsa_api_key     — VSA REST API key
      bms_url         — Kaseya BMS base URL
      bms_api_key     — BMS REST API key
      itglue_api_key  — IT Glue API key
      itglue_org_id   — IT Glue organisation ID (one per client)
      ticket_queue    — BMS queue name for Arckon tickets
      send_on         — severities to forward (creates BMS tickets)

    Hash task: HASH_SIEM_P06
    """
    siem_id   = 'kaseya'
    siem_name = 'Kaseya'

    def _kaseya_request(self, method: str, url: str, headers: dict, body: dict | None = None) -> tuple[int, str]:
        data = json.dumps(body).encode('utf-8') if body else None
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            resp = urllib.request.urlopen(req)
            return resp.status, resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode('utf-8', errors='replace') if e.fp else ''
            return e.code, resp_body
        except Exception as e:
            return 500, str(e)

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        bms_url = self.cfg.get('bms_url')
        bms_api_key = self.cfg.get('bms_api_key')
        if not bms_url or not bms_api_key:
            return False, "Kaseya BMS not configured: bms_url or bms_api_key missing"

        if finding.severity.upper() not in ('CRITICAL', 'HIGH'):
            return True, "finding severity not critical/high for ticketing in Kaseya BMS"

        priority_map = {'CRITICAL': 'Critical', 'HIGH': 'High'}
        priority = priority_map.get(finding.severity.upper(), 'Medium')
        queue = self.cfg.get('ticket_queue', 'Security')

        ticket_body = {
            "summary": f"Arckon: {finding.title} on {finding.hostname or finding.device_id}",
            "description": f"{finding.details}\n\nRemediation:\n{finding.remediation}",
            "priority": priority,
            "queue": queue,
            "source": "Arckon by RiskRaven",
            "customFields": {
                "CheckID": finding.check_id,
                "Customer": finding.customer_id,
                "RiskScore": finding.risk_score
            }
        }

        headers = {
            "Authorization": f"Bearer {bms_api_key}",
            "Content-Type": "application/json"
        }
        url = f"{bms_url.rstrip('/')}/api/v1/servicetickets"
        
        status, body = self._kaseya_request('POST', url, headers, ticket_body)

        if status in (200, 201):
            try:
                resp_json = json.loads(body)
                ticket_id = resp_json.get('id', 'UNKNOWN')
                return True, f"ticket created: {ticket_id}"
            except json.JSONDecodeError:
                return False, f"BMS API returned invalid JSON: {body[:200]}"
        return False, f"HTTP {status}: {body[:200]}"

    def test(self) -> tuple[bool, str]:
        bms_url = self.cfg.get('bms_url')
        bms_api_key = self.cfg.get('bms_api_key')
        vsa_url = self.cfg.get('vsa_url')
        vsa_api_key = self.cfg.get('vsa_api_key')

        if bms_url and bms_api_key:
            headers = {"Authorization": f"Bearer {bms_api_key}"}
            url = f"{bms_url.rstrip('/')}/api/v1/queues"
            status, body = self._kaseya_request('GET', url, headers)
            if status == 200:
                return True, "Kaseya BMS reachable"
            return False, f"BMS HTTP {status}: {body[:200]}"
        elif vsa_url and vsa_api_key:
            headers = {"Authorization": f"Bearer {vsa_api_key}"}
            url = f"{vsa_url.rstrip('/')}/api/v1.0/system/sessionId"
            status, body = self._kaseya_request('GET', url, headers)
            if status == 200:
                return True, "Kaseya VSA reachable"
            return False, f"VSA HTTP {status}: {body[:200]}"
        return False, "Neither BMS nor VSA configured for testing"

    def sync_inventory(self, inventory: list[dict]) -> tuple[bool, str]:
        itglue_api_key = self.cfg.get('itglue_api_key')
        itglue_org_id = self.cfg.get('itglue_org_id')
        if not itglue_api_key or not itglue_org_id:
            return False, "IT Glue not configured: itglue_api_key or itglue_org_id missing"

        itglue_base = "https://api.itglue.com"
        headers = {"x-api-key": itglue_api_key, "Content-Type": "application/json"}
        synced_count = 0
        
        # Step 1: Find or create "AI Inventory" Flexible Asset Type
        asset_type_id = None
        url = f"{itglue_base}/flexible_asset_types?filter[name]=AI+Inventory"
        status, body = self._kaseya_request('GET', url, headers)
        if status == 200:
            try:
                resp_json = json.loads(body)
                if resp_json.get('data'):
                    asset_type_id = resp_json['data'][0]['id']
                else:
                    # Create asset type
                    create_type_body = {
                        "data": {
                            "type": "flexible_asset_types",
                            "attributes": {
                                "name": "AI Inventory",
                                "description": "Arckon AI Inventory Assets"
                            },
                            "relationships": {
                                "flexible_asset_fields": {
                                    "data": [
                                        {"type": "flexible_asset_fields", "attributes": {"name": "Service", "field_type": "Text"}},
                                        {"type": "flexible_asset_fields", "attributes": {"name": "Vendor", "field_type": "Text"}},
                                        {"type": "flexible_asset_fields", "attributes": {"name": "Risk", "field_type": "Text"}},
                                        {"type": "flexible_asset_fields", "attributes": {"name": "Status", "field_type": "Text"}},
                                        {"type": "flexible_asset_fields", "attributes": {"name": "First Seen", "field_type": "Date"}},
                                        {"type": "flexible_asset_fields", "attributes": {"name": "Last Seen", "field_type": "Date"}}
                                    ]
                                }
                            }
                        }
                    }
                    url = f"{itglue_base}/flexible_asset_types"
                    status, body = self._kaseya_request('POST', url, headers, create_type_body)
                    if status in (200, 201):
                        try:
                            resp_json = json.loads(body)
                            asset_type_id = resp_json['data']['id']
                        except json.JSONDecodeError:
                            return False, f"IT Glue asset type create returned invalid JSON: {body[:200]}"
                    else:
                        return False, f"IT Glue asset type creation failed: HTTP {status}: {body[:200]}"
            except json.JSONDecodeError:
                return False, f"IT Glue asset type search returned invalid JSON: {body[:200]}"
        else:
            return False, f"IT Glue asset type search failed: HTTP {status}: {body[:200]}"

        if not asset_type_id:
            return False, "Failed to obtain IT Glue Flexible Asset Type ID for AI Inventory."

        # Step 2: For each item in inventory, create Flexible Asset
        for item in inventory:
            asset_body = {
                "data": {
                    "type": "flexible_assets",
                    "attributes": {
                        "name": item.get('name', 'Unknown Asset'),
                        "traits": {
                            "Service": item.get('service', ''),
                            "Vendor": item.get('vendor', ''),
                            "Risk": item.get('risk_level', ''),
                            "Status": item.get('status', ''),
                            "First Seen": item.get('first_seen', ''),
                            "Last Seen": item.get('last_seen', '')
                        }
                    },
                    "relationships": {
                        "organization": {
                            "data": {
                                "type": "organizations",
                                "id": itglue_org_id
                            }
                        },
                        "flexible_asset_type": {
                            "data": {
                                "type": "flexible_asset_types",
                                "id": asset_type_id
                            }
                        }
                    }
                }
            }
            url = f"{itglue_base}/flexible_assets"
            status, body = self._kaseya_request('POST', url, headers, asset_body)
            if status in (200, 201):
                synced_count += 1
            else:
                log.warning(f"IT Glue sync failed for asset {item.get('name')}: HTTP {status}: {body[:200]}")

        return True, f"synced {synced_count} assets to IT Glue"


# ── Registry & dispatch ───────────────────────────────────────────────────────

_CONNECTORS: dict[str, type[BaseSiemConnector]] = {
    'splunk':   SplunkHECConnector,
    'sentinel': SentinelConnector,
    'qradar':   QRadarConnector,
    'elastic':  ElasticConnector,
    'exabeam':  ExabeamConnector,
    'kaseya':   KaseyaConnector,
}


def _build_connectors(cfg: dict) -> list[BaseSiemConnector]:
    """Return enabled connector instances from config."""
    result = []
    for siem_id, cls in _CONNECTORS.items():
        siem_cfg = cfg.get(siem_id, {})
        if siem_cfg.get('enabled'):
            result.append(cls(siem_cfg))
    return result


def send_finding(finding: ArckonFinding, cfg: dict | None = None) -> None:
    """Dispatch one finding to all enabled SIEM connectors (non-blocking)."""
    if cfg is None:
        cfg = load_siem_config()
    if not cfg:
        return
    for connector in _build_connectors(cfg):
        if not connector._severity_filter(finding):
            continue
        try:
            ok, msg = connector.send(finding)
            if ok:
                log.debug('%s: sent %s', connector.siem_name, finding.check_id)
            else:
                log.warning('%s: send failed — %s', connector.siem_name, msg)
        except NotImplementedError:
            pass  # connector not yet implemented by Hash
        except Exception as e:
            log.error('%s: unexpected error: %s', connector.siem_name, e)


def send_report(report: dict, device_id: str = '', hostname: str = '',
                customer_id: str = '', cfg: dict | None = None) -> None:
    """Dispatch all FAIL/WARN findings in a report to enabled SIEMs."""
    if cfg is None:
        cfg = load_siem_config()
    if not cfg:
        return
    results = report.get('results', [])
    scan_date = report.get('scan_date', '')
    profile   = report.get('profile', '')
    connectors = _build_connectors(cfg)
    if not connectors:
        return
    for r in results:
        if r.get('status', '').upper() not in ('FAIL', 'WARN'):
            continue
        finding = ArckonFinding.from_result(
            r, device_id=device_id, hostname=hostname,
            customer_id=customer_id, scan_date=scan_date, profile=profile,
        )
        for connector in connectors:
            if not connector._severity_filter(finding):
                continue
            try:
                ok, msg = connector.send(finding)
                if not ok:
                    log.warning('%s: %s', connector.siem_name, msg)
            except NotImplementedError:
                pass
            except Exception as e:
                log.error('%s: %s', connector.siem_name, e)


def test_connection(siem_id: str, cfg: dict | None = None) -> tuple[bool, str]:
    """Test a specific SIEM connector. Returns (ok, message)."""
    if cfg is None:
        cfg = load_siem_config()
    cls = _CONNECTORS.get(siem_id)
    if not cls:
        return False, f'Unknown SIEM: {siem_id}'
    siem_cfg = cfg.get(siem_id, {})
    connector = cls(siem_cfg)
    try:
        return connector.test()
    except NotImplementedError:
        return False, f'{connector.siem_name} connector not yet implemented — Hash task pending'
    except Exception as e:
        return False, str(e)
