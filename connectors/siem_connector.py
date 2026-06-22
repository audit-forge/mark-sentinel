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

import json
import logging
import socket
import time
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

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        # TODO: Hash implements — see docs/HASH_SIEM_TASKS/HASH_SIEM_P01.md
        raise NotImplementedError('Splunk HEC send() — Hash task HASH_SIEM_P01')

    def test(self) -> tuple[bool, str]:
        # TODO: Hash implements
        raise NotImplementedError('Splunk HEC test() — Hash task HASH_SIEM_P01')


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

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        # TODO: Hash implements — see docs/HASH_SIEM_TASKS/HASH_SIEM_P02.md
        raise NotImplementedError('Sentinel send() — Hash task HASH_SIEM_P02')

    def test(self) -> tuple[bool, str]:
        raise NotImplementedError('Sentinel test() — Hash task HASH_SIEM_P02')


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
        # TODO: Hash implements — see docs/HASH_SIEM_TASKS/HASH_SIEM_P03.md
        raise NotImplementedError('QRadar send() — Hash task HASH_SIEM_P03')

    def test(self) -> tuple[bool, str]:
        raise NotImplementedError('QRadar test() — Hash task HASH_SIEM_P03')


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

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        # TODO: Hash implements — see docs/HASH_SIEM_TASKS/HASH_SIEM_P04.md
        raise NotImplementedError('Elastic send() — Hash task HASH_SIEM_P04')

    def test(self) -> tuple[bool, str]:
        raise NotImplementedError('Elastic test() — Hash task HASH_SIEM_P04')


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
        # TODO: Hash implements — see docs/HASH_SIEM_TASKS/HASH_SIEM_P05.md
        raise NotImplementedError('Exabeam send() — Hash task HASH_SIEM_P05')

    def test(self) -> tuple[bool, str]:
        raise NotImplementedError('Exabeam test() — Hash task HASH_SIEM_P05')


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

    def send(self, finding: ArckonFinding) -> tuple[bool, str]:
        # TODO: Hash implements — see docs/HASH_SIEM_TASKS/HASH_SIEM_P06.md
        raise NotImplementedError('Kaseya send() — Hash task HASH_SIEM_P06')

    def test(self) -> tuple[bool, str]:
        raise NotImplementedError('Kaseya test() — Hash task HASH_SIEM_P06')

    def sync_inventory(self, inventory: list[dict]) -> tuple[bool, str]:
        """Sync AI asset inventory to IT Glue Flexible Assets. Hash implements."""
        raise NotImplementedError('Kaseya sync_inventory() — Hash task HASH_SIEM_P06')


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
