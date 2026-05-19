"""
M.A.R.K. Sentinel — License enforcement, telemetry, and device monitoring

License file (license.json) sits next to server.py.
Fields:
  customer_id          — unique slug (e.g. "acme-corp")
  licensed_to          — display name
  max_agents           — contracted seat count (0 = unlimited)
  grace_pct            — overage % tolerance before hard-alert (default 10)
  expires_at           — ISO date "YYYY-MM-DD"
  issued_at            — ISO date
  issued_by            — "M.A.R.K. AI Systems"
  webhook_url          — (optional) overage + stale-device alerts → customer channel
  telemetry_url        — (set by M.A.R.K.) rolling usage reports → M.A.R.K. endpoint
  telemetry_interval_h — hours between usage reports (default 24)
  stale_alert_hours    — hours of silence before a device is flagged unreachable (default 26)

Enforcement is always soft — agents are never blocked from reporting.
"""
import json
import logging
import threading
import time
from datetime import date
from pathlib import Path
from typing import Optional
import urllib.request

log = logging.getLogger('sentinel.license')

_UNLIMITED = 0
_DEFAULT_GRACE = 10


class License:
    # plan values: 'standard' (exec+ciso reports only) | 'plus' (full technical+remediation)
    # No license file = defaults to 'plus' so existing installs are unaffected.
    PLAN_STANDARD = 'standard'
    PLAN_PLUS     = 'plus'

    def __init__(self, data: dict):
        self.customer_id          = data.get('customer_id', 'unknown')
        self.licensed_to          = data.get('licensed_to', 'Unknown')
        self.max_agents           = int(data.get('max_agents', _UNLIMITED))
        self.grace_pct            = float(data.get('grace_pct', _DEFAULT_GRACE))
        self.expires_at           = data.get('expires_at', '')
        self.issued_at            = data.get('issued_at', '')
        self.issued_by            = data.get('issued_by', 'M.A.R.K. AI Systems')
        self.webhook_url          = data.get('webhook_url', '')
        self.telemetry_url        = data.get('telemetry_url', '')
        self.telemetry_interval_h = float(data.get('telemetry_interval_h', 24))
        self.stale_alert_hours    = float(data.get('stale_alert_hours', 26))
        self.plan                 = data.get('plan', self.PLAN_PLUS)

    @property
    def has_technical_reports(self) -> bool:
        """True when the license includes Technical reports and remediation steps."""
        return self.plan == self.PLAN_PLUS

    @property
    def unlimited(self) -> bool:
        return self.max_agents == _UNLIMITED

    @property
    def expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            return date.fromisoformat(self.expires_at) < date.today()
        except ValueError:
            return False

    @property
    def days_until_expiry(self) -> Optional[int]:
        if not self.expires_at:
            return None
        try:
            delta = date.fromisoformat(self.expires_at) - date.today()
            return delta.days
        except ValueError:
            return None

    @property
    def grace_limit(self) -> int:
        if self.unlimited:
            return 0
        return int(self.max_agents * (1 + self.grace_pct / 100))

    def check(self, current_count: int) -> str:
        if self.expired:
            return 'expired'
        if self.unlimited:
            return 'unlimited'
        if current_count > self.grace_limit:
            return 'over_grace'
        if current_count > self.max_agents:
            return 'over_limit'
        return 'ok'


# ── Singleton ─────────────────────────────────────────────────────────────────

_license: Optional[License] = None
_license_lock = threading.Lock()


def load_license(path: Path) -> License:
    global _license
    with _license_lock:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
                _license = License(data)
                log.info(
                    'License: %s — %d seats, expires %s, telemetry every %.0fh, stale threshold %.0fh',
                    _license.licensed_to, _license.max_agents,
                    _license.expires_at or 'never',
                    _license.telemetry_interval_h,
                    _license.stale_alert_hours,
                )
            except Exception as e:
                log.warning('Could not parse license.json: %s — running unlimited', e)
                _license = License({})
        else:
            log.info('No license.json — running unlimited (dev/internal mode)')
            _license = License({})
    return _license


def get_license() -> License:
    global _license
    if _license is None:
        with _license_lock:
            if _license is None:
                _license = License({})
    return _license


# ── Overage check (called on new device registration) ────────────────────────

def check_overage(device_id: str, hostname: str, current_count: int, store) -> str:
    lic = get_license()
    status = lic.check(current_count)

    if status in ('over_limit', 'over_grace', 'expired'):
        try:
            store.log_license_event(
                event_type=status,
                device_id=device_id,
                hostname=hostname,
                agent_count=current_count,
                max_agents=lic.max_agents,
            )
        except Exception as e:
            log.error('license event log failed: %s', e)

        log.warning(
            'LICENSE %s — device=%s host=%s count=%d max=%d grace=%d',
            status.upper(), device_id, hostname,
            current_count, lic.max_agents, lic.grace_limit,
        )

        if status == 'over_grace' and lic.webhook_url:
            threading.Thread(
                target=_post,
                args=(lic.webhook_url, {
                    'event':          'sentinel_license_overage',
                    'status':         status,
                    'customer_id':    lic.customer_id,
                    'licensed_to':    lic.licensed_to,
                    'max_agents':     lic.max_agents,
                    'grace_limit':    lic.grace_limit,
                    'current_agents': current_count,
                    'overage':        current_count - lic.max_agents,
                    'new_device_id':  device_id,
                    'new_hostname':   hostname,
                    'timestamp':      _now_iso(),
                }),
                daemon=True,
            ).start()

    return status


# ── Background monitors ───────────────────────────────────────────────────────

def start_monitors(store) -> None:
    """Start telemetry + stale-device background threads. Call once at server startup."""
    lic = get_license()
    if lic.telemetry_url:
        threading.Thread(
            target=_telemetry_loop,
            args=(store,),
            daemon=True,
            name='sentinel-telemetry',
        ).start()
        log.info('Telemetry thread started — reporting every %.0fh to %s',
                 lic.telemetry_interval_h, lic.telemetry_url)
    else:
        log.info('No telemetry_url in license — usage reporting disabled')

    threading.Thread(
        target=_stale_device_loop,
        args=(store,),
        daemon=True,
        name='sentinel-stale-monitor',
    ).start()
    log.info('Stale-device monitor started — threshold %.0fh', lic.stale_alert_hours)


def _telemetry_loop(store) -> None:
    """Post a usage heartbeat to M.A.R.K.'s telemetry endpoint on a schedule."""
    lic = get_license()
    interval = max(3600, lic.telemetry_interval_h * 3600)

    # Initial report fires 60s after startup so the server is fully up
    time.sleep(60)

    while True:
        try:
            _send_telemetry(lic, store)
        except Exception as e:
            log.error('telemetry send failed: %s', e)
        time.sleep(interval)


def _send_telemetry(lic: License, store) -> None:
    current_count = store.device_count()
    status = lic.check(current_count)
    devices = store.get_all_devices_summary()
    now = time.time()

    payload = {
        'event':            'sentinel_usage_heartbeat',
        'customer_id':      lic.customer_id,
        'licensed_to':      lic.licensed_to,
        'max_agents':       lic.max_agents if not lic.unlimited else None,
        'grace_limit':      lic.grace_limit if not lic.unlimited else None,
        'current_agents':   current_count,
        'overage':          max(0, current_count - lic.max_agents) if not lic.unlimited else 0,
        'status':           status,
        'expires_at':       lic.expires_at or None,
        'days_until_expiry': lic.days_until_expiry,
        'timestamp':        _now_iso(),
        'devices': [
            {
                'device_id':    d['device_id'],
                'hostname':     d['hostname'],
                'platform':     d['platform'],
                'last_seen_h':  round((now - d['last_seen']) / 3600, 1),
            }
            for d in devices
        ],
    }

    ok = _post(lic.telemetry_url, payload)
    if ok:
        log.info(
            'Telemetry sent — customer=%s agents=%d/%s status=%s',
            lic.customer_id, current_count,
            str(lic.max_agents) if not lic.unlimited else 'unlimited',
            status,
        )


def _stale_device_loop(store) -> None:
    """Check every hour for devices that haven't reported recently and alert."""
    lic = get_license()
    threshold_s = int(lic.stale_alert_hours * 3600)
    check_interval = 3600  # re-check every hour

    # Track which device_ids we've already alerted on so we don't spam
    alerted: set[str] = set()

    # Give the server 2 minutes to fully start before first check
    time.sleep(120)

    while True:
        try:
            stale = store.get_stale_devices(threshold_s)
            newly_stale = [d for d in stale if d['device_id'] not in alerted]

            if newly_stale:
                log.warning('%d device(s) unreachable (no report in %.0fh)',
                            len(newly_stale), lic.stale_alert_hours)
                for d in newly_stale:
                    hours_silent = (time.time() - d['last_seen']) / 3600
                    log.warning('  STALE device=%s host=%s last_seen=%.1fh ago',
                                d['device_id'], d['hostname'], hours_silent)
                    alerted.add(d['device_id'])

                if lic.webhook_url:
                    threading.Thread(
                        target=_post,
                        args=(lic.webhook_url, {
                            'event':        'sentinel_devices_unreachable',
                            'customer_id':  lic.customer_id,
                            'licensed_to':  lic.licensed_to,
                            'threshold_h':  lic.stale_alert_hours,
                            'stale_count':  len(newly_stale),
                            'devices': [
                                {
                                    'device_id':   d['device_id'],
                                    'hostname':    d['hostname'],
                                    'platform':    d['platform'],
                                    'last_seen_h': round((time.time() - d['last_seen']) / 3600, 1),
                                }
                                for d in newly_stale
                            ],
                            'timestamp': _now_iso(),
                        }),
                        daemon=True,
                    ).start()

            # Clear alerted set for devices that have come back online
            current_stale_ids = {d['device_id'] for d in stale}
            recovered = alerted - current_stale_ids
            if recovered:
                for device_id in recovered:
                    log.info('Device recovered: %s', device_id)
                alerted -= recovered

                if lic.webhook_url and recovered:
                    threading.Thread(
                        target=_post,
                        args=(lic.webhook_url, {
                            'event':           'sentinel_devices_recovered',
                            'customer_id':     lic.customer_id,
                            'recovered_count': len(recovered),
                            'device_ids':      list(recovered),
                            'timestamp':       _now_iso(),
                        }),
                        daemon=True,
                    ).start()

        except Exception as e:
            log.error('stale device monitor error: %s', e)

        time.sleep(check_interval)


# ── Summary (dashboard + admin API) ──────────────────────────────────────────

def license_summary(store) -> dict:
    lic = get_license()
    current_count = store.device_count()
    status = lic.check(current_count)
    return {
        'customer_id':      lic.customer_id,
        'licensed_to':      lic.licensed_to,
        'max_agents':       lic.max_agents if not lic.unlimited else None,
        'grace_limit':      lic.grace_limit if not lic.unlimited else None,
        'current_agents':   current_count,
        'overage':          max(0, current_count - lic.max_agents) if not lic.unlimited else 0,
        'status':           status,
        'expires_at':       lic.expires_at or None,
        'days_until_expiry': lic.days_until_expiry,
        'unlimited':        lic.unlimited,
        'recent_events':    store.get_license_events(limit=50),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _post(url: str, payload: dict) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={'Content-Type': 'application/json', 'User-Agent': 'sentinel-license/1.0'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        log.error('POST to %s failed: %s', url, e)
        return False
