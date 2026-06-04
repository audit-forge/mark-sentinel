"""Tests for the alerts delivery module."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import alerts


def _make_config(**kwargs):
    base = {
        'slack_webhook': '',
        'google_chat_webhook': '',
        'webhook_url': '',
        'email': {},
        'triggers': {
            'new_critical': True,
            'new_high': True,
            'new_shadow_ai': True,
            'device_offline': True,
        },
    }
    base.update(kwargs)
    return base


def _report(*findings):
    return {'findings': list(findings)}


def _finding(check_id, severity, status='FAIL'):
    return {'check_id': check_id, 'severity': severity, 'status': status, 'title': f'Test {check_id}'}


class TestLoadAlertConfig(unittest.TestCase):
    def test_missing_file_returns_none(self):
        self.assertIsNone(alerts.load_alert_config(Path('/nonexistent/path.json')))

    def test_loads_valid_config(self):
        data = {'slack_webhook': 'https://hooks.slack.com/x', 'triggers': {}}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            p = Path(f.name)
        try:
            cfg = alerts.load_alert_config(p)
            self.assertEqual(cfg['slack_webhook'], 'https://hooks.slack.com/x')
        finally:
            p.unlink()

    def test_invalid_json_returns_none(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('not json{')
            p = Path(f.name)
        try:
            self.assertIsNone(alerts.load_alert_config(p))
        finally:
            p.unlink()


class TestFormatText(unittest.TestCase):
    def test_critical_finding(self):
        text = alerts._format_text({'event': 'new_critical_finding', 'severity': 'CRITICAL',
                                    'device': 'myhost', 'check_id': 'AI-INP-001', 'title': 'Injection'})
        self.assertIn('CRITICAL', text)
        self.assertIn('myhost', text)
        self.assertIn('AI-INP-001', text)

    def test_shadow_ai(self):
        text = alerts._format_text({'event': 'new_shadow_ai', 'device': 'laptop',
                                    'service': 'ollama', 'host': '192.168.1.5'})
        self.assertIn('Shadow AI', text)
        self.assertIn('ollama', text)

    def test_device_offline(self):
        text = alerts._format_text({'event': 'device_offline', 'device': 'server1',
                                    'hours_offline': 27.5})
        self.assertIn('Offline', text)
        self.assertIn('server1', text)
        self.assertIn('27.5', text)

    def test_test_alert(self):
        text = alerts._format_text({'event': 'test_alert', 'title': 'Test works'})
        self.assertIn('Test works', text)


class TestFireAlerts(unittest.TestCase):
    @patch('alerts._post_slack')
    def test_fires_slack_on_new_critical(self, mock_slack):
        mock_slack.return_value = True
        cfg = _make_config(slack_webhook='https://hooks.slack.com/x')
        report = _report(_finding('AI-INP-001', 'CRITICAL'))
        alerts.fire_alerts(report, 'dev1', 'host1', cfg)
        mock_slack.assert_called_once()

    @patch('alerts._post_google_chat')
    def test_fires_google_chat_on_new_critical(self, mock_gchat):
        mock_gchat.return_value = True
        cfg = _make_config(google_chat_webhook='https://chat.googleapis.com/v1/spaces/xxx/messages?key=yyy')
        report = _report(_finding('AI-INP-001', 'CRITICAL'))
        alerts.fire_alerts(report, 'dev1', 'host1', cfg)
        mock_gchat.assert_called_once()

    @patch('alerts._send_email')
    def test_fires_email_on_new_high(self, mock_email):
        mock_email.return_value = True
        cfg = _make_config(email={'smtp_host': 'smtp.gmail.com', 'smtp_port': 587,
                                  'smtp_user': 'u', 'smtp_pass': 'p',
                                  'from': 'a@b.com', 'to': 'sec@example.com'})
        report = _report(_finding('AI-GOV-001', 'HIGH'))
        alerts.fire_alerts(report, 'dev1', 'host1', cfg)
        mock_email.assert_called_once()

    @patch('alerts._post_slack')
    def test_no_alert_when_trigger_disabled(self, mock_slack):
        cfg = _make_config(slack_webhook='https://hooks.slack.com/x',
                           triggers={'new_critical': False, 'new_high': False})
        report = _report(_finding('AI-INP-001', 'CRITICAL'))
        alerts.fire_alerts(report, 'dev1', 'host1', cfg)
        mock_slack.assert_not_called()

    @patch('alerts._post_slack')
    def test_no_duplicate_alert_for_existing_finding(self, mock_slack):
        cfg = _make_config(slack_webhook='https://hooks.slack.com/x')
        report = _report(_finding('AI-INP-001', 'CRITICAL'))
        mock_store = MagicMock()
        mock_store.get_previous_report.return_value = {
            'findings': [_finding('AI-INP-001', 'CRITICAL')]
        }
        alerts.fire_alerts(report, 'dev1', 'host1', cfg, store=mock_store)
        mock_slack.assert_not_called()


class TestFireStaleDeviceAlert(unittest.TestCase):
    @patch('alerts._post_google_chat')
    def test_fires_when_trigger_enabled(self, mock_gchat):
        mock_gchat.return_value = True
        cfg = _make_config(google_chat_webhook='https://chat.googleapis.com/xxx',
                           triggers={'device_offline': True})
        alerts.fire_stale_device_alert('myserver', 'abc123', 30.0, cfg)
        mock_gchat.assert_called_once()

    @patch('alerts._post_slack')
    def test_skips_when_trigger_disabled(self, mock_slack):
        cfg = _make_config(slack_webhook='https://hooks.slack.com/x',
                           triggers={'device_offline': False})
        alerts.fire_stale_device_alert('myserver', 'abc123', 30.0, cfg)
        mock_slack.assert_not_called()


class TestSendTestAlert(unittest.TestCase):
    @patch('alerts._post_slack')
    def test_slack_test_ok(self, mock_slack):
        mock_slack.return_value = True
        cfg = _make_config(slack_webhook='https://hooks.slack.com/x')
        ok, msg = alerts.send_test_alert(cfg, 'slack')
        self.assertTrue(ok)
        self.assertIn('Slack', msg)

    @patch('alerts._post_google_chat')
    def test_google_chat_test_ok(self, mock_gchat):
        mock_gchat.return_value = True
        cfg = _make_config(google_chat_webhook='https://chat.googleapis.com/xxx')
        ok, msg = alerts.send_test_alert(cfg, 'google_chat')
        self.assertTrue(ok)
        self.assertIn('Google Chat', msg)

    def test_slack_test_no_url(self):
        ok, msg = alerts.send_test_alert(_make_config(), 'slack')
        self.assertFalse(ok)

    def test_google_chat_test_no_url(self):
        ok, msg = alerts.send_test_alert(_make_config(), 'google_chat')
        self.assertFalse(ok)


if __name__ == '__main__':
    unittest.main()
