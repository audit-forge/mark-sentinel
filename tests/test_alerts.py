import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))
from alerts import AlertConfig, fire_alerts, load_alert_config, should_alert


class TestShouldAlert(unittest.TestCase):
    def _cfg(self, severity='CRITICAL'):
        return AlertConfig(min_severity=severity)

    def test_passes_critical_when_threshold_critical(self):
        report = {'findings': [{'severity': 'CRITICAL', 'check_id': 'X', 'title': 'T', 'status': 'FAIL'}]}
        result = should_alert(report, self._cfg('CRITICAL'))
        self.assertEqual(len(result), 1)

    def test_filters_below_threshold(self):
        report = {'findings': [{'severity': 'LOW', 'check_id': 'X', 'title': 'T', 'status': 'FAIL'}]}
        result = should_alert(report, self._cfg('HIGH'))
        self.assertEqual(len(result), 0)

    def test_empty_findings(self):
        self.assertEqual(should_alert({}, self._cfg()), [])


class TestLoadAlertConfig(unittest.TestCase):
    def test_returns_none_for_missing_file(self):
        self.assertIsNone(load_alert_config(Path('/nonexistent/path.json')))

    def test_loads_valid_config(self, tmp_path=None):
        import tempfile, os
        data = {'webhook_url': 'https://example.com', 'min_severity': 'HIGH'}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            name = f.name
        try:
            cfg = load_alert_config(Path(name))
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg.webhook_url, 'https://example.com')
            self.assertEqual(cfg.min_severity, 'HIGH')
        finally:
            os.unlink(name)


class TestFireAlerts(unittest.TestCase):
    def _report(self):
        return {'findings': [{'severity': 'CRITICAL', 'check_id': 'AI-DEPLOY-001', 'title': 'API key exposed', 'status': 'FAIL'}]}

    @patch('alerts.send_webhook')
    def test_fires_webhook_when_configured(self, mock_wh):
        mock_wh.return_value = True
        cfg = AlertConfig(webhook_url='https://hooks.example.com/x', min_severity='CRITICAL')
        fire_alerts(self._report(), 'dev1', 'host1', cfg)
        mock_wh.assert_called_once()

    @patch('alerts.send_email')
    def test_fires_email_when_configured(self, mock_email):
        mock_email.return_value = True
        cfg = AlertConfig(email_to='sec@example.com', email_from='sentinel@example.com',
                          smtp_host='smtp.example.com', min_severity='CRITICAL')
        fire_alerts(self._report(), 'dev1', 'host1', cfg)
        mock_email.assert_called_once()

    @patch('alerts.send_webhook')
    def test_no_alert_when_below_threshold(self, mock_wh):
        report = {'findings': [{'severity': 'LOW', 'check_id': 'X', 'title': 'T', 'status': 'FAIL'}]}
        cfg = AlertConfig(webhook_url='https://hooks.example.com/x', min_severity='CRITICAL')
        fire_alerts(report, 'dev1', 'host1', cfg)
        mock_wh.assert_not_called()


if __name__ == '__main__':
    unittest.main()
