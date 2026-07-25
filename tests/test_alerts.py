import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
from alerts import (is_valid_slack_webhook, load_alert_config,
                    load_alert_config_for_ui, save_alert_config, send_test_alert)


class TestLoadAlertConfig(unittest.TestCase):
    def test_returns_none_for_missing_file(self):
        self.assertIsNone(load_alert_config(Path('/nonexistent/path.json')))

    def test_loads_valid_config(self, tmp_path=None):
        import tempfile
        import os
        data = {'webhook_url': 'https://example.com'}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            name = f.name
        try:
            cfg = load_alert_config(Path(name))
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg['webhook_url'], 'https://example.com')
        finally:
            os.unlink(name)


class TestSlackWebhookConfig(unittest.TestCase):
    def test_only_accepts_official_slack_webhook_urls(self):
        self.assertTrue(is_valid_slack_webhook('https://hooks.slack.com/services/T000/B000/secret'))
        self.assertFalse(is_valid_slack_webhook('http://hooks.slack.com/services/T000/B000/secret'))
        self.assertFalse(is_valid_slack_webhook('https://example.com/services/T000/B000/secret'))

    def test_ui_never_returns_slack_webhook(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
            json.dump({'slack_webhook': 'https://hooks.slack.com/services/T000/B000/secret'}, f)
            f.flush()
            result = load_alert_config_for_ui(Path(f.name))
        self.assertEqual(result['slack_webhook'], '')
        self.assertTrue(result['slack_webhook_configured'])

    def test_blank_slack_value_preserves_saved_webhook(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
            json.dump({'slack_webhook': 'https://hooks.slack.com/services/T000/B000/secret'}, f)
            f.flush()
            save_alert_config(Path(f.name), {'slack_webhook': ''}, Path(f.name))
            self.assertEqual(load_alert_config(Path(f.name))['slack_webhook'],
                             'https://hooks.slack.com/services/T000/B000/secret')

    def test_test_alert_rejects_invalid_slack_url_without_request(self):
        with patch('alerts.urllib.request.urlopen') as urlopen:
            ok, message = send_test_alert({'slack_webhook': 'https://example.com/secret'}, 'slack')
        self.assertFalse(ok)
        self.assertIn('hooks.slack.com', message)
        urlopen.assert_not_called()

    @patch('alerts._post_slack', return_value=True)
    def test_test_alert_delivers_to_valid_slack_url(self, post_slack):
        ok, message = send_test_alert(
            {'slack_webhook': 'https://hooks.slack.com/services/T000/B000/secret'}, 'slack')
        self.assertTrue(ok)
        self.assertEqual(message, 'Test sent to Slack')
        post_slack.assert_called_once()


if __name__ == '__main__':
    unittest.main()
