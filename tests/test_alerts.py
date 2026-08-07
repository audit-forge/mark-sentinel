import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))
from alerts import (is_valid_gchat_webhook, is_valid_slack_webhook,
                    is_valid_teams_webhook, is_valid_url, load_alert_config,
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


class TestGchatWebhookConfig(unittest.TestCase):
    GOOD = (
        'https://chat.googleapis.com/v1/spaces/test-space/messages?key=test-key&token=test-token'
    )

    def test_accepts_valid_google_chat_webhook(self):
        self.assertTrue(is_valid_gchat_webhook(self.GOOD))

    def test_rejects_non_google_chat_urls(self):
        self.assertFalse(is_valid_gchat_webhook('https://example.com/space/messages?key=1&token=2'))
        self.assertFalse(is_valid_gchat_webhook('http://chat.googleapis.com/v1/spaces/ABC/messages?key=1&token=2'))
        self.assertFalse(is_valid_gchat_webhook('https://chat.googleapis.com/v1/spaces/ABC/messages?key=1'))
        self.assertFalse(is_valid_gchat_webhook('https://chat.googleapis.com/v1/spaces/ABC?key=1&token=2'))

    def test_save_rejects_invalid_gchat_url(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
            json.dump({}, f)
            f.flush()
            with self.assertRaises(ValueError) as ctx:
                save_alert_config(Path(f.name), {'gchat_webhook': 'https://example.com'}, Path(f.name))
            self.assertIn('Google Chat webhook', str(ctx.exception))

    @patch('alerts._post_gchat', return_value=True)
    def test_test_alert_delivers_to_valid_gchat_url(self, post_gchat):
        ok, message = send_test_alert({'gchat_webhook': self.GOOD}, 'gchat')
        self.assertTrue(ok)
        self.assertEqual(message, 'Test sent to Google Chat')
        post_gchat.assert_called_once()

    def test_test_alert_rejects_invalid_gchat_url_without_request(self):
        with patch('alerts.urllib.request.urlopen') as urlopen:
            ok, message = send_test_alert({'gchat_webhook': 'https://example.com'}, 'gchat')
        self.assertFalse(ok)
        self.assertIn('chat.googleapis.com', message)
        urlopen.assert_not_called()


class TestTeamsWebhookConfig(unittest.TestCase):
    GOOD = 'https://auditforge.webhook.office.com/webhookb2/aaaa-bbbb-cccc@aaaa-bbbb-cccc/IncomingWebhook/dddddd/aaaa-bbbb-cccc'

    def test_accepts_valid_teams_webhook(self):
        self.assertTrue(is_valid_teams_webhook(self.GOOD))

    def test_rejects_invalid_teams_urls(self):
        self.assertFalse(is_valid_teams_webhook('https://example.com/webhookb2/abc/IncomingWebhook/def'))
        self.assertFalse(is_valid_teams_webhook('http://auditforge.webhook.office.com/webhookb2/abc/IncomingWebhook/def'))
        self.assertFalse(is_valid_teams_webhook('https://auditforge.webhook.office.com/webhookb2/abc'))


class TestGenericWebhookConfig(unittest.TestCase):
    def test_is_valid_url_accepts_https(self):
        self.assertTrue(is_valid_url('https://example.com/alerts'))
        self.assertFalse(is_valid_url('ftp://example.com/alerts'))
        self.assertFalse(is_valid_url('not-a-url'))

    def test_save_rejects_invalid_generic_webhook_url(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
            json.dump({}, f)
            f.flush()
            with self.assertRaises(ValueError) as ctx:
                save_alert_config(Path(f.name), {'webhook_url': 'ftp://example.com'}, Path(f.name))
            self.assertIn('Webhook URL', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
