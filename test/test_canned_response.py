"""
Tests for alerts._build_canned_response() — pure function, no network,
no mock server needed. Covers the rich case (all fields present) and the
graceful-degradation case (missing fields), since this feeds chat
messages, PSA tickets, and Notion pages alike and must never crash or
emit a literal "None" into a customer-facing notification.

Run: pytest test/test_canned_response.py -v
"""
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import alerts  # noqa: E402


_RICH_PAYLOAD = {
    'severity': 'CRITICAL',
    'device': 'DESKTOP-FIN02',
    'check_id': 'AI-DEPLOY-001',
    'title': 'API keys found in repository',
    'category': 'AI-DEPLOY',
    'details': 'A hardcoded OpenAI API key was found in config/settings.py.',
    'remediation': 'Revoke the exposed key immediately and rotate to a secrets manager.',
    'frameworks': {'NIST AI RMF': 'GOVERN 1.2', 'CMMC': 'AC.L2-3.1.1'},
}

_MINIMAL_PAYLOAD = {
    'severity': 'CRITICAL',
    'device': 'srv-prod-01',
    'check_id': 'AI-INP-004',
    'title': 'Prompt injection probe succeeded',
    'category': 'AI-INP',
    'details': '',
    'remediation': '',
    'frameworks': {},
}


class TestBuildCannedResponse:
    def test_returns_all_four_keys(self):
        resp = alerts._build_canned_response(_RICH_PAYLOAD)
        assert set(resp.keys()) == {'summary', 'detail_text', 'body_text', 'body_markdown'}

    def test_rich_payload_includes_all_content(self):
        resp = alerts._build_canned_response(_RICH_PAYLOAD)
        assert 'AI-DEPLOY-001' in resp['body_text']
        assert 'API keys found in repository' in resp['body_text']
        assert 'AI-DEPLOY' in resp['body_text']
        assert 'hardcoded OpenAI API key' in resp['body_text']
        assert 'NIST AI RMF: GOVERN 1.2' in resp['body_text']
        assert 'CMMC: AC.L2-3.1.1' in resp['body_text']
        assert 'Revoke the exposed key' in resp['body_text']

    def test_rich_payload_never_shows_login_fallback(self):
        resp = alerts._build_canned_response(_RICH_PAYLOAD)
        assert 'Log in to RiskRaven' not in resp['body_text']

    def test_minimal_payload_falls_back_without_crashing(self):
        resp = alerts._build_canned_response(_MINIMAL_PAYLOAD)
        assert 'Log in to RiskRaven: Arckon' in resp['body_text']

    def test_minimal_payload_never_prints_none_or_empty_labels(self):
        resp = alerts._build_canned_response(_MINIMAL_PAYLOAD)
        for text in (resp['body_text'], resp['body_markdown'], resp['detail_text']):
            assert 'None' not in text
            assert 'What we found:' not in text  # details empty -> line omitted entirely
            assert 'Mapped controls:' not in text  # frameworks empty -> line omitted entirely

    def test_empty_payload_does_not_raise(self):
        resp = alerts._build_canned_response({})
        assert isinstance(resp['body_text'], str)
        assert 'Log in to RiskRaven: Arckon' in resp['body_text']

    def test_detail_text_omits_the_summary_device_line(self):
        """detail_text is for callers (like _format_text) that render
        their own header — it must not duplicate the summary line that
        body_text/body_markdown include for self-contained callers."""
        resp = alerts._build_canned_response(_RICH_PAYLOAD)
        assert 'on DESKTOP-FIN02' not in resp['detail_text']
        assert 'on DESKTOP-FIN02' in resp['body_text']

    def test_markdown_bolds_only_labels_not_values(self):
        resp = alerts._build_canned_response(_RICH_PAYLOAD)
        md = resp['body_markdown']
        assert '**Category:** AI-DEPLOY' in md
        assert '**AI-DEPLOY**' not in md  # value itself must not be bolded
        assert '**Recommended fix:** Revoke the exposed key immediately and rotate to a secrets manager.' in md

    def test_high_severity_uses_high_prefix(self):
        payload = {**_MINIMAL_PAYLOAD, 'severity': 'HIGH'}
        resp = alerts._build_canned_response(payload)
        assert resp['summary'].startswith('HIGH Finding')


class TestFindingPayload:
    def test_carries_all_enrichment_fields_from_finding_dict(self):
        finding = {
            'check_id': 'AI-GOV-003', 'title': 'No logging enabled',
            'category': 'AI-GOV', 'details': 'No logs.', 'remediation': 'Enable logging.',
            'frameworks': {'EU AI Act': 'Art. 12'},
        }
        payload = alerts._finding_payload('new_high_finding', 'HIGH', 'jdoe-laptop', finding)
        assert payload['event'] == 'new_high_finding'
        assert payload['severity'] == 'HIGH'
        assert payload['device'] == 'jdoe-laptop'
        assert payload['category'] == 'AI-GOV'
        assert payload['details'] == 'No logs.'
        assert payload['remediation'] == 'Enable logging.'
        assert payload['frameworks'] == {'EU AI Act': 'Art. 12'}

    def test_missing_fields_default_safely(self):
        payload = alerts._finding_payload('new_critical_finding', 'CRITICAL', 'host1', {})
        assert payload['category'] == ''
        assert payload['details'] == ''
        assert payload['remediation'] == ''
        assert payload['frameworks'] == {}


class TestFormatTextIntegration:
    """_format_text() is what actually reaches Slack/Teams/email — confirm
    it now carries the enriched content instead of the old bare fallback."""

    def test_standard_finding_includes_remediation(self):
        text = alerts._format_text(_RICH_PAYLOAD)
        assert 'Revoke the exposed key immediately' in text
        assert 'RiskRaven: Arckon — CRITICAL Finding' in text
        assert 'Device: DESKTOP-FIN02' in text

    def test_shadow_ai_path_is_unaffected(self):
        text = alerts._format_text({'event': 'new_shadow_ai', 'device': 'host1', 'service': 'ChatGPT'})
        assert 'Shadow AI Detected' in text

    def test_test_alert_path_is_unaffected(self):
        text = alerts._format_text({'event': 'test_alert', 'device': 'host1'})
        assert 'Test alert' in text
