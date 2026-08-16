from unittest.mock import MagicMock, patch

from connectors.siem_connector import SplunkHECConnector


def _connector() -> SplunkHECConnector:
    return SplunkHECConnector({
        "hec_url": "https://splunk.example.test",
        "hec_token": "test-token",
    })


def test_splunk_retries_transient_dns_failure():
    connector = _connector()
    finding = MagicMock()
    finding.to_splunk_event.return_value = {"event": {"check_id": "AI-TEST"}}
    with patch.object(connector, "_post", side_effect=[(0, "temporary failure"), (200, '{"code":0}')]):
        with patch("connectors.siem_connector.time.sleep") as sleep:
            assert connector.send(finding) == (True, "sent")
    sleep.assert_called_once_with(1)


def test_splunk_does_not_retry_auth_failure():
    connector = _connector()
    finding = MagicMock()
    finding.to_splunk_event.return_value = {"event": {"check_id": "AI-TEST"}}
    with patch.object(connector, "_post", return_value=(401, "invalid token")) as post:
        assert connector.send(finding) == (False, "401 invalid token")
    post.assert_called_once()
