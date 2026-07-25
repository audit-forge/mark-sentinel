"""Regression checks for the large DNS inventory upload path."""

from pathlib import Path

from admin.dns_connector import parse_log


ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_uploads_selected_log_as_a_file():
    template = (ROOT / "admin/templates/dns_inventory.html").read_text()

    assert "fd.append('log_file', _selectedFile" in template
    assert "readAsText" not in template


def test_gcp_admin_ingress_allows_documented_upload_limit():
    for relative_path in (
        "deploy/gcp/nginx/admin.conf",
        "deploy/gcp/nginx/direct.conf",
    ):
        config = (ROOT / relative_path).read_text()
        assert "location = /dns-inventory/analyze" in config
        assert "client_max_body_size 200m;" in config
        assert "proxy_request_buffering off;" in config


def test_connector_parses_rows_lazily():
    _, entries = parse_log(
        "timestamp,domain,query_type,client_ip,device_name,device_local_ip\n"
        "2026-07-23T12:00:00Z,api.openai.com,A,203.0.113.10,laptop,192.168.1.20\n"
    )

    assert not isinstance(entries, list)
    assert next(entries).hostname == "laptop"
