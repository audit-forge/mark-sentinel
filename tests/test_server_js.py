"""Regression coverage for JavaScript rendered from the dashboard f-string."""

from pathlib import Path

from scripts.check_server_js import check_server_js


def test_rendered_dashboard_javascript_is_valid():
    root = Path(__file__).resolve().parents[1]
    assert check_server_js(root / "server.py")
