"""Tests for Arckon AI spend tracking connectors, storage, and API routes."""

import json
import tempfile
import time
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from connectors.anthropic_cost_connector import AnthropicCostConnector
from connectors.cost_connector import CostConnector, SpendRecord
from connectors.gemini_cost_connector import GeminiCostConnector
from connectors.key_store import (
    RedactedKey, config_to_redacted_keys, hash_key, last4, public_view,
    redact, resolve_key, upsert_key, remove_key,
)
from connectors.ollama_cost_connector import OllamaCostConnector
from connectors.openai_cost_connector import OpenAICostConnector
from storage import AgentStore


# -- SpendRecord normalization ------------------------------------------------

def test_spend_record_computes_total_tokens():
    rec = SpendRecord(provider="openai", model="gpt-4o", period_date="2026-08-14",
                      input_tokens=100, output_tokens=50)
    assert rec.total_tokens == 150


def test_spend_record_to_dict_round_trip():
    rec = SpendRecord(provider="openai", model="gpt-4o", period_date="2026-08-14",
                      input_tokens=10, output_tokens=5, cost_usd=0.01)
    d = rec.to_dict()
    assert d["provider"] == "openai"
    assert d["model"] == "gpt-4o"
    assert d["total_tokens"] == 15


# -- OpenAI cost connector ----------------------------------------------------

def test_openai_connector_requires_api_key():
    conn = OpenAICostConnector(api_key="")
    with pytest.raises(ValueError):
        conn.fetch_usage(date.today())


def test_openai_connector_requires_admin_api_key():
    conn = OpenAICostConnector(api_key="sk-proj-test")
    with pytest.raises(ValueError, match="Admin API key"):
        conn.fetch_usage(date.today())


def test_openai_connector_parses_usage_data():
    conn = OpenAICostConnector(api_key="sk-admin-test")
    mock_response = {
        "data": [{
            "start_time": 1723593600,
            "end_time": 1723680000,
            "results": [
                {"line_item": "completions", "amount": {"value": 17.5, "currency": "usd"}},
                {"line_item": "audio", "amount": {"value": 2.25, "currency": "usd"}},
            ],
        }],
        "has_more": False,
    }
    usage_response = {
        "data": [{
            "start_time": 1723593600,
            "end_time": 1723680000,
            "results": [{
                "model": "gpt-4o", "input_tokens": 1200,
                "output_tokens": 300, "num_model_requests": 12,
            }],
        }],
        "has_more": False,
    }

    import urllib.request
    class MockResponse:
        def __init__(self, body):
            self._body = body
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    def mock_urlopen(req, timeout=None):
        assert "bucket_width=1d" in req.full_url
        if "/v1/organization/costs?" in req.full_url:
            assert "group_by=line_item" in req.full_url
            return MockResponse(json.dumps(mock_response).encode())
        assert "/v1/organization/usage/completions?" in req.full_url
        assert "group_by=model" in req.full_url
        return MockResponse(json.dumps(usage_response).encode())

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        records = conn.fetch_usage(date(2024, 8, 14))

    by_model = {record.model: record for record in records}
    assert by_model["completions"].cost_usd == 17.5
    assert by_model["completions"].currency == "USD"
    assert by_model["gpt-4o"].input_tokens == 1200
    assert by_model["gpt-4o"].output_tokens == 300
    assert by_model["gpt-4o"].total_tokens == 1500
    assert by_model["gpt-4o"].request_count == 12


def test_openai_connector_does_not_expose_upstream_error_body():
    import io
    import urllib.error

    conn = OpenAICostConnector(api_key="sk-admin-test")
    error = urllib.error.HTTPError(
        "https://api.openai.com/test", 500, "Server Error", {}, io.BytesIO(b"internal detail"))
    with patch("urllib.request.urlopen", side_effect=error):
        with pytest.raises(RuntimeError, match="HTTP 500") as exc:
            conn.fetch_usage(date(2024, 8, 14))
    assert "internal detail" not in str(exc.value)


def test_openai_connector_retries_transient_error():
    import io
    import urllib.error

    conn = OpenAICostConnector(api_key="sk-admin-test")
    response = {"data": [], "has_more": False}

    class MockResponse:
        def read(self):
            return json.dumps(response).encode()
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    error = urllib.error.HTTPError(
        "https://api.openai.com/test", 429, "Too Many Requests", {}, io.BytesIO())
    with patch("urllib.request.urlopen", side_effect=[error, MockResponse(), MockResponse()]) as urlopen:
        with patch("connectors.openai_cost_connector.time_module.sleep") as sleep:
            assert conn.fetch_usage(date(2024, 8, 14)) == []
    assert urlopen.call_count == 3
    sleep.assert_called_once_with(1)


# -- Anthropic cost connector -------------------------------------------------

def test_anthropic_connector_requires_api_key():
    conn = AnthropicCostConnector(api_key="")
    with pytest.raises(ValueError):
        conn.fetch_usage(date.today())


def test_anthropic_connector_requires_admin_api_key():
    conn = AnthropicCostConnector(api_key="sk-ant-test")
    with pytest.raises(ValueError, match="Admin API key"):
        conn.fetch_usage(date.today())


def test_anthropic_connector_merges_official_usage_and_cost_reports():
    conn = AnthropicCostConnector(api_key="sk-ant-admin01-test")
    usage_response = {
        "data": [{"starting_at": "2026-08-14T00:00:00Z", "results": [{
            "model": "claude-sonnet-4-6", "uncached_input_tokens": 1000000,
            "cache_read_input_tokens": 200000, "cache_creation": {
                "ephemeral_1h_input_tokens": 100000, "ephemeral_5m_input_tokens": 50000,
            }, "output_tokens": 500000,
        }]}], "has_more": False,
    }
    cost_response = {
        "data": [{"starting_at": "2026-08-14T00:00:00Z", "results": [
            {"model": "claude-sonnet-4-6", "amount": "525.00", "currency": "USD"},
            {"cost_type": "web_search", "amount": "12.50", "currency": "USD"},
        ]}], "has_more": False,
    }
    import urllib.request
    class MockResponse:
        def __init__(self, body):
            self._body = body
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    def mock_urlopen(req, timeout=None):
        if "/usage_report/messages" in req.full_url:
            return MockResponse(json.dumps(usage_response).encode())
        assert "/cost_report" in req.full_url
        return MockResponse(json.dumps(cost_response).encode())

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        records = conn.fetch_usage(date(2026, 8, 14))

    by_model = {record.model: record for record in records}
    sonnet = by_model["claude-sonnet-4-6"]
    assert sonnet.provider == "anthropic"
    assert sonnet.input_tokens == 1_350_000
    assert sonnet.output_tokens == 500_000
    assert sonnet.cost_usd == 5.25
    assert by_model["web_search"].cost_usd == 0.125


# -- Gemini cost connector ----------------------------------------------------

def test_gemini_connector_returns_placeholder_without_cloud_monitoring():
    conn = GeminiCostConnector(api_key="test-key")
    records = conn.fetch_usage(date.today())
    assert len(records) == 1
    assert records[0].provider == "gemini"
    assert records[0].cost_usd == 0.0


def test_gemini_connector_estimates_from_response():
    conn = GeminiCostConnector(api_key="test-key")
    response = {"usageMetadata": {"promptTokenCount": 1000, "candidatesTokenCount": 500}}
    rec = conn.fetch_from_response("gemini-1.5-pro", response)
    assert rec.input_tokens == 1000
    assert rec.output_tokens == 500
    assert rec.cost_usd > 0


# -- Ollama cost connector ----------------------------------------------------

def test_ollama_connector_does_not_invent_historical_zero_cost_records():
    conn = OllamaCostConnector(base_url="http://ollama:11434")
    records = conn.fetch_usage(date.today())
    assert records == []


def test_ollama_connector_counts_tokens_from_response():
    conn = OllamaCostConnector()
    response = {"prompt_eval_count": 2000, "eval_count": 750}
    rec = conn.fetch_from_response("llama3.2", response)
    assert rec.input_tokens == 2000
    assert rec.output_tokens == 750
    assert rec.cost_usd == 0.0


# -- Storage layer ------------------------------------------------------------

def test_ai_spend_storage_upsert_and_summary():
    with tempfile.TemporaryDirectory() as tmp:
        store = AgentStore(Path(tmp) / "test.db")
        records = [
            {"provider": "openai", "model": "gpt-4o", "period_date": "2026-08-14",
             "client_org_id": "orgA", "input_tokens": 100, "output_tokens": 50,
             "total_tokens": 150, "cost_usd": 1.25, "currency": "USD",
             "request_count": 10, "raw_snapshot": "{}"},
            {"provider": "anthropic", "model": "claude-sonnet-4-6", "period_date": "2026-08-14",
             "client_org_id": "orgA", "input_tokens": 200, "output_tokens": 100,
             "total_tokens": 300, "cost_usd": 2.50, "currency": "USD",
             "request_count": 5, "raw_snapshot": "{}"},
        ]
        count = store.upsert_ai_spend(records)
        assert count == 2

        summary = store.get_ai_spend_summary(days=7)
        assert summary["total_cost_usd"] == 3.75
        assert summary["total_tokens"] == 450
        assert len(summary["by_provider"]) == 2
        assert len(summary["by_model"]) == 2
        assert len(summary["daily"]) == 1


def test_ai_spend_upsert_overwrites_same_day_model():
    with tempfile.TemporaryDirectory() as tmp:
        store = AgentStore(Path(tmp) / "test.db")
        records = [
            {"provider": "openai", "model": "gpt-4o", "period_date": "2026-08-14",
             "client_org_id": "orgA", "input_tokens": 100, "output_tokens": 50,
             "total_tokens": 150, "cost_usd": 1.00, "currency": "USD",
             "request_count": 1, "raw_snapshot": "{}"},
        ]
        store.upsert_ai_spend(records)
        records[0]["cost_usd"] = 2.00
        store.upsert_ai_spend(records)
        summary = store.get_ai_spend_summary(days=7)
        assert summary["total_cost_usd"] == 2.00


def test_ai_spend_summary_filters_by_client_org():
    """get_ai_spend_summary(client_org_id=...) must only return that org's rows."""
    with tempfile.TemporaryDirectory() as tmp:
        store = AgentStore(Path(tmp) / "test.db")
        store.upsert_ai_spend([
            {"provider": "openai", "model": "gpt-4o", "period_date": "2026-08-14",
             "client_org_id": "orgA", "input_tokens": 100, "output_tokens": 50,
             "total_tokens": 150, "cost_usd": 5.00, "currency": "USD",
             "request_count": 1, "raw_snapshot": "{}"},
            {"provider": "anthropic", "model": "claude-sonnet-4-6", "period_date": "2026-08-14",
             "client_org_id": "orgB", "input_tokens": 200, "output_tokens": 100,
             "total_tokens": 300, "cost_usd": 9.00, "currency": "USD",
             "request_count": 1, "raw_snapshot": "{}"},
        ])

        summary_a = store.get_ai_spend_summary(days=7, client_org_id="orgA")
        assert summary_a["total_cost_usd"] == 5.00
        assert all(r["provider"] != "anthropic" for r in summary_a["by_provider"])

        summary_b = store.get_ai_spend_summary(days=7, client_org_id="orgB")
        assert summary_b["total_cost_usd"] == 9.00
        assert all(r["provider"] != "openai" for r in summary_b["by_provider"])

        # Unfiltered sees both.
        summary_all = store.get_ai_spend_summary(days=7)
        assert summary_all["total_cost_usd"] == 14.00


def test_ai_spend_by_client_org_aggregates():
    with tempfile.TemporaryDirectory() as tmp:
        store = AgentStore(Path(tmp) / "test.db")
        store.upsert_ai_spend([
            {"provider": "openai", "model": "gpt-4o", "period_date": "2026-08-14",
             "client_org_id": "orgA", "input_tokens": 100, "output_tokens": 50,
             "total_tokens": 150, "cost_usd": 5.00, "currency": "USD",
             "request_count": 1, "raw_snapshot": "{}"},
            {"provider": "anthropic", "model": "claude", "period_date": "2026-08-14",
             "client_org_id": "orgB", "input_tokens": 200, "output_tokens": 100,
             "total_tokens": 300, "cost_usd": 9.00, "currency": "USD",
             "request_count": 1, "raw_snapshot": "{}"},
        ])
        rows = store.get_ai_spend_by_client_org(days=7)
        by_org = {r["client_org_id"]: r for r in rows}
        assert by_org["orgA"]["cost_usd"] == 5.00
        assert by_org["orgB"]["cost_usd"] == 9.00


# -- server.py spend helpers --------------------------------------------------

def test_load_spend_config_uses_key_store_and_never_returns_full_key():
    """Config persistence must only ever contain redacted fields."""
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = Path(tmp) / "spend_config.json"
        secret_dir = Path(tmp) / "secrets"
        rk = redact("sk-real-secret-key-12345", "openai", "orgA", "Acme Production")
        # Simulate persisting via key_store.write_secret_file + upsert_key.
        secret_path = __import__("connectors.key_store", fromlist=["write_secret_file"]).write_secret_file(
            secret_dir, "sk-real-secret-key-12345")
        rk2 = RedactedKey(provider="openai", client_org_id="orgA", label="Acme Production",
                         key_hash=rk.key_hash, key_last4=rk.key_last4,
                         api_key_file=str(secret_path))
        config = {}
        upsert_key(config, rk2)
        import json as _json
        cfg_path.write_text(_json.dumps(config, indent=2))

        # The written config must NOT contain the full key anywhere.
        written = cfg_path.read_text()
        assert "sk-real-secret-key-12345" not in written
        assert "2345" in written  # only last4
        assert rk.key_hash in written


def test_fetch_all_spend_tags_records_with_client_org_id():
    """Fetched records must carry the client_org_id of the key that produced them."""
    import server
    full_key = "sk-test-key-abcdef"
    config = {
        "providers": {
            "openai": [
                {"client_org_id": "orgA", "label": "Acme", "key_hash": hash_key(full_key),
                 "key_last4": last4(full_key), "api_key_env": "TEST_OPENAI_KEY",
                 "api_key_file": ""},
            ],
        }
    }
    with patch.object(OpenAICostConnector, "fetch_usage", return_value=[
        SpendRecord(provider="openai", model="gpt-4o", period_date="2026-08-14",
                    input_tokens=100, output_tokens=50, cost_usd=1.0)
    ]):
        with patch.dict("os.environ", {"TEST_OPENAI_KEY": full_key}):
            records = server._fetch_all_spend(config, days=1)
    assert len(records) == 1
    assert records[0]["client_org_id"] == "orgA"
    assert records[0]["key_label"] == "Acme"
    assert records[0]["key_last4"] == "abcdef"[-4:]


def test_fetch_all_spend_returns_provider_error_to_the_caller():
    import server
    full_key = "sk-admin-test-abcdef"
    config = {
        "providers": {
            "openai": [{"client_org_id": "orgA", "label": "Acme", "key_hash": hash_key(full_key),
                          "key_last4": last4(full_key), "api_key_env": "TEST_OPENAI_KEY",
                          "api_key_file": ""}],
        }
    }
    errors = []
    with patch.object(OpenAICostConnector, "fetch_usage", side_effect=RuntimeError("upstream detail")):
        with patch.dict("os.environ", {"TEST_OPENAI_KEY": full_key}):
            assert server._fetch_all_spend(config, days=1, errors=errors) == []
    assert errors == ["openai: fetch failed; check provider credentials and service status"]


# -- Key redaction security ---------------------------------------------------

def test_redact_never_exposes_full_key_on_object():
    rk = redact("sk-super-secret-key-ABCD", "openai", "orgA", "Acme")
    assert not hasattr(rk, "api_key")
    assert "sk-super-secret-key-ABCD" not in repr(rk.__dict__)
    assert rk.key_last4 == "ABCD"
    assert len(rk.key_hash) == 64  # SHA-256 hex


def test_public_view_never_contains_full_key_or_paths():
    rk = redact("sk-super-secret-key-ABCD", "openai", "orgA", "Acme",
                api_key_file="/opt/sentinel-secrets/spend/abc.key")
    view = public_view(rk)
    assert "api_key" not in view
    assert "api_key_file" not in view
    assert "api_key_env" not in view
    assert "key_hash" not in view  # only a prefix
    assert "sk-super-secret-key-ABCD" not in json.dumps(view)
    assert view["key_last4"] == "ABCD"


def test_resolve_key_reads_env_var():
    rk = RedactedKey(provider="openai", client_org_id="orgA", label="x",
                     key_hash="h", key_last4="1234", api_key_env="MY_KEY")
    with patch.dict("os.environ", {"MY_KEY": "sk-real-key-1234"}):
        assert resolve_key(rk) == "sk-real-key-1234"


def test_resolve_key_reads_secret_file():
    with tempfile.TemporaryDirectory() as tmp:
        secret = Path(tmp) / "secret.key"
        secret.write_text("sk-from-file-5678")
        rk = RedactedKey(provider="openai", client_org_id="orgA", label="x",
                         key_hash="h", key_last4="5678", api_key_file=str(secret))
        assert resolve_key(rk) == "sk-from-file-5678"


def test_upsert_key_allows_multiple_keys_for_same_org_and_provider():
    config = {}
    rk1 = redact("sk-key-one-1234", "openai", "orgA", "First")
    rk2 = redact("sk-key-two-5678", "openai", "orgA", "Second")
    upsert_key(config, rk1)
    upsert_key(config, rk2)
    keys = config_to_redacted_keys(config)
    openai_keys = [k for k in keys if k.client_org_id == "orgA"]
    assert len(openai_keys) == 2
    assert {k.label for k in openai_keys} == {"First", "Second"}


def test_remove_key_deletes_entry():
    config = {}
    rk = redact("sk-key-one-1234", "openai", "orgA", "Acme")
    upsert_key(config, rk)
    remove_key(config, "openai", rk.key_hash[:16])
    assert "openai" not in config.get("providers", {})


# -- Client-viewer allowlist + scoping ----------------------------------------

def test_spend_routes_are_on_client_viewer_allowlist():
    """Client viewers can read their own org's spend (scoping enforced in the
    handler via _scoped_client_org). MSP-only routes are NOT in the allowlist."""
    import server
    exact = server._Handler._CLIENT_VIEWER_ALLOWED_EXACT
    prefix = server._Handler._CLIENT_VIEWER_ALLOWED_PREFIX
    for path in ('/api/spend/summary', '/api/spend/by-model', '/api/spend/by-provider', '/api/spend/daily'):
        assert path in exact, f"{path} missing from client_viewer exact allowlist"
    # No broad /api/spend/ prefix should exist.
    assert not any(p.startswith('/api/spend/') for p in prefix), \
        "broad /api/spend/ prefix found in client_viewer allowlist"
    # MSP-only routes must NOT be reachable by client_viewer.
    for admin_path in ('/api/spend/fetch', '/api/spend/keys', '/api/spend/by-client-org',
                       '/api/spend/by-api-key', '/api/spend/keys/remove'):
        assert admin_path not in exact, f"{admin_path} must not be client_viewer-accessible"


def test_spend_days_param_clamps_and_defaults():
    import server
    h = server._Handler.__new__(server._Handler)
    h.path = "/api/spend/summary?days=abc"
    assert h._spend_days_param() == 30
    h.path = "/api/spend/summary?days=999"
    assert h._spend_days_param() == 365
    h.path = "/api/spend/summary?days=10"
    assert h._spend_days_param() == 7
    h.path = "/api/spend/summary"
    assert h._spend_days_param() == 30
    h.path = "/api/spend/summary?days=90"
    assert h._spend_days_param() == 90


# -- Cross-customer tenant isolation ------------------------------------------

def test_ai_spend_is_isolated_per_customer_store():
    """Two separate per-customer stores must not share spend rows."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store_a = AgentStore(root / "customers" / "custA" / "agents.db")
        store_b = AgentStore(root / "customers" / "custB" / "agents.db")

        store_a.upsert_ai_spend([
            {"provider": "openai", "model": "gpt-4o", "period_date": "2026-08-14",
             "client_org_id": "orgA", "input_tokens": 100, "output_tokens": 50,
             "total_tokens": 150, "cost_usd": 5.00, "currency": "USD",
             "request_count": 1, "raw_snapshot": "{}"},
        ])
        store_b.upsert_ai_spend([
            {"provider": "anthropic", "model": "claude-sonnet-4-6", "period_date": "2026-08-14",
             "client_org_id": "orgX", "input_tokens": 200, "output_tokens": 100,
             "total_tokens": 300, "cost_usd": 9.00, "currency": "USD",
             "request_count": 1, "raw_snapshot": "{}"},
        ])

        summary_a = store_a.get_ai_spend_summary(days=7)
        summary_b = store_b.get_ai_spend_summary(days=7)
        assert summary_a["total_cost_usd"] == 5.00
        assert summary_b["total_cost_usd"] == 9.00
        assert store_a._path != store_b._path


def test_get_store_resolves_to_customer_specific_db():
    import server
    with tempfile.TemporaryDirectory() as tmp:
        orig_root = server.ROOT
        server.ROOT = Path(tmp)
        server._store_cache.clear()
        try:
            store_a = server._get_store("custX")
            store_b = server._get_store("custY")
            assert store_a._path != store_b._path
        finally:
            server.ROOT = orig_root
            server._store_cache.clear()


def test_store_method_uses_session_user_customer_id():
    """_Handler._store() must resolve to the logged-in user's customer_id."""
    import server
    h = server._Handler.__new__(server._Handler)
    h._session_user = lambda: {"customer_id": "acme", "role": "admin"}
    with patch.object(server, "_get_store") as mock_get_store:
        mock_get_store.return_value = "ACME_STORE"
        result = h._store()
        mock_get_store.assert_called_once_with("acme")
        assert result == "ACME_STORE"


def test_scoped_client_org_pins_client_viewer_to_their_own_org():
    """A client_viewer's own client_org_id must always win; the ?client_org=
    query param is ignored so a scoped user cannot widen their own view."""
    import server
    h = server._Handler.__new__(server._Handler)
    h._session_user = lambda: {"customer_id": "msp1", "role": "client_viewer",
                                "client_org_id": "orgA"}
    # Stub the registry lookup so _resolve_session_org returns the pinned org.
    org = {"id": "orgA", "customer_id": "msp1", "active": True}
    with patch.object(server, "_get_registry") as mock_reg:
        mock_reg.return_value.get_client_org.return_value = org
        from urllib.parse import parse_qs, urlparse as _up
        h.path = "/api/spend/summary?client_org=orgB"
        assert h._scoped_client_org() == "orgA"


def test_scoped_client_org_allows_msp_admin_to_drill_in():
    """An MSP admin (no client_org_id) may pass ?client_org=<id> to drill in."""
    import server
    h = server._Handler.__new__(server._Handler)
    h._session_user = lambda: {"customer_id": "msp1", "role": "admin"}
    org = {"id": "orgB", "customer_id": "msp1", "active": True}
    with patch.object(server, "_get_registry") as mock_reg:
        mock_reg.return_value.get_client_org.return_value = org
        h.path = "/api/spend/summary?client_org=orgB"
        assert h._scoped_client_org() == "orgB"
        h.path = "/api/spend/summary"
        assert h._scoped_client_org() is None  # sees all orgs


def test_spend_config_is_customer_isolated():
    """Key metadata is stored below each customer, never in a shared config."""
    import server
    from connectors import key_store
    with tempfile.TemporaryDirectory() as tmp:
        original_root = server.ROOT
        server.ROOT = Path(tmp)
        try:
            config_a, config_b = {}, {}
            upsert_key(config_a, redact("sk-customer-a-1234", "openai", "", "Customer A"))
            upsert_key(config_b, redact("sk-customer-b-5678", "openai", "", "Customer B"))
            key_store.save_config(server._spend_config_path("custA"), config_a)
            key_store.save_config(server._spend_config_path("custB"), config_b)
            rendered_a = json.dumps(server._load_spend_config("custA"))
            rendered_b = json.dumps(server._load_spend_config("custB"))
            assert "Customer A" in rendered_a and "Customer B" not in rendered_a
            assert "Customer B" in rendered_b and "Customer A" not in rendered_b
            assert server._spend_budget_path("custA") != server._spend_budget_path("custB")
            assert server._spend_fetch_state_path("custA") != server._spend_fetch_state_path("custB")
        finally:
            server.ROOT = original_root
