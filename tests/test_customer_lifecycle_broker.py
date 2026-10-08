import importlib.util
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO = Path(__file__).resolve().parents[1]


def _load_broker():
    path = REPO / "deploy" / "gcp" / "deployer" / "server.py"
    spec = importlib.util.spec_from_file_location("lifecycle_broker", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_lifecycle_broker_rejects_invalid_customer_ids():
    broker = _load_broker()
    with pytest.raises(ValueError):
        broker._validate_payload({"customer_id": "../../host"}, "remove")


def test_lifecycle_broker_requires_full_provisioning_payload():
    broker = _load_broker()
    with pytest.raises(ValueError):
        broker._validate_payload({"customer_id": "acme"}, "provision")


def test_lifecycle_broker_writes_a_restrictive_license(tmp_path, monkeypatch):
    broker = _load_broker()
    broker.LICENSES_DIR = str(tmp_path)
    monkeypatch.setattr(broker.os, "chown", lambda *_args: None)
    payload = {
        "customer_id": "acme",
        "customer_name": "Acme",
        "tier": "standard",
        "expires": "2027-01-01",
        "issued_at": "2026-01-01",
        "max_seats": 5,
    }
    broker._write_license(payload)
    license_path = tmp_path / "acme" / "license.json"
    assert license_path.exists()
    assert license_path.stat().st_mode & 0o777 == 0o400


def test_lifecycle_broker_counts_agents_from_customer_runtime(monkeypatch):
    broker = _load_broker()
    monkeypatch.setattr(
        broker.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout="9\n")
    )
    assert broker._agent_count("acme") == 9


def test_lifecycle_broker_rejects_invalid_stale_agent_customer_ids():
    broker = _load_broker()
    with pytest.raises(ValueError):
        broker._stale_agents("../acme")


def test_lifecycle_broker_only_removes_a_device_that_stayed_stale(tmp_path, monkeypatch):
    broker = _load_broker()
    database = tmp_path / "agents.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE devices (device_id TEXT, hostname TEXT, platform TEXT, last_seen INTEGER)")
        conn.execute("INSERT INTO devices VALUES ('still-stale', 'old-host', 'linux', 1)")
        conn.execute("INSERT INTO devices VALUES ('reported-again', 'new-host', 'linux', 2)")
    monkeypatch.setattr(broker, "_customer_db", lambda _customer_id: sqlite3.connect(database))
    monkeypatch.setattr(broker.time, "time", lambda: broker.STALE_REMOVAL_SECONDS + 100)

    assert broker._remove_stale_agent({"customer_id": "acme", "device_id": "still-stale", "last_seen": 1})
    assert not broker._remove_stale_agent({"customer_id": "acme", "device_id": "reported-again", "last_seen": 1})

    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_admin_routes_lifecycle_work_to_internal_broker():
    source = (REPO / "admin" / "app.py").read_text()
    assert 'http://sentinel-deployer:9000/lifecycle/{operation}' in source
    assert '"X-Arckon-Deploy-Token": DEPLOY_TOKEN' in source
    assert "_require_host_operations" not in source


def test_deployer_is_the_only_host_docker_socket_consumer():
    compose = (REPO / "deploy" / "gcp" / "docker-compose.yml").read_text()
    dockerfile = (REPO / "deploy" / "gcp" / "deployer" / "Dockerfile").read_text()
    assert "sentinel-deployer" in compose
    assert "/var/run/docker.sock:/var/run/docker.sock" in compose
    assert "/opt/sentinel:/opt/sentinel\n" in compose
    assert "apk add --no-cache bash python3 git" in dockerfile
    assert "ports:" not in compose[compose.index("  deployer:"):]
