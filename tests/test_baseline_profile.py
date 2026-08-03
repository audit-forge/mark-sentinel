"""Customer baseline profile regression coverage."""

import importlib
import io
import json
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def _server():
    return importlib.import_module("server")


def test_baseline_profile_persists_and_excludes_container_profiles(tmp_path, monkeypatch):
    srv = _server()
    monkeypatch.setattr(srv, "_BASELINE_PROFILE_PATH", tmp_path / "baseline_profile.json")

    assert srv._load_baseline_profile() == "default"
    srv._save_baseline_profile("biotech")
    assert json.loads(srv._BASELINE_PROFILE_PATH.read_text()) == {"profile": "biotech"}
    assert srv._load_baseline_profile() == "biotech"
    assert "docker" not in srv._BASELINE_PROFILES
    assert "kubernetes" not in srv._BASELINE_PROFILES


def test_scan_all_without_override_uses_each_devices_saved_baseline(monkeypatch):
    srv = _server()
    commands = []

    class Store:
        def list_devices(self, client_org_id=None):
            assert client_org_id is None
            return [
                {"device_id": "one"}, {"device_id": "two"},
                {"device_id": "docker", "hostname": "docker:api"},
                {"device_id": "k8s", "hostname": "k8s:cluster"},
            ]

        def enqueue_command(self, device_id, command):
            commands.append((device_id, command))

    class ImmediateThread:
        def __init__(self, target, **_kwargs):
            self.target = target

        def start(self):
            self.target()

    handler = srv._Handler.__new__(srv._Handler)
    body = json.dumps({"stagger": "instant"}).encode()
    handler.headers = {"Content-Length": str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler._store = lambda: Store()
    handler._scoped_client_org = lambda: None
    response = {}
    handler._json = lambda value, status=200: response.update(value=value, status=status)
    monkeypatch.setattr(srv, "_get_store_for_device", lambda _device_id: Store())
    monkeypatch.setattr(srv.threading, "Thread", ImmediateThread)

    handler._api_fleet_scan_all()

    assert commands == [
        ("one", "scan_now"), ("two", "scan_now"),
        ("docker", "scan_profile:docker"), ("k8s", "scan_profile:kubernetes"),
    ]
    assert response["value"]["using_baseline"] is True


def test_scan_all_explicit_profile_remains_a_one_time_override(monkeypatch):
    srv = _server()
    commands = []

    class Store:
        def list_devices(self, client_org_id=None):
            return [{"device_id": "one"}]

        def enqueue_command(self, device_id, command):
            commands.append((device_id, command))

    class ImmediateThread:
        def __init__(self, target, **_kwargs):
            self.target = target

        def start(self):
            self.target()

    handler = srv._Handler.__new__(srv._Handler)
    body = json.dumps({"profiles": ["docker"], "stagger": "instant"}).encode()
    handler.headers = {"Content-Length": str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler._store = lambda: Store()
    handler._scoped_client_org = lambda: None
    handler._json = lambda *_args, **_kwargs: None
    monkeypatch.setattr(srv, "_get_store_for_device", lambda _device_id: Store())
    monkeypatch.setattr(srv.threading, "Thread", ImmediateThread)

    handler._api_fleet_scan_all()

    assert commands == [("one", "scan_profile:docker")]
