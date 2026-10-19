from storage import AgentStore


def test_is_known_device_returns_false_then_true(tmp_path):
    store = AgentStore(tmp_path / "agents.db")

    assert store.is_known_device("missing") is False
    with store._conn() as conn:
        conn.execute(
            "INSERT INTO devices (device_id, hostname, first_seen, last_seen) VALUES (?,?,?,?)",
            ("device-1", "host-1", 1, 1),
        )
    assert store.is_known_device("device-1") is True
