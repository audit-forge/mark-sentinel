import json

import agent


def test_load_config_records_the_explicit_config_path(tmp_path):
    config_path = tmp_path / 'agent_config.json'
    config_path.write_text(json.dumps({'target': '~'}))

    config = agent.load_config(config_path)

    assert config['_config_path'] == str(config_path)
    assert config['target'] == '~'


def test_token_rotation_updates_the_explicit_config_path(tmp_path):
    config_path = tmp_path / 'agent_config.json'
    config_path.write_text(json.dumps({'token': 'old-token'}))
    config = agent.load_config(config_path)

    agent._apply_token_update(config, 'new-token')

    assert json.loads(config_path.read_text())['token'] == 'new-token'
    assert config['token'] == 'new-token'
