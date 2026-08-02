import json

import agent


def test_load_config_records_the_explicit_config_path(tmp_path):
    config_path = tmp_path / 'agent_config.json'
    config_path.write_text(json.dumps({'target': '~'}))

    config = agent.load_config(config_path)

    assert config['_config_path'] == str(config_path)
    assert config['target'] == '~'
