import json
import os

import pytest

from scripts.retire_test_splunk import retire


def test_only_orphan_is_removed_and_private_backup_preserves_other_config(tmp_path):
    config = tmp_path / 'siem.json'
    value = {'splunk': {'hec_url': 'https://splunk-test:8088', 'hec_token': 'synthetic'},
             'elastic': {'enabled': True, 'api_key': 'retained'}}
    config.write_text(json.dumps(value))
    backup_dir = tmp_path / 'backups'
    backup_dir.mkdir(mode=0o700)
    backup = backup_dir / 'before.json'
    assert retire(config, backup)
    assert json.loads(backup.read_text()) == value
    assert json.loads(config.read_text()) == {'elastic': value['elastic']}
    assert os.stat(backup).st_mode & 0o777 == 0o600
    assert not retire(config, backup)


def test_real_splunk_and_existing_backup_are_never_overwritten(tmp_path):
    config = tmp_path / 'siem.json'
    original = json.dumps({'splunk': {'hec_url': 'https://real.example'}})
    config.write_text(original)
    tmp_path.chmod(0o700)
    backup = tmp_path / 'backup'
    with pytest.raises(ValueError):
        retire(config, backup)
    assert config.read_text() == original
    assert not backup.exists()
    config.write_text(json.dumps({'splunk': {'hec_url': 'https://splunk-test:8088'}}))
    backup.write_text('retain')
    with pytest.raises(FileExistsError):
        retire(config, backup)
    assert backup.read_text() == 'retain'
