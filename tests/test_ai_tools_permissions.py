"""Permission checks must account for parent-directory traversal access."""

import os

import pytest

from checks.ai_tools import _world_readable_in


@pytest.mark.skipif(os.name == 'nt', reason='POSIX permission semantics')
def test_private_claude_directory_prevents_world_readable_finding(tmp_path):
    claude_dir = tmp_path / '.claude'
    claude_dir.mkdir()
    settings = claude_dir / 'settings.local.json'
    settings.write_text('{}')
    claude_dir.chmod(0o700)
    settings.chmod(0o644)

    assert _world_readable_in(claude_dir) == []


@pytest.mark.skipif(os.name == 'nt', reason='POSIX permission semantics')
def test_world_readable_file_is_reported_when_directory_is_traversable(tmp_path):
    claude_dir = tmp_path / '.claude'
    claude_dir.mkdir()
    settings = claude_dir / 'settings.local.json'
    settings.write_text('{}')
    claude_dir.chmod(0o755)
    settings.chmod(0o644)

    assert _world_readable_in(claude_dir) == [str(settings)]
