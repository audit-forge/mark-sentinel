from checks import FAIL, PASS
from checks.deploy import _dockerignore_excludes, check_deploy_002
from checks.supply_chain import check_supply_006
from connectors.config_connector import ScanContext


def _ctx(files: dict[str, str], env_files: list[str] | None = None) -> ScanContext:
    ctx = ScanContext(target_dir='/test')
    ctx.files = files
    ctx.env_files = env_files or []
    return ctx


def test_claude_settings_are_not_instruction_files():
    result = check_supply_006(_ctx({
        '.claude/settings.json': '{"hooks": {"PostToolUse": []}}',
    }))

    assert result.status == PASS


def test_internal_url_alone_is_not_an_instruction_file_secret():
    result = check_supply_006(_ctx({
        'CLAUDE.md': 'Use http://10.0.0.8:8000 for local testing.',
    }))

    assert result.status != FAIL


def test_url_with_embedded_credentials_is_an_instruction_file_secret():
    result = check_supply_006(_ctx({
        'CLAUDE.md': 'Use http://scanner:supersecret@10.0.0.8:8000 for local testing.',
    }))

    assert result.status == FAIL


def test_docker_copy_all_fails_for_unignored_runtime_credentials():
    result = check_deploy_002(_ctx({
        'Dockerfile': 'FROM python:3.12\nCOPY . .\n',
        'agent_config.json': '{"token": "' + ('a' * 24) + '"}',
        'deploy/gcp/.env': 'SECRET_KEY=production-secret-value\nSMTP_PASSWORD=mail-password-value\n',
        '.dockerignore': '.claude/\n',
    }, ['deploy/gcp/.env']))

    assert result.status == FAIL
    assert any('agent_config.json' in item for item in result.evidence)
    assert any('deploy/gcp/.env' in item for item in result.evidence)
    assert 'production-secret-value' not in ' '.join(result.evidence)


def test_docker_context_detection_covers_copy_destination_and_add():
    for instruction in ('COPY . /app', 'ADD . .'):
        result = check_deploy_002(_ctx({
            'Dockerfile': f'FROM python:3.12\n{instruction}\n',
            'agent_token.txt': 'a' * 24,
            '.dockerignore': '',
        }))
        assert result.status == FAIL
        assert any('agent_token.txt' in item for item in result.evidence)


def test_copy_from_stage_does_not_scan_local_build_context():
    result = check_deploy_002(_ctx({
        'Dockerfile': 'FROM python:3.12\nCOPY --from=builder . .\n',
        'agent_token.txt': 'a' * 24,
        '.dockerignore': '',
    }))

    assert result.status != FAIL


def test_dockerignore_directory_matching_excludes_nested_files():
    result = check_deploy_002(_ctx({
        'Dockerfile': 'FROM python:3.12\nCOPY . /app\n',
        'deploy/gcp/.env': 'password=production-secret-value\n',
        '.dockerignore': 'deploy/*\n',
    }, ['deploy/gcp/.env']))

    assert result.status != FAIL


def test_dockerignore_directory_rule_excludes_nested_runtime_file():
    result = check_deploy_002(_ctx({
        'Dockerfile': 'FROM python:3.12\nCOPY . /app\n',
        '.claude/agent_config.json': '{"auth_token": "' + ('a' * 24) + '"}',
        '.dockerignore': '.claude/\n',
    }))

    assert result.status != FAIL


def test_dockerignore_directory_rule_does_not_exclude_same_named_file():
    assert not _dockerignore_excludes('secrets', 'secrets/\n')


def test_docker_context_detection_covers_dot_slash_source():
    result = check_deploy_002(_ctx({
        'Dockerfile': 'FROM python:3.12\nCOPY ./ /app\n',
        'agent_token.txt': 'a' * 24,
        '.dockerignore': '',
    }))

    assert result.status == FAIL


def test_dockerignored_runtime_credentials_do_not_fail():
    result = check_deploy_002(_ctx({
        'Dockerfile': 'FROM python:3.12\nCOPY . .\n',
        'agent_config.json': '{"token": "' + ('a' * 24) + '"}',
        'deploy/gcp/.env': 'SECRET_KEY=production-secret-value\n',
        '.dockerignore': 'agent_config.json\n*.env\n',
    }, ['deploy/gcp/.env']))

    assert result.status != FAIL


def test_credential_outside_any_dockerfiles_build_context_is_not_flagged():
    """A whole-filesystem scan (--target /) can see a Dockerfile that COPY . .s
    its own directory, plus same-named runtime config files elsewhere on the
    host that Dockerfile's build context can never reach (e.g. a native
    service's own /etc config, or a sibling project). Only the file actually
    inside that Dockerfile's own directory tree can be baked into its image."""
    result = check_deploy_002(_ctx({
        'opt/sentinel/Dockerfile': 'FROM python:3.12\nCOPY . .\n',
        'opt/sentinel/agent_config.json': '{"token": "' + ('a' * 24) + '"}',
        'etc/arckon/agent_config.json': '{"token": "' + ('b' * 24) + '"}',
        'etc/other-service/agent_token.txt': 'c' * 24,
    }))

    assert result.status == FAIL
    evidence = ' '.join(result.evidence)
    assert 'opt/sentinel/agent_config.json' in evidence
    assert 'etc/arckon/agent_config.json' not in evidence
    assert 'etc/other-service/agent_token.txt' not in evidence


def test_per_build_context_dockerignore_is_respected_not_only_the_root_one():
    """A nested build context (e.g. admin/Dockerfile) uses its own
    admin/.dockerignore, not a .dockerignore that happens to sit elsewhere
    on a broader scan."""
    result = check_deploy_002(_ctx({
        'admin/Dockerfile': 'FROM python:3.12\nCOPY . .\n',
        'admin/agent_config.json': '{"token": "' + ('a' * 24) + '"}',
        'admin/.dockerignore': 'agent_config.json\n',
    }))

    assert result.status != FAIL
