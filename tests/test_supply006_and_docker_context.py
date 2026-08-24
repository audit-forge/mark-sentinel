from checks import FAIL, PASS
from checks.deploy import check_deploy_002
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


def test_dockerignored_runtime_credentials_do_not_fail():
    result = check_deploy_002(_ctx({
        'Dockerfile': 'FROM python:3.12\nCOPY . .\n',
        'agent_config.json': '{"token": "' + ('a' * 24) + '"}',
        'deploy/gcp/.env': 'SECRET_KEY=production-secret-value\n',
        '.dockerignore': 'agent_config.json\n*.env\n',
    }, ['deploy/gcp/.env']))

    assert result.status != FAIL
