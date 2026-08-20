from connectors.config_connector import ScanContext
from checks import FAIL
from checks.deploy import PLAINTEXT_API_KEY_TITLE, check_deploy_001


def test_plaintext_runtime_key_is_not_mislabeled_as_source_or_git_exposure():
    ctx = ScanContext(target_dir="/runtime-data")
    ctx.files = {
        "alerts_config.json": '{"gemini_api_key": "AIza' + "a" * 35 + '"}',
    }

    result = check_deploy_001(ctx)

    assert result.status == FAIL
    assert result.severity == "CRITICAL"
    assert result.title == PLAINTEXT_API_KEY_TITLE
    assert "secret(s) detected in plaintext configuration or deployment files" in result.details
    assert "source files" not in result.details.lower()
    assert "repo access" not in result.details.lower()
    assert "If the file is tracked by Git" in result.remediation
    assert "AIza" not in " ".join(result.evidence)


def test_google_chat_webhook_is_not_reported_as_a_gemini_api_key():
    ctx = ScanContext(target_dir="/runtime-data")
    ctx.files = {
        "alerts_config.json": (
            '{"gchat_webhook": "https://chat.googleapis.com/v1/spaces/example/messages?key=AIza'
            + "a" * 35
            + '&token=example"}'
        ),
    }
    ctx.has_gitignore = True
    ctx.gitignore_content = ".env\n*.env\n"

    result = check_deploy_001(ctx)

    assert result.status != FAIL
    assert result.title == "API Keys Not Exposed"
