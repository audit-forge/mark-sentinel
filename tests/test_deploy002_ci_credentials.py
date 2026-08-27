"""AI-DEPLOY-002 — narrow CI test-fixture classifier."""
from connectors.config_connector import ScanContext
from checks import FAIL, WARN
from checks.deploy import CI_TEST_CREDENTIAL_TITLE, check_deploy_002

STRICT_TITLE = "No Hardcoded Credentials in Model Config"

# Qualifying fixture: workflow path, localhost URL, postgres service, test-named DB.
CI_WORKFLOW = """
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: runner
          POSTGRES_PASSWORD: ci_local_pw
          POSTGRES_DB: arckon_test
        ports:
          - 5432:5432
    env:
      DATABASE_URL: postgres://runner:ci_local_pw@localhost:5432/arckon_test
    steps:
      - uses: actions/checkout@v4
      - run: pytest
"""

# Same shape, but no postgres service block and no test-named POSTGRES_DB.
BARE_LOCALHOST_WORKFLOW = """
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      DATABASE_URL: postgres://runner:ci_local_pw@localhost:5432/appdb
    steps:
      - run: pytest
"""

EXTERNAL_COMPOSE = """
services:
  api:
    image: app:1.0
    environment:
      DATABASE_URL: postgres://appuser:prodpassword123@db.example.com:5432/appdb
"""

CI_PATH = ".github/workflows/ci.yml"
COMPOSE_PATH = "docker-compose.yml"


def make_ctx(files: dict) -> ScanContext:
    ctx = ScanContext(target_dir="/fake/target")
    ctx.files = files
    return ctx


def _no_credential_values(res, secrets=("ci_local_pw", "prodpassword123")):
    blob = " ".join([res.details, res.remediation, *res.evidence])
    return not any(s in blob for s in secrets)


def test_qualifying_ci_fixture_downgrades_to_warn_low():
    res = check_deploy_002(make_ctx({CI_PATH: CI_WORKFLOW}))
    assert res.status == WARN
    assert res.severity == "LOW"
    assert res.title == CI_TEST_CREDENTIAL_TITLE
    assert res.evidence and all(CI_PATH in e for e in res.evidence)
    assert _no_credential_values(res)


def test_external_postgres_url_stays_fail_high():
    res = check_deploy_002(make_ctx({COMPOSE_PATH: EXTERNAL_COMPOSE}))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STRICT_TITLE
    assert _no_credential_values(res)


def test_localhost_workflow_without_service_or_test_db_stays_fail_high():
    res = check_deploy_002(make_ctx({CI_PATH: BARE_LOCALHOST_WORKFLOW}))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STRICT_TITLE


def test_smb_plain_english_uses_details_not_generic_copy():
    from output.plain_english import format_report

    res = check_deploy_002(make_ctx({CI_PATH: CI_WORKFLOW}))
    out = format_report([res], {"name": "smb", "smb_language": True}, "demo")
    assert CI_TEST_CREDENTIAL_TITLE in out
    assert "CI fixtures scoped to the ephemeral runner" in out
    assert "Other passwords your AI uses" not in out


def test_dashboard_prefers_details_for_special_title():
    from output.dashboard import _JS

    assert "DETAIL_OVER_BIZ_TITLES" in _JS
    assert f"'{CI_TEST_CREDENTIAL_TITLE}'" in _JS


def test_ci_fixture_classified_before_password_is_captured():
    """CI hits must be classified without the password ever reaching _is_placeholder."""
    from checks import deploy

    seen = []
    original = deploy._is_placeholder
    deploy._is_placeholder = lambda val: seen.append(val) or original(val)
    try:
        res = check_deploy_002(make_ctx({CI_PATH: CI_WORKFLOW}))
    finally:
        deploy._is_placeholder = original

    assert res.title == CI_TEST_CREDENTIAL_TITLE
    assert "ci_local_pw" not in seen

    # Non-CI hits still go through placeholder handling.
    seen.clear()
    deploy._is_placeholder = lambda val: seen.append(val) or original(val)
    try:
        check_deploy_002(make_ctx({COMPOSE_PATH: EXTERNAL_COMPOSE}))
    finally:
        deploy._is_placeholder = original
    assert "prodpassword123" in seen


def test_mixed_ci_and_external_stays_fail_high():
    res = check_deploy_002(make_ctx({CI_PATH: CI_WORKFLOW, COMPOSE_PATH: EXTERNAL_COMPOSE}))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STRICT_TITLE
    assert any(COMPOSE_PATH in e for e in res.evidence)
    assert _no_credential_values(res)


def test_env_file_secret_references_are_not_hardcoded_credentials():
    """Variables ending in _FILE point at secret files, not baked-in values."""
    env_example = """
DATABASE_URL_FILE=./secrets/database-url
MIGRATION_DATABASE_URL_FILE=./secrets/migration-database-url
RAVENOPS_APP_PASSWORD_FILE=./secrets/ravenops-app-password
SEED_ADMIN_PASSWORD_FILE=./secrets/admin-password
GOOGLE_OAUTH_CLIENT_FILE=./secrets/google-oauth-client.json
GOOGLE_TOKEN_ENCRYPTION_KEY_FILE=./secrets/google-token-encryption-key
"""
    compose = """
services:
  api:
    build: .
    env_file: .env.example
"""
    dockerfile = """
FROM node:20
COPY . .
"""
    res = check_deploy_002(make_ctx({
        "Dockerfile": dockerfile,
        "docker-compose.yml": compose,
        ".env.example": env_example,
    }))
    assert res.status != FAIL
