"""AI-DEPLOY-002 — CI test credential classification.

A PostgreSQL URL only counts as a CI test fixture when it sits in a GitHub
Actions workflow, points at a loopback host, and that same workflow stands up a
postgres service for a test-named database. Everything else stays FAIL/HIGH.
"""
from checks import CheckResult, FAIL, WARN
from checks import deploy
from checks.deploy import check_deploy_002
from connectors.config_connector import ScanContext
from output import plain_english

CI_TITLE = "CI Test Credential Hygiene"
STD_TITLE = "No Hardcoded Credentials in Model Config"

WORKFLOW_YML = ".github/workflows/tests.yml"
WORKFLOW_YAML = ".github/workflows/ci.yaml"
COMPOSE_PATH = "docker-compose.yml"
CHECK_ID = "AI-DEPLOY-002"

# Password used only by the CI service container in these fixtures.
FIXTURE_PW = "ci_local_pw"


def _workflow(db_name: str = "sentinel_test", host: str = "localhost",
              with_service: bool = True) -> str:
    service = f"""    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: ci
          POSTGRES_PASSWORD: {FIXTURE_PW}
          POSTGRES_DB: {db_name}
        ports:
          - 5432:5432
""" if with_service else ""
    return f"""name: tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
{service}    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        env:
          DATABASE_URL: postgres://ci:{FIXTURE_PW}@{host}:5432/{db_name}
        run: python -m pytest
"""


def make_ctx(files: dict) -> ScanContext:
    ctx = ScanContext(target_dir="/fake/target")
    ctx.files = files
    return ctx


def _ctx_one(path: str, content: str) -> ScanContext:
    files = dict()
    files[path] = content
    return make_ctx(files)


# --- Qualifying fixture ----------------------------------------------------

def test_qualifying_ci_fixture_warns_low():
    res = check_deploy_002(_ctx_one(WORKFLOW_YML, _workflow()))
    assert res.status == WARN
    assert res.severity == "LOW"
    assert res.title == CI_TITLE


def test_qualifying_yaml_extension_also_qualifies():
    res = check_deploy_002(_ctx_one(WORKFLOW_YAML, _workflow()))
    assert res.status == WARN
    assert res.title == CI_TITLE


def test_qualifying_evidence_is_only_file_line_type_and_host():
    res = check_deploy_002(_ctx_one(WORKFLOW_YML, _workflow()))
    assert res.evidence, "qualifying fixture should still be evidenced"
    for ev in res.evidence:
        assert ev.startswith(WORKFLOW_YML + ":")
        assert "PostgreSQL URL with password" in ev
        assert "localhost" in ev
        assert FIXTURE_PW not in ev
    assert FIXTURE_PW not in res.details
    assert FIXTURE_PW not in res.remediation


def test_loopback_ip_qualifies():
    res = check_deploy_002(_ctx_one(WORKFLOW_YML, _workflow(host="127.0.0.1")))
    assert res.status == WARN
    assert res.title == CI_TITLE
    assert any("127.0.0.1" in ev for ev in res.evidence)


# --- Non-qualifying: external host ----------------------------------------

def test_external_host_in_qualifying_workflow_fails_high():
    res = check_deploy_002(_ctx_one(WORKFLOW_YML, _workflow(host="db.example.com")))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STD_TITLE


def test_external_credential_in_config_fails_high():
    compose = (
        "services:\n"
        "  app:\n"
        "    environment:\n"
        "      DATABASE_URL: postgres://app:Sup3rSecretPw@db.example.com:5432/app\n"
    )
    res = check_deploy_002(_ctx_one(COMPOSE_PATH, compose))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STD_TITLE


# --- Non-qualifying: loopback host, but a condition is missing -------------

def test_loopback_outside_workflow_path_fails_high():
    compose = "  DATABASE_URL: postgres://ci:" + FIXTURE_PW + "@localhost:5432/app_test\n"
    res = check_deploy_002(_ctx_one(COMPOSE_PATH, compose))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STD_TITLE


def test_loopback_workflow_without_postgres_service_fails_high():
    res = check_deploy_002(_ctx_one(WORKFLOW_YML, _workflow(with_service=False)))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STD_TITLE


def test_loopback_workflow_without_test_named_db_fails_high():
    res = check_deploy_002(_ctx_one(WORKFLOW_YML, _workflow(db_name="production")))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STD_TITLE


# --- Mixed scan ------------------------------------------------------------

def test_mixed_qualifying_and_external_fails_high():
    files = dict()
    files[WORKFLOW_YML] = _workflow()
    files[COMPOSE_PATH] = "  DATABASE_URL: postgres://app:Sup3rSecretPw@db.example.com:5432/app\n"
    res = check_deploy_002(make_ctx(files))
    assert res.status == FAIL
    assert res.severity == "HIGH"
    assert res.title == STD_TITLE
    joined = " ".join(res.evidence) + res.details
    assert FIXTURE_PW not in joined


# --- The fixture password is never handled as a value ----------------------

def _record_placeholder_calls(monkeypatch) -> list:
    seen = []
    real_is_placeholder = deploy._is_placeholder

    def recording_is_placeholder(val):
        seen.append(val)
        return real_is_placeholder(val)

    monkeypatch.setattr(deploy, "_is_placeholder", recording_is_placeholder)
    return seen


def test_qualifying_password_never_reaches_placeholder_handling(monkeypatch):
    seen = _record_placeholder_calls(monkeypatch)
    res = check_deploy_002(_ctx_one(WORKFLOW_YML, _workflow()))

    assert res.title == CI_TITLE
    assert not any(FIXTURE_PW in str(v) for v in seen), (
        "CI fixture password was passed to placeholder handling"
    )


def test_nonqualifying_password_does_reach_placeholder_handling(monkeypatch):
    """Control for the test above — the guard is specific to qualifying fixtures."""
    seen = _record_placeholder_calls(monkeypatch)
    check_deploy_002(_ctx_one(WORKFLOW_YML, _workflow(db_name="production")))

    assert any(FIXTURE_PW in str(v) for v in seen)


# --- Reporting surfaces ----------------------------------------------------

def _ci_result() -> CheckResult:
    return CheckResult(
        check_id=CHECK_ID,
        title=CI_TITLE,
        status=WARN,
        severity="LOW",
        category="AI-DEPLOY",
        details="CI fixture credentials only reach a loopback test container.",
        evidence=[WORKFLOW_YML + ":12 — PostgreSQL URL with password (host localhost)"],
    )


# The formatter wraps long text, so match on an opening fragment that stays on
# one line rather than the full generic sentence.
SMB_FRAGMENT = " ".join(plain_english._SMB_DETAILS[CHECK_ID].split()[:5])


def test_smb_output_uses_result_details_for_special_title():
    out = "\n".join(plain_english._format_result(_ci_result(), is_smb=True))
    assert "CI fixture credentials only reach a loopback test container." in out
    assert SMB_FRAGMENT not in out


def test_smb_output_still_uses_generic_details_for_standard_title():
    r = _ci_result()
    r.title = STD_TITLE
    out = "\n".join(plain_english._format_result(r, is_smb=True))
    assert SMB_FRAGMENT in out
    assert "CI fixture credentials only reach a loopback test container." not in out
