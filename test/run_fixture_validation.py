"""
Fixture validation tests for M.A.R.K. Sentinel.
Run: pytest test/run_fixture_validation.py -v
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
AUDIT = str(ROOT / "audit.py")
HARDENED = str(ROOT / "test/fixtures/deploy-hardened")
BASELINE = str(ROOT / "test/fixtures/deploy-baseline")


def _run(target: str, profile: str = "default") -> dict:
    result = subprocess.run(
        [sys.executable, AUDIT, "--mode", "config", "--target", target,
         "--profile", profile, "--output", "json", "--quiet"],
        capture_output=True,
        text=True,
    )
    # Exit code 1 is expected for failing fixtures — parse stdout regardless
    return json.loads(result.stdout)


def _find(findings: list, check_id: str) -> dict | None:
    for f in findings:
        if f["check_id"] == check_id:
            return f
    return None


# ---------------------------------------------------------------------------
# deploy-hardened: should pass all DEPLOY checks and key supply checks
# ---------------------------------------------------------------------------

class TestHardenedFixture:
    @pytest.fixture(scope="class")
    def data(self):
        return _run(HARDENED)

    def test_no_api_key_exposure(self, data):
        r = _find(data["findings"], "AI-DEPLOY-001")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"

    def test_no_hardcoded_credentials(self, data):
        r = _find(data["findings"], "AI-DEPLOY-002")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"

    def test_logging_enabled(self, data):
        r = _find(data["findings"], "AI-DEPLOY-003")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"

    def test_access_controls(self, data):
        r = _find(data["findings"], "AI-DEPLOY-004")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"

    def test_tls_configured(self, data):
        r = _find(data["findings"], "AI-DEPLOY-005")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"

    def test_rate_limiting(self, data):
        r = _find(data["findings"], "AI-DEPLOY-006")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"

    def test_input_limits(self, data):
        r = _find(data["findings"], "AI-INP-005")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"

    def test_model_version_pinned(self, data):
        r = _find(data["findings"], "AI-SUPPLY-005")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"


# ---------------------------------------------------------------------------
# deploy-baseline: should fail/warn in expected places
# ---------------------------------------------------------------------------

class TestBaselineFixture:
    @pytest.fixture(scope="class")
    def data(self):
        return _run(BASELINE)

    def test_api_key_exposure_fails(self, data):
        r = _find(data["findings"], "AI-DEPLOY-001")
        assert r and r["status"] == "FAIL", f"Expected FAIL, got {r}"

    def test_api_key_evidence_references_config(self, data):
        r = _find(data["findings"], "AI-DEPLOY-001")
        assert r and any("config.json" in e for e in r["evidence"])

    def test_no_db_credentials_passes(self, data):
        r = _find(data["findings"], "AI-DEPLOY-002")
        assert r and r["status"] == "PASS", f"Expected PASS, got {r}"

    def test_logging_warns(self, data):
        r = _find(data["findings"], "AI-DEPLOY-003")
        assert r and r["status"] in ("WARN", "FAIL"), f"Expected WARN/FAIL, got {r}"

    def test_unauthenticated_endpoint_fails(self, data):
        r = _find(data["findings"], "AI-DEPLOY-004")
        assert r and r["status"] == "FAIL", f"Expected FAIL, got {r}"

    def test_no_tls_warns(self, data):
        r = _find(data["findings"], "AI-DEPLOY-005")
        assert r and r["status"] in ("WARN", "FAIL"), f"Expected WARN/FAIL, got {r}"

    def test_no_rate_limiting_fails(self, data):
        r = _find(data["findings"], "AI-DEPLOY-006")
        assert r and r["status"] == "FAIL", f"Expected FAIL, got {r}"

    def test_no_input_limits_warns(self, data):
        r = _find(data["findings"], "AI-INP-005")
        assert r and r["status"] in ("WARN", "FAIL"), f"Expected WARN/FAIL, got {r}"

    def test_floating_model_version_fails(self, data):
        r = _find(data["findings"], "AI-SUPPLY-005")
        assert r and r["status"] == "FAIL", f"Expected FAIL, got {r}"

    def test_has_critical_fails(self, data):
        assert data["summary"]["has_critical_fail"] is True

    def test_baseline_overall_fail_count(self, data):
        # At minimum the 4 README-expected FAILs must be present
        assert data["summary"]["fail"] >= 4


# ---------------------------------------------------------------------------
# SARIF output smoke test
# ---------------------------------------------------------------------------

class TestSarifOutput:
    def test_sarif_valid_schema(self):
        result = subprocess.run(
            [sys.executable, AUDIT, "--mode", "config", "--target", BASELINE,
             "--profile", "default", "--output", "sarif", "--quiet"],
            capture_output=True,
            text=True,
        )
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "M.A.R.K. Sentinel"
        assert len(run["results"]) > 0

    def test_sarif_fail_maps_to_error(self):
        result = subprocess.run(
            [sys.executable, AUDIT, "--mode", "config", "--target", BASELINE,
             "--profile", "default", "--output", "sarif", "--quiet"],
            capture_output=True,
            text=True,
        )
        sarif = json.loads(result.stdout)
        results = sarif["runs"][0]["results"]
        errors = [r for r in results if r["level"] == "error"]
        assert len(errors) >= 4, "Expected at least 4 SARIF errors from baseline"
