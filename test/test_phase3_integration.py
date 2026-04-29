import subprocess
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUDIT_SAFE = ROOT / 'audit_safe.py'
ARTIFACTS = ROOT / 'output' / 'artifacts'


def run_audit(profile: str, target: str, out_basename: str):
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    cmd = ["python3", str(AUDIT_SAFE), "--mode", "config", "--profile", profile, "--target", target,
           "--output", "json,compliance", "--out-file", str(ARTIFACTS / out_basename)]
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.returncode not in (0,1):
        print(completed.stdout)
        print(completed.stderr)
        raise RuntimeError(f"audit_safe exited with {completed.returncode}")
    return completed


def test_fedramp_compliance_artifact_exists(tmp_path):
    target = 'test/fixtures/deploy-hardened'
    run_audit('fedramp', target, 'hardened_run_test')
    md = ARTIFACTS / 'compliance_fedramp_moderate.md'
    assert md.exists(), f"Expected compliance md at {md}"
    content = md.read_text()
    assert 'FedRAMP' in content, 'FedRAMP mapping missing in compliance report'


def test_cmmc_compliance_artifact_exists(tmp_path):
    target = 'test/fixtures/deploy-hardened'
    run_audit('cmmc', target, 'hardened_run_cmmc')
    md = ARTIFACTS / 'compliance_cmmc_level_2.md'
    # If profile name uses spaces/underscores mapping, attempt fallback
    if not md.exists():
        # try deriving filename from profile name inside profile JSON
        import json
        p = ROOT / 'profiles' / 'cmmc.json'
        profile = json.loads(p.read_text())
        fname = 'compliance_' + profile['name'].lower().replace(' ', '_') + '.md'
        md = ARTIFACTS / fname
    assert md.exists(), f"Expected compliance md at {md}"
    content = md.read_text()
    assert 'CMMC' in content or 'CMMC' in content.upper() or 'Level' in content, 'CMMC mapping missing in compliance report'
