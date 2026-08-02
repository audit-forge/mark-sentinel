from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_windows_installer_uses_one_canonical_nssm_service():
    installer = (ROOT / 'install.ps1').read_text()

    assert '$ServiceName = "ArckonAgent"' in installer
    assert '$LegacyServiceName = "SentinelAgent"' in installer
    assert 'C:\\Program Files\\Arckon' in installer
    assert 'C:\\ProgramData\\Arckon' in installer
    assert 'throw "NSSM is required for a Windows service.' in installer
    assert 'sc.exe create $ServiceName' not in installer


def test_windows_installer_defaults_to_all_user_profile_scanning():
    installer = (ROOT / 'install.ps1').read_text()

    assert 'target   = "~"' in installer
