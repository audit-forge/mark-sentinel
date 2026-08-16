from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_public_installer_prefers_canonical_root_script():
    source = (ROOT / 'admin' / 'app.py').read_text(encoding='utf-8')
    dockerfile = (ROOT / 'admin' / 'Dockerfile').read_text(encoding='utf-8')

    assert '[f"/installers/{filename}"]' in source
    assert 'COPY install.sh install.ps1 /installers/' in dockerfile


def test_canonical_windows_installer_is_ascii_safe():
    installer = (ROOT / 'install.ps1').read_text(encoding='utf-8-sig')

    assert installer.isascii()
