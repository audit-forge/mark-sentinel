from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_public_installer_prefers_canonical_root_script():
    source = (ROOT / 'admin' / 'app.py').read_text(encoding='utf-8')
    dockerfile = (ROOT / 'admin' / 'Dockerfile').read_text(encoding='utf-8')

    assert '[f"/installers/{filename}"]' in source
    assert 'COPY install.sh install.ps1 /installers/' in dockerfile


def test_customer_installer_accepts_legacy_admin_role_with_tenant_scope():
    source = (ROOT / 'admin' / 'app.py').read_text(encoding='utf-8')

    assert 'user.get("role") in ("customer_admin", "admin")' in source
    assert 'user.get("customer_id") == customer_id' in source


def test_macos_uses_terminal_install_not_app_download():
    dashboard = (ROOT / 'server.py').read_text(encoding='utf-8')
    admin = (ROOT / 'admin' / 'app.py').read_text(encoding='utf-8')

    assert 'id="macos-curl-cmd"' in dashboard
    assert "'/install/install.sh | sudo bash -s -- --server '" in dashboard
    assert 'href="/api/installer/macos"' not in dashboard
    assert 'if platform != "windows":' in admin


def test_canonical_windows_installer_is_ascii_safe():
    installer = (ROOT / 'install.ps1').read_text(encoding='utf-8-sig')

    assert installer.isascii()
