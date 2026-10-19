from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_public_installer_prefers_canonical_root_script():
    source = (ROOT / 'admin' / 'app.py').read_text(encoding='utf-8')
    dockerfile = (ROOT / 'admin' / 'Dockerfile').read_text(encoding='utf-8')

    assert '[f"/installers/{filename}"]' in source
    assert 'COPY install.sh install.ps1 uninstall.ps1 /installers/' in dockerfile


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


def test_windows_installer_falls_back_to_a_system_startup_task_without_nssm():
    installer = (ROOT / 'install.ps1').read_text(encoding='utf-8-sig')

    assert 'NSSM unavailable; falling back to a SYSTEM startup task.' in installer
    assert 'New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount' in installer
    assert 'Start-ScheduledTask -TaskName $ServiceName' in installer
    assert "& '$PythonExe' '$InstallDir\\agent.py' --daemon --config '$ConfigFile'" in installer


def test_windows_uninstaller_removes_current_agent_paths_and_task_fallback():
    uninstaller = (ROOT / 'uninstall.ps1').read_text(encoding='utf-8-sig')

    assert 'C:\\Program Files\\Arckon' in uninstaller
    assert 'C:\\ProgramData\\Arckon' in uninstaller
    assert 'Unregister-ScheduledTask -TaskName $ServiceName' in uninstaller
    assert 'Unregister-ScheduledTask -TaskName "ArckonRepairWatchdog"' in uninstaller
