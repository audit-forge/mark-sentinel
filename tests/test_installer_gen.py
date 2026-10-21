import os
import shutil
import tempfile
import zipfile

import pytest

from admin.installer_gen import (
    generate_macos_installer,
    _NSI_TEMPLATE,
    _safe,
)


def test_nsi_template_bakes_in_server_token_and_customer_name():
    nsi = _NSI_TEMPLATE
    nsi = nsi.replace("__SERVER__", "https://arckon.example")
    nsi = nsi.replace("__TOKEN__", "tok-123")
    nsi = nsi.replace("__CUSTOMER_NAME__", "Acme Corp")
    nsi = nsi.replace("__OUTPUT__", "out.exe")
    assert '"https://arckon.example"' in nsi
    assert '"tok-123"' in nsi
    assert "Acme Corp" in nsi
    assert "RequestExecutionLevel admin" in nsi
    assert "install.ps1" in nsi
    assert "uninstall.ps1" in nsi
    assert "WriteUninstaller" in nsi
    assert "UninstallString" in nsi
    assert 'InstallDir "$PROGRAMFILES64\\Arckon"' in nsi
    assert nsi.count("SetRegView 64") == 2
    assert "!include" in nsi and "LogicLib.nsh" in nsi


def test_safe_strips_quotes_and_backslashes():
    assert _safe('hello"; rm -rf /') == "hello; rm -rf /"
    assert _safe("it's") == "its"
    assert _safe("a\\b") == "ab"


def test_macos_installer_produces_a_double_clickable_app_bundle(tmp_path):
    install_sh = tmp_path / "install.sh"
    install_sh.write_text("#!/bin/bash\necho ok\n")
    install_sh.chmod(0o755)

    zip_path = generate_macos_installer(
        server_url="https://arckon.example",
        agent_token="tok-123",
        customer_name="Acme Corp",
        install_sh_path=str(install_sh),
        output_dir=str(tmp_path),
    )

    assert zip_path.endswith(".zip")
    assert os.path.isfile(zip_path)

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        # The .app bundle structure must be present.
        assert any("Arckon Installer.app/Contents/Info.plist" in n for n in names)
        assert any("Arckon Installer.app/Contents/MacOS/ArckonInstaller" in n for n in names)
        assert any("Arckon Installer.app/Contents/Resources/install.sh" in n for n in names)
        assert any("Arckon Installer.app/Contents/Resources/server.txt" in n for n in names)
        assert any("Arckon Installer.app/Contents/Resources/token.txt" in n for n in names)

        server_data = [
            zf.read(n) for n in names if n.endswith("server.txt")
        ][0].decode().strip()
        token_data = [
            zf.read(n) for n in names if n.endswith("token.txt")
        ][0].decode().strip()
        assert server_data == "https://arckon.example"
        assert token_data == "tok-123"

        launcher = [
            zf.read(n) for n in names if n.endswith("ArckonInstaller")
        ][0].decode()
        assert "with administrator privileges" in launcher
        assert "--server" in launcher
        assert "--token" in launcher


def test_macos_installer_info_plist_has_valid_bundle_identifier(tmp_path):
    install_sh = tmp_path / "install.sh"
    install_sh.write_text("#!/bin/bash\necho ok\n")
    install_sh.chmod(0o755)

    zip_path = generate_macos_installer(
        "https://arckon.example", "tok", "Acme",
        str(install_sh), str(tmp_path),
    )
    with zipfile.ZipFile(zip_path) as zf:
        plist = [zf.read(n) for n in zf.namelist()
                 if n.endswith("Info.plist")][0].decode()
    assert "ai.mfdynamics.arckon-installer" in plist
    assert "ArckonInstaller" in plist


def test_windows_installer_raises_without_makensis(tmp_path, monkeypatch):
    from admin.installer_gen import generate_windows_installer
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    with pytest.raises(RuntimeError, match="makensis"):
        generate_windows_installer(
            "https://arckon.example", "tok", "Acme",
            str(tmp_path / "install.ps1"), str(tmp_path),
        )
