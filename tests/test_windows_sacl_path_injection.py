"""Regression test for PowerShell script-injection via protected-path values.

monitors.windows.WindowsCollector._set_path_sacl() used to build a
PowerShell script by f-string-interpolating a path directly into a
single-quoted string literal ($path = '{path}'). A protected path
containing a single quote (a real character in valid Windows paths,
e.g. C:\\Users\\O'Brien\\Documents) could break out of that string
literal and inject arbitrary PowerShell. protected_paths comes from
server-pushed policy, not raw end-user input, but that's still an
untrusted-enough channel that the script text must never contain the
path value at all.
"""
import monitors.windows as windows_mod


def _make_collector():
    # AccessCollector.__init__ only needs simple attributes; avoid
    # depending on the real queue/device wiring for this unit test.
    return windows_mod.WindowsCollector.__new__(windows_mod.WindowsCollector)


def test_set_path_sacl_never_interpolates_path_into_script_text(monkeypatch):
    collector = _make_collector()
    malicious_path = r"C:\Protected\x'; Remove-Item -Recurse -Force C:\; '"
    captured = {}

    class Result:
        returncode = 0
        stdout = ''
        stderr = ''

    def fake_run(command, **kwargs):
        captured['command'] = command
        captured['env'] = kwargs.get('env')
        return Result()

    monkeypatch.setattr(windows_mod.subprocess, 'run', fake_run)

    collector._set_path_sacl(malicious_path)

    assert captured['command'][0] == 'powershell'
    script_text = captured['command'][captured['command'].index('-Command') + 1]
    # The raw path value must never appear inside the script text itself —
    # it must only ever be read back out of an environment variable.
    assert malicious_path not in script_text
    assert "Remove-Item" not in script_text
    assert '$env:ARCKON_SACL_PATH' in script_text
    # The actual value is carried entirely through the environment.
    assert captured['env']['ARCKON_SACL_PATH'] == malicious_path


def test_set_path_sacl_passes_through_env_not_string_formatting(monkeypatch):
    collector = _make_collector()
    plain_path = r"C:\Protected\normal"
    captured = {}

    def fake_run(command, **kwargs):
        captured['env'] = kwargs.get('env')
        class Result:
            returncode = 0
        return Result()

    monkeypatch.setattr(windows_mod.subprocess, 'run', fake_run)
    collector._set_path_sacl(plain_path)

    assert captured['env']['ARCKON_SACL_PATH'] == plain_path
