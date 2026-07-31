#!/usr/bin/env python3
"""Package platform-specific agent releases using an explicit safe allowlist."""
import argparse
import platform
import tarfile
from pathlib import Path, PurePosixPath


_RUNTIME_DIRECTORIES = ('profiles',)
_SOURCE_FILES = (
    'agent.py', 'audit.py', 'arckon_version.py', 'discovery.py',
    'storage.py', 'aibom_generator.py', 'eu_ai_act_report.py',
    'requirements.txt', 'install.sh', 'install.ps1',
)
_SOURCE_DIRECTORIES = ('checks', 'connectors', 'profiles', 'output')
_BINARIES = ('agent', 'audit')


def _archive_name(relative: Path) -> str:
    name = PurePosixPath('sentinel', *relative.parts)
    if name.is_absolute() or any(part in ('', '.', '..') for part in name.parts):
        raise ValueError(f'unsafe archive path: {relative}')
    return str(name)


def _add_file(archive: tarfile.TarFile, path: Path, relative: Path, mode: int) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'expected a regular file: {path}')
    info = archive.gettarinfo(str(path), arcname=_archive_name(relative))
    info.mode = mode
    with path.open('rb') as source:
        archive.addfile(info, source)


def _package_linux(root: Path, output: Path) -> None:
    """Linux: ship compiled binaries + profile data."""
    binaries = [root / 'dist' / name for name in _BINARIES]
    runtime_files = [
        path for directory in _RUNTIME_DIRECTORIES
        for path in sorted((root / directory).glob('*.json'))
    ]
    if not runtime_files:
        raise ValueError('no runtime profile files found')

    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
        for binary in binaries:
            _add_file(archive, binary, Path(binary.name), 0o755)
        for runtime_file in runtime_files:
            _add_file(archive, runtime_file, runtime_file.relative_to(root), 0o644)


def _package_source(root: Path, output: Path) -> None:
    """macOS/Windows: ship Python source + install script + profile data."""
    root = root.resolve()
    runtime_files = [
        path for directory in _RUNTIME_DIRECTORIES
        for path in sorted((root / directory).glob('*.json'))
    ]
    if not runtime_files:
        raise ValueError('no runtime profile files found')

    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
        for name in _SOURCE_FILES:
            path = root / name
            if path.exists():
                _add_file(archive, path, Path(name), 0o644)
        for directory in _SOURCE_DIRECTORIES:
            base = root / directory
            if not base.exists():
                continue
            for path in sorted(base.rglob('*')):
                if path.is_file() and not path.is_symlink():
                    _add_file(archive, path, path.relative_to(root), 0o644)
        for runtime_file in runtime_files:
            _add_file(archive, runtime_file, runtime_file.relative_to(root), 0o644)


def package_release(root: Path, output: Path, platform_name: str | None = None) -> None:
    """Create a platform-specific archive. platform_name defaults to local OS."""
    platform_name = (platform_name or platform.system()).lower()
    if platform_name == 'linux':
        _package_linux(root, output)
    elif platform_name in ('darwin', 'macos'):
        _package_source(root, output)
    elif platform_name in ('windows', 'win32'):
        _package_source(root, output)
    else:
        raise ValueError(f'unsupported platform: {platform_name}')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--platform', choices=['linux', 'darwin', 'macos', 'windows'],
                        help='Target platform (defaults to current OS)')
    args = parser.parse_args()
    try:
        package_release(args.root, args.output, args.platform)
    except (OSError, ValueError, tarfile.TarError) as e:
        parser.error(str(e))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
