#!/usr/bin/env python3
"""Package platform-specific agent releases using Nuitka-compiled binaries."""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath


_RUNTIME_DIRECTORIES = ('profiles',)
_SOURCE_FILES = (
    'agent.py', 'audit.py', 'arckon_version.py', 'discovery.py', 'network_inventory.py',
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


def _ensure_nuitka() -> None:
    """Fail early if Nuitka is not available in the active environment."""
    if shutil.which('nuitka') is None and shutil.which('python -m nuitka') is None:
        try:
            import nuitka  # noqa: F401
        except Exception as exc:
            raise RuntimeError(
                'Nuitka is required but not installed. '
                'Install it in the build environment (e.g. pip install nuitka).'
            ) from exc


def _binary_extension(platform_name: str) -> str:
    return '.exe' if platform_name in ('windows', 'win32') else ''


def _nuitka_output_filename(output_name: str, platform_name: str) -> str:
    """Return the base filename Nuitka will produce for a onefile build."""
    return f'{output_name}{_binary_extension(platform_name)}'


def _build_nuitka_binary(
    root: Path,
    script: str,
    output_name: str,
    platform_name: str,
    cc: str | None = None,
) -> Path:
    """Compile a single Python entry point with Nuitka for the target platform."""
    _ensure_nuitka()
    source = root / script
    if not source.exists():
        raise ValueError(f'source script not found: {source}')

    dist_dir = root / 'dist'
    dist_dir.mkdir(parents=True, exist_ok=True)

    extension = _binary_extension(platform_name)
    output_binary = dist_dir / f'{output_name}{extension}'

    cmd = [
        sys.executable, '-m', 'nuitka',
        '--standalone',
        '--onefile',
        '--follow-imports',
        # These packages are imported by the compiled agent/audit binaries at
        # runtime. Include them explicitly so onefile releases work outside
        # the source checkout.
        '--include-package=checks',
        '--include-package=connectors',
        '--include-package=output',
        '--assume-yes-for-downloads',
        f'--output-filename={output_name}{extension}',
        f'--output-dir={dist_dir}',
        str(source),
    ]

    if platform_name in ('windows', 'win32'):
        cmd += [
            '--windows-console-mode=disable',
        ]
    elif platform_name in ('darwin', 'macos'):
        # Console application, not an app bundle.
        # macOS universal binaries cannot be produced on an arm64 Mac unless
        # we explicitly request a single-arch native build. Cross-compilation
        # to Linux/Windows from macOS is not supported by local Nuitka.
        if platform.system() == 'Darwin':
            cmd += ['--macos-target-arch=arm64']

    if cc:
        env = os.environ.copy()
        env['CC'] = cc
    else:
        env = os.environ.copy()

    subprocess.run(cmd, check=True, cwd=root, env=env)
    return output_binary


def _build_binaries(root: Path, platform_name: str, cc: str | None = None) -> list[Path]:
    """Build the agent and audit binaries for the requested platform."""
    return [
        _build_nuitka_binary(root, 'agent.py', 'agent', platform_name, cc=cc),
        _build_nuitka_binary(root, 'audit.py', 'audit', platform_name, cc=cc),
    ]


def _package_all(
    root: Path,
    output_dir: Path,
    *,
    local_only: bool = False,
    cc: str | None = None,
) -> list[Path]:
    """Build and package Linux, macOS, and Windows archives."""
    output_dir.mkdir(parents=True, exist_ok=True)
    platforms = ['macos'] if local_only else ['linux', 'macos', 'windows']
    created: list[Path] = []
    for plat in platforms:
        output = output_dir / f'sentinel-{plat}.tar.gz'
        package_release(root, output, plat, build=True, cc=cc)
        created.append(output)
    return created


def _package_binaries(root: Path, output: Path, platform_name: str) -> None:
    """Package compiled binaries + profile data for all native platforms."""
    extension = _binary_extension(platform_name)
    binaries = [root / 'dist' / f'{name}{extension}' for name in _BINARIES]
    missing = [str(b) for b in binaries if not b.exists()]
    if missing:
        raise ValueError(f'missing compiled binaries: {", ".join(missing)}')

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


def package_release(
    root: Path,
    output: Path,
    platform_name: str | None = None,
    *,
    build: bool = True,
    cc: str | None = None,
) -> None:
    """Create a platform-specific archive. platform_name defaults to local OS."""
    platform_name = (platform_name or platform.system()).lower()
    if platform_name not in ('linux', 'darwin', 'macos', 'windows', 'win32'):
        raise ValueError(f'unsupported platform: {platform_name}')

    if build:
        _build_binaries(root, platform_name, cc=cc)
    _package_binaries(root, output, platform_name)
    print(f'Packaged release: {output}')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, default=None,
                        help='Directory for --package-all archives')
    parser.add_argument('--platform', choices=['linux', 'darwin', 'macos', 'windows'],
                        help='Target platform (defaults to current OS)')
    parser.add_argument('--build-only', action='store_true',
                        help='Compile binaries without packaging')
    parser.add_argument('--package-all', action='store_true',
                        help='Build and package Linux, macOS, and Windows archives')
    parser.add_argument('--cc', type=str, default=None,
                        help='C compiler binary or cross-compiler for Nuitka')
    args = parser.parse_args()
    try:
        if args.package_all:
            _package_all(args.root, args.output_dir or args.output.parent, cc=args.cc)
        elif args.build_only:
            _build_binaries(args.root, (args.platform or platform.system()).lower(), cc=args.cc)
        else:
            package_release(args.root, args.output, args.platform, cc=args.cc)
    except (OSError, ValueError, tarfile.TarError, RuntimeError, subprocess.CalledProcessError) as e:
        parser.error(str(e))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
