#!/usr/bin/env python3
"""Package the already-built agent release using an explicit safe allowlist."""
import argparse
import tarfile
from pathlib import Path, PurePosixPath


_RUNTIME_DIRECTORIES = ('profiles',)
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


def package_release(root: Path, output: Path) -> None:
    """Create an archive containing binaries and profile data, and nothing else."""
    root = root.resolve()
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        package_release(args.root, args.output)
    except (OSError, ValueError, tarfile.TarError) as e:
        parser.error(str(e))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
