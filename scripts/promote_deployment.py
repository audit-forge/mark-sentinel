#!/usr/bin/env python3
"""Create/verify signed complete server deployments; root-only host poller.

Host requirements: trusted /opt/sentinel checkout including deploy_images.py and
publish_release.py; root-owned /opt/sentinel/releases bind-mounted into tenants
(mount the parent directory, not individual symlinks). Platform/current paths
must be absent or symlinks, never legacy real directories. Catalog staging needs
up to 2 GiB plus retained version directories; nested agent archives are never
unpacked. Failed revisions are durably quarantined; operator investigation
or a strictly newer signed version is required, not automatic retry.
/opt/sentinel/venv with cryptography, gsutil with bucket read credentials, Docker
Compose, and completed customer security migration/preflights. Install the units
only after review; manually approve before enabling the timer. No bootstrap,
source extraction, remote script execution, image pulling, or key logging.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from .create_release import _PINNED_PUBLIC_KEY_DER_B64
    from .publish_release import _verify_manifest
except ImportError:
    from create_release import _PINNED_PUBLIC_KEY_DER_B64
    from publish_release import _verify_manifest

MAX_ARCHIVE = 8 * 1024**3
ROOT = Path('/opt/sentinel')
CATALOG_ROOT = ROOT / 'releases'
PLATFORMS = ('linux', 'macos', 'windows')
MAX_AGENT = 512 * 1024**2
MAX_CATALOG = 2 * 1024**3
REVISION = re.compile(r'[0-9a-f]{40}')
VERSION = re.compile(r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def require(condition):
    if not condition:
        raise ValueError('Invalid deployment metadata or integrity check')


def timestamp(value):
    require(isinstance(value, str) and bool(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value)))
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def version(value):
    require(isinstance(value, str) and bool(VERSION.fullmatch(value)))
    return tuple(map(int, value.split('.')))


def schema(value):
    require(isinstance(value, dict) and set(value) == {'product', 'schema', 'revision', 'version', 'created', 'images', 'catalog'})
    require(value['product'] == 'arckon-server-deployment' and type(value['schema']) is int and value['schema'] == 2)
    require(isinstance(value['revision'], str) and bool(REVISION.fullmatch(value['revision'])))
    version(value['version'])
    require(timestamp(value['created']) <= datetime.now(timezone.utc))
    require(isinstance(value['images'], dict) and set(value['images']) == {'tenant', 'admin'})
    for role, image in value['images'].items():
        require(isinstance(image, dict) and set(image) == {'id', 'archive', 'sha256', 'size'})
        require(image['archive'] == role + '.docker.tar.gz')
        require(isinstance(image['id'], str) and bool(re.fullmatch(r'sha256:[0-9a-f]{64}', image['id'])))
        require(isinstance(image['sha256'], str) and bool(re.fullmatch(r'[0-9a-f]{64}', image['sha256'])))
        require(type(image['size']) is int and 0 < image['size'] <= MAX_ARCHIVE)
    catalog = value['catalog']
    require(isinstance(catalog, dict) and set(catalog) == {'archive', 'sha256', 'size'})
    require(catalog['archive'] == 'catalog.tar.gz')
    require(isinstance(catalog['sha256'], str) and bool(re.fullmatch(r'[0-9a-f]{64}', catalog['sha256'])))
    require(type(catalog['size']) is int and 0 < catalog['size'] <= MAX_CATALOG)
    return value


def verify(raw, signature):
    require(len(raw) <= 16384 and len(signature) == 64)
    public = serialization.load_der_public_key(base64.b64decode(_PINNED_PUBLIC_KEY_DER_B64, validate=True))
    public.verify(signature, raw)
    value = json.loads(raw)
    require(canonical(value) == raw)
    return schema(value)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def check_archive(path, image):
    require(path.stat().st_size == image['size'] and digest(path) == image['sha256'])


def catalog_files(release_version):
    version(release_version)
    files = {}
    for platform in PLATFORMS:
        suffix = 'linux-amd64' if platform == 'linux' else platform
        files[f'{platform}/arckon-agent-{release_version}-{suffix}.tar.gz'] = MAX_AGENT
        files[f'{platform}/manifest.json'] = 16384
        files[f'{platform}/manifest.sig'] = 64
    return files


def verify_catalog(directory, release_version):
    files = catalog_files(release_version)
    require(directory.is_dir() and not directory.is_symlink())
    require({path.name for path in directory.iterdir()} == set(PLATFORMS))
    public = serialization.load_der_public_key(base64.b64decode(_PINNED_PUBLIC_KEY_DER_B64, validate=True))
    for platform in PLATFORMS:
        parent = directory / platform
        require(parent.is_dir() and not parent.is_symlink())
        names = {name.split('/')[1] for name in files if name.startswith(platform + '/')}
        require({path.name for path in parent.iterdir()} == names)
        for name in names:
            info = (parent / name).lstat()
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= files[platform + '/' + name])
        artifact = next(parent / name for name in names if name.endswith('.tar.gz'))
        manifest = _verify_manifest(public, parent / 'manifest.json', parent / 'manifest.sig', artifact)
        require(isinstance(manifest, dict) and set(manifest) == {'product', 'version', 'platform', 'artifact', 'sha256', 'size'})
        require(manifest['product'] == 'sentinel-agent' and manifest['version'] == release_version)
        require(manifest['platform'] == platform and manifest['artifact'] == artifact.name)
        require(type(manifest['size']) is int and 0 < manifest['size'] <= MAX_AGENT)
        require(isinstance(manifest['sha256'], str) and bool(re.fullmatch(r'[0-9a-f]{64}', manifest['sha256'])))


def unpack_catalog(archive, destination, release_version):
    """Read only nine exact regular USTAR members, never tar extract/extractall.

    Parsing headers directly rejects PAX/GNU metadata, sparse files, links and
    directories too. Payloads, padding and the trailer have hard byte bounds.
    """
    files = catalog_files(release_version)
    destination.mkdir(mode=0o755)
    for platform in PLATFORMS:
        (destination / platform).mkdir(mode=0o755)
    seen = set()
    with gzip.open(archive, 'rb') as stream:
        for _ in files:
            header = stream.read(512)
            require(len(header) == 512 and header[257:263] == b'ustar\x00')
            member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.linkname)
            require(member.name in files and member.name not in seen)
            require(0 < member.size <= files[member.name])
            seen.add(member.name)
            with (destination / member.name).open('xb') as output:
                remaining = member.size
                while remaining:
                    chunk = stream.read(min(remaining, 1024 * 1024))
                    require(bool(chunk))
                    output.write(chunk)
                    remaining -= len(chunk)
            padding = (-member.size) % 512
            require(stream.read(padding) == b'\x00' * padding)
        trailer = stream.read(10241)
        require(1024 <= len(trailer) <= 10240 and not trailer.strip(b'\x00'))
    verify_catalog(destination, release_version)


def pack_catalog(directory, output, release_version):
    verify_catalog(directory, release_version)
    with tarfile.open(output, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(catalog_files(release_version)):
            archive.add(directory / name, arcname=name, recursive=False)


def create(args):
    # Never include parser/crypto exception details: a private key may be malformed.
    secret = os.environ.get('ARCKON_RELEASE_SIGNING_KEY', '')
    if secret.startswith('-----BEGIN'):
        key = serialization.load_pem_private_key(secret.encode(), password=None)
    else:
        key = serialization.load_der_private_key(base64.b64decode(secret, validate=True), password=None)
    require(isinstance(key, Ed25519PrivateKey))
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(base64.b64encode(public).decode() == _PINNED_PUBLIC_KEY_DER_B64)
    images = {}
    for role in ('tenant', 'admin'):
        path = args.directory / (role + '.docker.tar.gz')
        images[role] = {'archive': path.name, 'id': getattr(args, role + '_image'),
                        'size': path.stat().st_size, 'sha256': digest(path)}
    catalog = args.directory / 'catalog.tar.gz'
    with tempfile.TemporaryDirectory() as temporary:
        unpack_catalog(catalog, Path(temporary) / 'catalog', args.version)
    value = schema({'product': 'arckon-server-deployment', 'schema': 2,
                    'revision': args.revision, 'version': args.version,
                    'created': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'images': images,
                    'catalog': {'archive': catalog.name, 'size': catalog.stat().st_size, 'sha256': digest(catalog)}})
    raw = canonical(value)
    (args.directory / 'manifest.json').write_bytes(raw)
    (args.directory / 'manifest.sig').write_bytes(key.sign(raw))
    (args.directory / 'deployment.json').write_bytes(canonical({'revision': value['revision']}))


def run(argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3600)


def download(url, path, limit):
    # Stream with a hard byte limit and deadline, including untrusted pointer data.
    with subprocess.Popen(['gsutil', 'cat', url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            deadline, size = time.monotonic() + 1800, 0
            with path.open('xb') as stream:
                while True:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0)
                    ready, _, _ = select.select([process.stdout], [], [], min(remaining, 30))
                    if not ready:
                        continue
                    chunk = os.read(process.stdout.fileno(), min(1024 * 1024, limit - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    require(size <= limit)
                    stream.write(chunk)
            require(process.wait(timeout=30) == 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def succeeded(path, manifest):
    if not path.exists():
        return False
    value = json.loads(path.read_bytes())
    if value.get('revision') != manifest['revision']:
        return False
    require(value.get('status') == 'succeeded')
    require(value.get('tenant_image') == manifest['images']['tenant']['id'])
    require(value.get('admin_image') == manifest['images']['admin']['id'])
    return True


def catalog_links(release_version):
    return {**{platform: f'v{release_version}/{platform}' for platform in PLATFORMS},
            'current': f'v{release_version}/linux'}


def replace_links(links):
    for name, target in links.items():
        require(name in (*PLATFORMS, 'current'))
        path = CATALOG_ROOT / name
        require(path.is_symlink() or not path.exists())
        if target is None:
            path.unlink(missing_ok=True)
        else:
            require(isinstance(target, str))
            with tempfile.TemporaryDirectory(prefix='.link-', dir=CATALOG_ROOT) as temporary:
                link = Path(temporary) / 'link'
                link.symlink_to(target)
                os.replace(link, path)
        sync_directory(CATALOG_ROOT)


def served_catalog(manifest):
    for name, target in catalog_links(manifest['version']).items():
        path = CATALOG_ROOT / name
        require(path.is_symlink() and os.readlink(path) == target)
    verify_catalog(CATALOG_ROOT / ('v' + manifest['version']), manifest['version'])


def stage_catalog(directory, manifest):
    for path in (CATALOG_ROOT, *CATALOG_ROOT.parents):
        require(not path.is_symlink())
    CATALOG_ROOT.mkdir(mode=0o755, exist_ok=True)
    info = CATALOG_ROOT.stat()
    require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022)
    final = CATALOG_ROOT / ('v' + manifest['version'])
    if final.exists() or final.is_symlink():
        verify_catalog(final, manifest['version'])
        for name in catalog_files(manifest['version']):
            require(digest(final / name) == digest(directory / name))
    else:
        # Stage on the release filesystem so the final rename is atomic even
        # when the poller's private state directory lives on another device.
        with tempfile.TemporaryDirectory(prefix='.stage-', dir=CATALOG_ROOT) as temporary:
            staging = Path(temporary) / 'catalog'
            shutil.copytree(directory, staging)
            for path in staging.rglob('*'):
                path.chmod(0o755 if path.is_dir() else 0o644)
                if path.is_file():
                    with path.open('rb') as stream:
                        os.fsync(stream.fileno())
            for platform in PLATFORMS:
                sync_directory(staging / platform)
            staging.chmod(0o755)
            sync_directory(staging)
            os.replace(staging, final)
            sync_directory(CATALOG_ROOT)
    previous = {}
    for name in catalog_links(manifest['version']):
        path = CATALOG_ROOT / name
        require(path.is_symlink() or not path.exists())
        previous[name] = os.readlink(path) if path.is_symlink() else None
    return previous


def recover_catalog(state):
    transaction = state / 'catalog-transaction.json'
    if not transaction.exists():
        return
    value = json.loads(transaction.read_bytes())
    manifest = schema(value['manifest'])
    require(set(value['previous']) == set(catalog_links(manifest['version'])))
    quarantined = state / 'failed-revisions' / (manifest['revision'] + '.json')
    if not quarantined.exists() and succeeded(state / 'successful.json', manifest):
        served_catalog(manifest)
        save(state / 'applied.json', manifest)
    else:
        replace_links(value['previous'])
    transaction.unlink()
    sync_directory(state)


def poll(args):
    require(os.geteuid() == 0)
    require(bool(re.fullmatch(r'gs://[a-z0-9][a-z0-9.-]{1,220}[a-z0-9]', args.bucket)))
    state = args.state_dir.absolute()
    for path in (state, *state.parents):
        require(not path.is_symlink())
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = state.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    fd = os.open(state / 'poll.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recover_catalog(state)
        with tempfile.TemporaryDirectory(prefix='promotion-', dir=state) as temporary:
            directory = Path(temporary)
            download(args.bucket + '/latest/deployment.json', directory / 'pointer', 256)
            pointer = json.loads((directory / 'pointer').read_bytes())
            require(isinstance(pointer, dict) and set(pointer) == {'revision'})
            revision = pointer['revision']
            require(isinstance(revision, str) and bool(REVISION.fullmatch(revision)))
            failed = state / 'failed-revisions'
            # Quarantine survives rollback and process restarts. Do not even
            # download manifests/images for a candidate whose engine failed.
            require(not (failed / (revision + '.json')).exists())
            prefix = args.bucket + '/deployments/' + revision + '/'
            download(prefix + 'manifest.json', directory / 'manifest.json', 16384)
            download(prefix + 'manifest.sig', directory / 'manifest.sig', 64)
            manifest = verify((directory / 'manifest.json').read_bytes(), (directory / 'manifest.sig').read_bytes())
            require(manifest['revision'] == revision)
            # Pending metadata is a durable high-water mark too: a failed rollout
            # or crash must not permit a rollback/re-signed revision on the next poll.
            for name in ('applied.json', 'pending.json'):
                path = state / name
                if path.exists():
                    previous = schema(json.loads(path.read_bytes()))
                    if previous['revision'] == revision:
                        require(previous == manifest)
                    else:
                        require(version(manifest['version']) > version(previous['version']))
                        require(timestamp(manifest['created']) > timestamp(previous['created']))
            successful = state / 'successful.json'
            if succeeded(successful, manifest):
                served_catalog(manifest)
                save(state / 'applied.json', manifest)
                return
            journal = state / 'transaction.json'
            if journal.exists():
                require(json.loads(journal.read_bytes()).get('status') in ('succeeded', 'rolled_back'))
            catalog = manifest['catalog']
            download(prefix + catalog['archive'], directory / catalog['archive'], catalog['size'])
            check_archive(directory / catalog['archive'], catalog)
            unpack_catalog(directory / catalog['archive'], directory / 'catalog', manifest['version'])
            for image in manifest['images'].values():
                path = directory / image['archive']
                download(prefix + image['archive'], path, image['size'])
                check_archive(path, image)
            save(state / 'pending.json', manifest)
            # Both archives are authenticated before the first Docker mutation.
            for image in manifest['images'].values():
                run(['docker', 'load', '--input', str(directory / image['archive'])])
            for image in manifest['images'].values():
                result = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image['id']],
                                        check=True, capture_output=True, text=True, timeout=60)
                require(result.stdout.strip() == image['id'])
            previous = stage_catalog(directory / 'catalog', manifest)
            transaction = state / 'catalog-transaction.json'
            save(transaction, {'manifest': manifest, 'previous': previous})
            try:
                replace_links(catalog_links(manifest['version']))
                served_catalog(manifest)
                run([sys.executable, str(ROOT / 'scripts/deploy_images.py'),
                     '--tenant-image', manifest['images']['tenant']['id'],
                     '--admin-image', manifest['images']['admin']['id'],
                     '--revision', revision, '--state-dir', str(state)])
                require(succeeded(successful, manifest))
                served_catalog(manifest)
            except Exception:
                try:
                    failed.mkdir(mode=0o700, exist_ok=True)
                    sync_directory(state)
                    save(failed / (revision + '.json'), manifest)
                finally:
                    replace_links(previous)
                    transaction.unlink()
                    sync_directory(state)
                raise
            save(state / 'applied.json', manifest)
            transaction.unlink()
            sync_directory(state)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    signing = commands.add_parser('create')
    signing.add_argument('--directory', type=Path, required=True)
    signing.add_argument('--revision', required=True)
    signing.add_argument('--version', required=True)
    signing.add_argument('--tenant-image', required=True)
    signing.add_argument('--admin-image', required=True)
    checking = commands.add_parser('verify')
    checking.add_argument('--directory', type=Path, required=True)
    polling = commands.add_parser('poll')
    polling.add_argument('--bucket', required=True, help='root-configured GCS bucket, never read from signed metadata')
    polling.add_argument('--state-dir', type=Path, default=Path('/opt/arckon-deploy'))
    args = parser.parse_args(argv)
    try:
        if args.command == 'create':
            create(args)
        elif args.command == 'verify':
            value = verify((args.directory / 'manifest.json').read_bytes(), (args.directory / 'manifest.sig').read_bytes())
            for image in value['images'].values():
                check_archive(args.directory / image['archive'], image)
            check_archive(args.directory / value['catalog']['archive'], value['catalog'])
            with tempfile.TemporaryDirectory() as temporary:
                unpack_catalog(args.directory / value['catalog']['archive'], Path(temporary) / 'catalog', value['version'])
        else:
            poll(args)
    except Exception:
        print('Deployment promotion failed; check trusted configuration, metadata, and host readiness.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
