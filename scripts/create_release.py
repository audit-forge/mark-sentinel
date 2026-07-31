#!/usr/bin/env python3
"""Create the signed static files consumed by Sentinel agents."""
import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


_VERSION_RE = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')
_PINNED_PUBLIC_KEY_DER_B64 = 'MCowBQYDK2VwAyEAxQSQJT9gaFKKcPEy7nPM7Bdk0fT8LXNDIsQkw1qfLyw='


def create_release(artifact: Path, version: str, output: Path, key_b64: str, *, platform: str = '') -> None:
    """Write an artifact and its pinned-key-signed canonical manifest."""
    if not _VERSION_RE.fullmatch(version):
        raise ValueError('version must be a numeric MAJOR.MINOR.PATCH version')
    if not key_b64:
        raise ValueError('ARCKON_RELEASE_SIGNING_KEY must contain an Ed25519 private key')
    try:
        key_bytes = key_b64.encode()
        if key_bytes.startswith(b'-----BEGIN'):
            private_key = serialization.load_pem_private_key(key_bytes, password=None)
        else:
            private_key = serialization.load_der_private_key(
                base64.b64decode(key_b64, validate=True), password=None)
    except (ValueError, TypeError) as e:
        raise ValueError(f'invalid ARCKON_RELEASE_SIGNING_KEY: {e}') from e
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError('ARCKON_RELEASE_SIGNING_KEY is not an Ed25519 private key')
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if base64.b64encode(public_der).decode() != _PINNED_PUBLIC_KEY_DER_B64:
        raise ValueError('ARCKON_RELEASE_SIGNING_KEY does not match the pinned agent public key')

    data = artifact.read_bytes()
    artifact_name = artifact.name
    manifest = {
        'artifact': artifact_name,
        'product': 'sentinel-agent',
        'sha256': hashlib.sha256(data).hexdigest(),
        'size': len(data),
        'version': version,
    }
    if platform:
        manifest['platform'] = platform
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
    output.mkdir(parents=True, exist_ok=True)
    (output / artifact_name).write_bytes(data)
    (output / 'manifest.json').write_bytes(manifest_bytes)
    (output / 'manifest.sig').write_bytes(private_key.sign(manifest_bytes))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path, default=Path('releases/current'))
    parser.add_argument('--platform', type=str, default='',
                        help='Platform label to embed in the manifest')
    args = parser.parse_args()
    try:
        create_release(
            args.artifact,
            args.version,
            args.output,
            os.environ.get('ARCKON_RELEASE_SIGNING_KEY', ''),
            platform=args.platform,
        )
    except ValueError as e:
        parser.error(str(e))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
