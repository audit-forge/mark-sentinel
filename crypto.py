#!/usr/bin/env python3
"""RiskRaven Arckon — Crypto primitives for Protected Files monitoring.

FedRAMP controls implemented:
  SC-13 (cryptographic protection) — AES-256-GCM authenticated encryption
  AU-2  (audit events)              — SHA-256 hash chain for tamper detection

Key management:
  Set exactly one of ARCKON_MASTER_KEY or ARCKON_MASTER_KEY_FILE.
  Both accept a base64- or hex-encoded 32-byte key. Key files must be regular,
  owned by the current user, and inaccessible to group/other users.
  Missing or invalid configuration fails closed; there is no default key.

Encryption:
  AES-256-GCM (FIPS 140-2 validated when the cryptography library is built
  against a validated provider). Authenticated encryption detects tampering
  of ciphertext or nonce — a modified blob will fail decryption.

Hash chain:
  Each access event stores prev_hash + event_hash where
  event_hash = SHA-256(prev_hash || canonical_event_json).
  This creates a tamper-evident chain: modifying any event breaks the chain
  for all subsequent events, detectable by verify_hash_chain().
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import stat
from typing import Any, Optional

log = logging.getLogger('arckon.crypto')

_GCM_NONCE_LEN = 12   # 96-bit nonce — NIST SP 800-38D recommended
_GCM_TAG_LEN = 16     # 128-bit authentication tag
_KEY_LEN = 32         # 256-bit key for AES-256


def _validate_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != _KEY_LEN:
        raise ValueError('Encryption key must be exactly 32 bytes')
    return key


def _decode_master_key(raw: str) -> bytes:
    """Decode only explicit, unambiguous encoded AES-256 keys."""
    if len(raw) == 64 and all(c in '0123456789abcdefABCDEF' for c in raw):
        return _validate_key(bytes.fromhex(raw))
    try:
        return _validate_key(base64.b64decode(raw, validate=True))
    except (ValueError, TypeError):
        raise ValueError('Master key must encode exactly 32 bytes as base64 or hex') from None


def _load_key_file(path: str) -> bytes:
    """Read a private key file without following symlinks."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError('Master key file must be owner-only and owned by the current user')
        try:
            raw = stream.read(1024).decode('ascii').rstrip('\r\n')
        except UnicodeError:
            raise ValueError('Master key file must contain an ASCII encoded key') from None
        return _decode_master_key(raw)


def _load_master_key() -> bytes:
    """Load exactly one configured source; never substitute another key."""
    raw = os.environ.get('ARCKON_MASTER_KEY')
    path = os.environ.get('ARCKON_MASTER_KEY_FILE')
    if raw is not None and path is not None:
        raise ValueError('Configure only one master key source')
    if raw is not None:
        return _decode_master_key(raw)
    if path is not None:
        if not path:
            raise ValueError('ARCKON_MASTER_KEY_FILE must not be empty')
        return _load_key_file(path)
    raise ValueError('Set ARCKON_MASTER_KEY or ARCKON_MASTER_KEY_FILE')


def _get_aesgcm():
    """Lazily import cryptography's AESGCM. Raises with a clear message if
    the package is not installed."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError as e:
        raise ImportError(
            'The cryptography package is required for protected-files '
            'encryption. Install it with: pip install cryptography'
        ) from e


def encrypt_field(plaintext: str, key: Optional[bytes] = None) -> str:
    """Encrypt a string field with AES-256-GCM.

    Returns a base64 string containing nonce + ciphertext + tag, prefixed
    with 'enc:' so the column is self-describing (encrypted vs plaintext).

    FedRAMP SC-13: AES-256-GCM provides confidentiality + integrity.
    """
    k = _load_master_key() if key is None else _validate_key(key)
    if not plaintext:
        return ''
    AESGCM = _get_aesgcm()
    nonce = secrets.token_bytes(_GCM_NONCE_LEN)
    ct = AESGCM(k).encrypt(nonce, plaintext.encode('utf-8'), None)
    blob = nonce + ct
    return 'enc:' + base64.b64encode(blob).decode('ascii')


def decrypt_field(encrypted: str, key: Optional[bytes] = None) -> str:
    """Decrypt an 'enc:'-prefixed AES-256-GCM field.

    Returns the original plaintext. Raises if the ciphertext was tampered
    with (GCM tag verification fails) — this is the tamper-detection property.
    """
    if key is not None:
        _validate_key(key)
    if not encrypted or not encrypted.startswith('enc:'):
        return encrypted  # plaintext passthrough (legacy data)
    k = _load_master_key() if key is None else key
    AESGCM = _get_aesgcm()
    blob = base64.b64decode(encrypted[4:], validate=True)
    if len(blob) < _GCM_NONCE_LEN + _GCM_TAG_LEN:
        raise ValueError('Invalid encrypted field')
    nonce = blob[:_GCM_NONCE_LEN]
    ct = blob[_GCM_NONCE_LEN:]
    pt = AESGCM(k).decrypt(nonce, ct, None)
    return pt.decode('utf-8')


def canonicalize_event(event: dict[str, Any]) -> str:
    """Produce a canonical JSON string for an access event.

    Keys are sorted, separators are compact — ensures the same event always
    hashes to the same value regardless of dict insertion order.
    """
    return json.dumps(event, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False)


def compute_event_hash(prev_hash: str, event_data: dict[str, Any]) -> str:
    """Compute the SHA-256 hash for an access event in the tamper-evident chain.

    event_hash = SHA-256(prev_hash || canonical_event_json)

    FedRAMP AU-2: every access event is cryptographically linked to the
    previous one, making retroactive tampering detectable.
    """
    payload = prev_hash + canonicalize_event(event_data)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def verify_hash_chain(events: list[dict[str, Any]]) -> bool:
    """Verify the integrity of an access event hash chain.

    Returns True if every event_hash matches the recomputed value.
    A False result means the chain was tampered with — the server should
    log a security alert (potential DB tampering).

    The event_hash and prev_hash fields are excluded from the recomputation
    (they are the output, not the input).
    """
    prev = ''
    for evt in events:
        data = {k: v for k, v in evt.items()
                if k not in ('event_hash', 'prev_hash')}
        expected = compute_event_hash(prev, data)
        if evt.get('event_hash') != expected:
            return False
        prev = evt['event_hash']
    return True


def hash_path(path: str) -> str:
    """SHA-256 hash of a canonical path for DB lookup.

    Allows fast equality lookup without storing the plaintext path in an
    index. The path itself is stored encrypted (encrypt_field).
    """
    return hashlib.sha256(path.encode('utf-8')).hexdigest()
