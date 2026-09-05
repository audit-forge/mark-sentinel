#!/usr/bin/env python3
"""RiskRaven Arckon — Crypto primitives for Protected Files monitoring.

FedRAMP controls implemented:
  SC-13 (cryptographic protection) — AES-256-GCM authenticated encryption
  AU-2  (audit events)              — SHA-256 hash chain for tamper detection
  SC-8  (transmission confidentiality) — keys never written to disk

Key management:
  The master key is read from the ARCKON_MASTER_KEY environment variable.
  It is NEVER written to disk. If the env var is absent (e.g. dev mode),
  a derived dev key is used so the feature still works locally — but a
  warning is logged. Production deployments MUST set ARCKON_MASTER_KEY to
  a 32-byte (256-bit) random value stored in a KMS / secret manager.

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
from typing import Any, Optional

log = logging.getLogger('arckon.crypto')

_GCM_NONCE_LEN = 12   # 96-bit nonce — NIST SP 800-38D recommended
_GCM_TAG_LEN = 16     # 128-bit authentication tag
_KEY_LEN = 32         # 256-bit key for AES-256


def _load_master_key() -> bytes:
    """Load the 256-bit master key from ARCKON_MASTER_KEY env var.

    In production this must be set to a 32-byte random value (base64-encoded
    or hex-encoded). If unset, a deterministic dev-only key is derived so
    local testing works — but a warning is emitted.
    """
    raw = os.environ.get('ARCKON_MASTER_KEY')
    if raw:
        # Accept base64 or hex encoding for operational convenience.
        try:
            key = base64.b64decode(raw, validate=True)
            if len(key) == _KEY_LEN:
                return key
        except Exception:
            pass
        try:
            key = bytes.fromhex(raw)
            if len(key) == _KEY_LEN:
                return key
        except Exception:
            pass
        # If raw is exactly 32 chars, use it directly (legacy / simple).
        if len(raw) == _KEY_LEN:
            return raw.encode('utf-8')
        log.warning('ARCKON_MASTER_KEY present but not 32 bytes after '
                    'decode — falling back to dev key')

    log.warning('ARCKON_MASTER_KEY not set — using derived dev key. '
                'DO NOT use in production/FedRAMP deployments.')
    return hashlib.sha256(b'arckon-dev-key-DO-NOT-USE-IN-PROD').digest()


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
    if not plaintext:
        return ''
    k = key or _load_master_key()
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
    if not encrypted or not encrypted.startswith('enc:'):
        return encrypted  # plaintext passthrough (legacy data)
    k = key or _load_master_key()
    AESGCM = _get_aesgcm()
    blob = base64.b64decode(encrypted[4:])
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
