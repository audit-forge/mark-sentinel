"""
M.A.R.K. Sentinel — Report signing utilities.

Signs report content with HMAC-SHA256 using a server-local key.
The signature proves the report came from this Sentinel instance
and has not been altered since it was generated.
"""
import hashlib
import hmac
import os
import secrets
import uuid
from pathlib import Path

_KEY_PATH = Path(__file__).parent / 'sentinel_signing_key.txt'


def get_signing_key() -> bytes:
    """Load or generate the HMAC signing key. Stored in output/sentinel_signing_key.txt."""
    if _KEY_PATH.exists():
        try:
            return bytes.fromhex(_KEY_PATH.read_text().strip())
        except (ValueError, OSError):
            pass
    key = secrets.token_bytes(32)
    _KEY_PATH.write_text(key.hex())
    return key


def key_fingerprint() -> str:
    """Return first 8 hex chars of the SHA-256 of the signing key (safe to publish)."""
    k = get_signing_key()
    return hashlib.sha256(k).hexdigest()[:16]


def sign_content(content: str | bytes) -> tuple[str, str]:
    """Return (report_id, signature_hex) for the given content."""
    if isinstance(content, str):
        content = content.encode('utf-8')
    report_id = uuid.uuid4().hex[:12].upper()
    key = get_signing_key()
    sig = hmac.new(key, content, hashlib.sha256).hexdigest()
    return report_id, sig


def verify_content(content: str | bytes, sig_hex: str) -> bool:
    """Return True if sig_hex is a valid HMAC-SHA256 signature of content."""
    if isinstance(content, str):
        content = content.encode('utf-8')
    key = get_signing_key()
    expected = hmac.new(key, content, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_hex)
