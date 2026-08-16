"""
Arckon — Redacted API key store for AI spend tracking.

Security model
--------------
The full provider API key is NEVER written to any file that could be committed
or leaked. Only a non-reversible SHA-256 hash and the last 4 characters (for
display) are persisted in the spend config. The full key lives only:

  1. in the MSP's env var / secret file (owned by the operator, mode 0600), or
  2. in process memory for the duration of a single fetch, then discarded.

This module provides the helpers to register, resolve, and redact keys. It
deliberately has no function that returns a full key to a caller that already
has a redacted record — a redacted record can only be resolved to a full key
if the caller independently supplies the env var or secret file path.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RedactedKey:
    """What gets persisted to disk and returned by list APIs. No full key."""

    provider: str
    client_org_id: str
    label: str
    key_hash: str       # SHA-256 hex of the full key
    key_last4: str       # last 4 chars, for display only
    api_key_env: str = ""     # env var name holding the real key
    api_key_file: str = ""    # secret file path holding the real key


def hash_key(full_key: str) -> str:
    """SHA-256 hex digest of the full key. Non-reversible."""
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def last4(full_key: str) -> str:
    """Last 4 characters of the key, for display only."""
    return full_key[-4:] if len(full_key) >= 4 else full_key


def redact(full_key: str, provider: str, client_org_id: str, label: str,
           api_key_env: str = "", api_key_file: str = "") -> RedactedKey:
    """Build a RedactedKey from a full key. The full key is used only to derive
    key_hash and key_last4; it is never stored on the returned object."""
    return RedactedKey(
        provider=provider,
        client_org_id=client_org_id,
        label=label,
        key_hash=hash_key(full_key),
        key_last4=last4(full_key),
        api_key_env=api_key_env,
        api_key_file=api_key_file,
    )


def resolve_key(rec: RedactedKey) -> str:
    """Resolve a RedactedKey back to the full key by reading the configured
    env var or secret file. Returns '' if the key cannot be resolved.

    The returned string is the full key — callers must use it transiently and
    must never persist, log, or return it."""
    if rec.api_key_env:
        return os.environ.get(rec.api_key_env, "")
    if rec.api_key_file:
        try:
            return Path(rec.api_key_file).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


def write_secret_file(secret_dir: Path, full_key: str) -> Path:
    """Write the full key to a 0600 secret file named by its hash and return
    the path. The directory should be operator-owned (e.g. /opt/sentinel-secrets)."""
    secret_dir.mkdir(parents=True, exist_ok=True)
    path = secret_dir / f"{hash_key(full_key)}.key"
    # Mode 0600 — only the service user can read it.
    path.write_text(full_key, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def load_config(config_path: Path) -> dict:
    """Load the redacted spend config from disk. Returns {} if missing/invalid."""
    try:
        if config_path.exists():
            return json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_config(config_path: Path, config: dict) -> None:
    """Persist the redacted spend config. Only redacted fields are ever written."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def config_to_redacted_keys(config: dict) -> list[RedactedKey]:
    """Parse the persisted config into a list of RedactedKey objects."""
    out: list[RedactedKey] = []
    providers = config.get("providers", {})
    for provider, entries in providers.items():
        if isinstance(entries, dict):
            # Legacy single-key shape — normalize to a one-entry list.
            entries = [entries]
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            out.append(RedactedKey(
                provider=provider,
                client_org_id=entry.get("client_org_id", ""),
                label=entry.get("label", ""),
                key_hash=entry.get("key_hash", ""),
                key_last4=entry.get("key_last4", ""),
                api_key_env=entry.get("api_key_env", ""),
                api_key_file=entry.get("api_key_file", ""),
            ))
    return out


def upsert_key(config: dict, rec: RedactedKey) -> dict:
    """Add or replace a redacted key entry in the in-memory config dict.
    Returns the updated config. Does NOT write to disk. Replaces only an
    entry with the same key hash, so multiple labeled keys can serve one
    provider/client-org pair."""
    providers = config.setdefault("providers", {})
    entries = providers.get(rec.provider, [])
    if isinstance(entries, dict):
        entries = [entries]
    # Entries are stored per-provider. A matching hash represents the same key.
    entries = [e for e in entries
               if e.get("key_hash") != rec.key_hash]
    entries.append({
        "client_org_id": rec.client_org_id,
        "label": rec.label,
        "key_hash": rec.key_hash,
        "key_last4": rec.key_last4,
        "api_key_env": rec.api_key_env,
        "api_key_file": rec.api_key_file,
    })
    providers[rec.provider] = entries
    return config


def remove_key(config: dict, provider: str, key_hash_prefix: str) -> dict:
    """Remove a redacted key entry. Returns the updated config."""
    providers = config.get("providers", {})
    entries = providers.get(provider, [])
    if isinstance(entries, dict):
        entries = [entries]
    providers[provider] = [e for e in entries
                          if not e.get("key_hash", "").startswith(key_hash_prefix)]
    if not providers[provider]:
        del providers[provider]
    return config


def public_view(rec: RedactedKey) -> dict:
    """The shape returned by list/GET APIs. No full key, no secret file path,
    no env var name — only display-safe fields."""
    return {
        "provider": rec.provider,
        "client_org_id": rec.client_org_id,
        "label": rec.label,
        "key_last4": rec.key_last4,
        "key_id": rec.key_hash[:16] if rec.key_hash else "",
    }
