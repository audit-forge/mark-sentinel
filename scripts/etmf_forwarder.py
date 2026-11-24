#!/usr/bin/env python3
"""eTMF document metadata forwarder for Arckon.

Polls an eTMF system (Veeva Vault, PhlexElection, or any system with a
REST API that returns document metadata) and forwards normalized
metadata to Arckon's authenticated ingest endpoint.

Arckon never receives eTMF system credentials or document contents —
only metadata (artifact type, study ID, version, status, author,
approver, signatures, AI provenance).

Supported eTMF systems:
  - Veeva Vault (REST API v20.3+)
  - PhlexElection (REST API)
  - Generic REST API (custom adapter)

Usage:
  pip install requests
  python3 etmf_forwarder.py \
    --etmf-system veeva \
    --vault-url https://myvault.veevavault.com \
    --vault-username admin@company.com \
    --vault-password "$VAULT_PASSWORD" \
    --arckon-url https://arckon.riskraven.ai \
    --arckon-token-file /etc/arckon/ingest-token \
    --study-id NCT05567890 \
    --state-file /var/lib/arckon-etmf/state

Run as a scheduled job every 5 minutes. State is persisted in the
configured state file so only new/updated documents are sent.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path


def _load_state(state_file: Path) -> str:
    if state_file.is_file():
        return state_file.read_text().strip()
    return ''


def _save_state(ts: str, state_file: Path) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(ts)


# ── Veeva Vault adapter ──────────────────────────────────────────────────────

def _veeva_authenticate(vault_url: str, username: str, password: str) -> str:
    """Authenticate to Veeva Vault and return a session ID."""
    import requests
    resp = requests.post(
        f'{vault_url}/api/v20.3/auth',
        data={'username': username, 'password': password},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get('responseStatus') != 'SUCCESS':
        raise ValueError(f'Veava auth failed: {data.get("errors")}')
    return data['sessionId']


def _veeva_fetch_documents(vault_url: str, session_id: str, study_id: str,
                             start_date: str) -> list[dict]:
    """Fetch document metadata from Veeva Vault since start_date."""
    import requests
    headers = {'Authorization': session_id}
    docs = []
    offset = 0
    while True:
        params = {
            'limit': 500,
            'offset': offset,
            'q': f'study__v:"{study_id}"',
        }
        if start_date:
            params['q'] += f' AND document_date__v > "{start_date}"'
        resp = requests.get(
            f'{vault_url}/api/v20.3/objects/documents',
            headers=headers, params=params, timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get('responseStatus') != 'SUCCESS':
            break
        docs.extend(data.get('documents', []))
        if len(data.get('documents', [])) < 500:
            break
        offset += 500
    return docs


def _veeva_normalize(doc: dict, study_id: str) -> dict | None:
    """Normalize a Veeva Vault document to Arckon's eTMF format."""
    artifact_type = doc.get('type__v', doc.get('document_type__v', ''))
    doc_id = doc.get('id', doc.get('document_id__v', ''))
    if not artifact_type or not doc_id:
        return None
    return {
        'document_id': str(doc_id),
        'artifact_type': artifact_type,
        'study_id': study_id,
        'site_id': doc.get('site__v', doc.get('site_number__v', '')),
        'version': str(doc.get('version__v', doc.get('major_version_number__v', '1'))),
        'author': doc.get('created_by__v', ''),
        'approver': doc.get('approved_by__v', ''),
        'approved_at': doc.get('approval_date__v', ''),
        'created_at': doc.get('document_date__v', doc.get('created_date__v', '')),
        'status': doc.get('status__v', 'draft').lower().replace(' ', '_'),
        'signatures': [],
        'ai_provenance': None,
        'source_system': 'veeva-vault',
        'metadata': {},
    }


# ── Generic REST API adapter ────────────────────────────────────────────────

def _generic_fetch(api_url: str, api_key: str, study_id: str,
                    start_date: str) -> list[dict]:
    """Fetch documents from a generic REST API."""
    import requests
    headers = {'Authorization': f'Bearer {api_key}'}
    params = {'study_id': study_id}
    if start_date:
        params['updated_since'] = start_date
    resp = requests.get(api_url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json() if isinstance(resp.json(), list) else resp.json().get('documents', [])


# ── Forward to Arckon ───────────────────────────────────────────────────────

def _forward_to_arckon(documents: list[dict], arckon_url: str, token: str) -> tuple[int, int]:
    """Forward documents to Arckon's eTMF ingest endpoint."""
    url = f'{arckon_url.rstrip("/")}/api/etmf/events'
    payload = json.dumps(documents).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            return result.get('stored', 0), result.get('failed', 0)
    except Exception as e:
        print(f'Forward error: {e}', file=sys.stderr)
        return 0, len(documents)


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description='Forward eTMF document metadata to Arckon')
    parser.add_argument('--etmf-system', choices=['veeva', 'phlex', 'generic'],
                        default='generic', help='eTMF system type')
    parser.add_argument('--vault-url', help='Veeva Vault URL (for --etmf-system veeva)')
    parser.add_argument('--vault-username', help='Veeva Vault username')
    parser.add_argument('--vault-password', help='Veeva Vault password')
    parser.add_argument('--api-url', help='Generic REST API URL')
    parser.add_argument('--api-key', help='Generic REST API key')
    parser.add_argument('--arckon-url', required=True, help='Arckon server URL')
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument('--arckon-token', help='Arckon ingest token')
    token_group.add_argument('--arckon-token-file', help='File containing Arckon ingest token')
    parser.add_argument('--study-id', required=True, help='Study identifier (e.g., NCT05567890)')
    parser.add_argument('--state-file', default='/var/lib/arckon-etmf/state',
                        help='Persistent file for last forwarded timestamp')
    args = parser.parse_args()

    token = args.arckon_token
    if args.arckon_token_file:
        try:
            token = Path(args.arckon_token_file).read_text().strip()
        except OSError as e:
            print(f'Could not read token file: {e}', file=sys.stderr)
            return 2
    if not token:
        print('Arckon ingest token is empty', file=sys.stderr)
        return 2

    state_file = Path(args.state_file)
    start_date = _load_state(state_file)

    # Fetch documents from eTMF system
    try:
        if args.etmf_system == 'veeva':
            if not args.vault_url or not args.vault_username:
                print('Veeva requires --vault-url and --vault-username', file=sys.stderr)
                return 2
            session_id = _veeva_authenticate(args.vault_url, args.vault_username,
                                             args.vault_password or os.environ.get('VAULT_PASSWORD', ''))
            raw_docs = _veeva_fetch_documents(args.vault_url, session_id,
                                              args.study_id, start_date)
            documents = [_veeva_normalize(d, args.study_id) for d in raw_docs]
            documents = [d for d in documents if d is not None]
        else:
            if not args.api_url:
                print('Generic API requires --api-url', file=sys.stderr)
                return 2
            raw_docs = _generic_fetch(args.api_url, args.api_key or '',
                                       args.study_id, start_date)
            documents = raw_docs if isinstance(raw_docs, list) else []
    except Exception as e:
        print(f'Fetch error: {e}', file=sys.stderr)
        return 1

    if not documents:
        print('No new documents to forward.')
        return 0

    # Forward to Arckon
    forwarded, failed = _forward_to_arckon(documents, args.arckon_url, token)
    print(f'Forwarded {forwarded} document(s), {failed} failed.')

    # Update state
    _save_state(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), state_file)
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
