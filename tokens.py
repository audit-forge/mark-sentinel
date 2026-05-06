#!/usr/bin/env python3
# Multi-token mode: set SENTINEL_TOKEN_STORE=output/agent_tokens.json in the server
# environment. server.py will be updated separately to read this store in addition to
# the legacy SENTINEL_AGENT_TOKEN env var and agent_token.txt single-token methods.
import sys
if sys.version_info < (3, 11):
    sys.exit(
        "M.A.R.K. Sentinel requires Python 3.11 or later.\n"
        f"Running: Python {sys.version.split()[0]}\n"
        "Install: https://python.org/downloads/"
    )

import argparse
import json
import secrets
from datetime import date, timedelta
from pathlib import Path

DEFAULT_STORE = Path(__file__).parent / 'output' / 'agent_tokens.json'


def _load(store: Path) -> dict:
    if store.exists():
        try:
            return json.loads(store.read_text())
        except (json.JSONDecodeError, OSError):
            return {'tokens': []}
    return {'tokens': []}


def _save(store: Path, data: dict) -> None:
    import os
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps(data, indent=2) + '\n')
    try:
        os.chmod(store, 0o600)
    except OSError:
        pass


def cmd_generate(args: argparse.Namespace) -> None:
    store = Path(args.store)
    data = _load(store)
    token = secrets.token_hex(32)
    label = args.label or f'token-{len(data["tokens"]) + 1}'
    expires_at = None
    if getattr(args, 'expires_days', None) is not None:
        expires_at = str(date.today() + timedelta(days=args.expires_days))
    data['tokens'].append({
        'token': token,
        'label': label,
        'created': str(date.today()),
        'last_used': None,
        'expires_at': expires_at,
    })
    _save(store, data)
    print(token)


def cmd_list(args: argparse.Namespace) -> None:
    store = Path(args.store)
    data = _load(store)
    tokens = data.get('tokens', [])
    if not tokens:
        print('No tokens found.')
        return
    print(f'{"LABEL":<24}  {"CREATED":<12}  {"LAST USED":<12}  {"EXPIRES":<12}  TOKEN (first 8)')
    print('-' * 92)
    for t in tokens:
        tok_preview = t['token'][:8] if t.get('token') else '?'
        expires = t.get('expires_at')
        if not expires:
            expires_display = 'never'
        else:
            expires_display = expires
            try:
                if expires < date.today().isoformat():
                    expires_display = f'{expires_display} [EXPIRED]'
            except Exception:
                pass
        print(
            f'{(t.get("label") or ""):<24}  '
            f'{(t.get("created") or ""):<12}  '
            f'{(t.get("last_used") or "never"):<12}  '
            f'{expires_display:<12}  '
            f'{tok_preview}...'
        )


def cmd_revoke(args: argparse.Namespace) -> None:
    store = Path(args.store)
    data = _load(store)
    prefix = args.token_prefix
    matches = [t for t in data['tokens'] if t.get('token', '').startswith(prefix)]
    if not matches:
        print(f'No token matching prefix "{prefix}" found.')
        return
    if len(matches) > 1:
        print(f'Prefix "{prefix}" matches {len(matches)} tokens. Use a longer prefix to be specific.')
        for t in matches:
            print(f'  {t.get("label", "")}: {t.get("token", "")[:12]}...')
        return
    data['tokens'] = [t for t in data['tokens'] if not t.get('token', '').startswith(prefix)]
    _save(store, data)
    print(f'Revoked {len(matches)} token(s).')


def cmd_verify(args: argparse.Namespace) -> None:
    store = Path(args.store)
    data = _load(store)
    token = args.token
    matched = next((t for t in data.get('tokens', []) if t.get('token') == token), None)
    if not matched:
        print('invalid')
        return
    expires = matched.get('expires_at')
    if expires and expires < date.today().isoformat():
        print('expired')
        sys.exit(1)
    print('valid')


def cmd_prune(args: argparse.Namespace) -> None:
    store = Path(args.store)
    data = _load(store)
    tokens = data.get('tokens', [])
    remaining = []
    pruned = 0
    for t in tokens:
        expires = t.get('expires_at')
        if expires and expires < date.today().isoformat():
            pruned += 1
            continue
        remaining.append(t)
    data['tokens'] = remaining
    _save(store, data)
    print(f'Pruned {pruned} expired token(s).')


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='tokens',
        description='M.A.R.K. Sentinel — manage agent bearer tokens',
    )
    parser.add_argument('--store', default=str(DEFAULT_STORE), metavar='PATH',
                        help='Path to agent_tokens.json (default: output/agent_tokens.json)')

    sub = parser.add_subparsers(dest='cmd', required=True)

    p_gen = sub.add_parser('generate', help='Generate a new bearer token')
    p_gen.add_argument('--label', default='', metavar='NAME',
                       help='Human-readable label for the token')
    p_gen.add_argument('--expires-days', type=int, default=None, metavar='N',
                       help='Days until token expires (optional)')

    sub.add_parser('list', help='List all tokens')

    p_rev = sub.add_parser('revoke', help='Revoke token matching a prefix')
    p_rev.add_argument('token_prefix', metavar='token-prefix')

    p_ver = sub.add_parser('verify', help='Check if a token is valid')
    p_ver.add_argument('token', metavar='token')

    sub.add_parser('prune', help='Remove expired tokens')

    args = parser.parse_args()

    dispatch = {
        'generate': cmd_generate,
        'list': cmd_list,
        'revoke': cmd_revoke,
        'verify': cmd_verify,
        'prune': cmd_prune,
    }
    dispatch[args.cmd](args)


if __name__ == '__main__':
    main()
