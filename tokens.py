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
from datetime import date
from pathlib import Path

DEFAULT_STORE = Path('output/agent_tokens.json')


def _load(store: Path) -> dict:
    if store.exists():
        return json.loads(store.read_text())
    return {'tokens': []}


def _save(store: Path, data: dict) -> None:
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps(data, indent=2) + '\n')


def cmd_generate(args: argparse.Namespace) -> None:
    store = Path(args.store)
    data = _load(store)
    token = secrets.token_hex(32)
    label = args.label or f'token-{len(data["tokens"]) + 1}'
    data['tokens'].append({
        'token': token,
        'label': label,
        'created': str(date.today()),
        'last_used': None,
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
    print(f'{"LABEL":<24}  {"CREATED":<12}  {"LAST USED":<12}  TOKEN (first 8)')
    print('-' * 72)
    for t in tokens:
        tok_preview = t['token'][:8] if t.get('token') else '?'
        print(
            f'{(t.get("label") or ""):<24}  '
            f'{(t.get("created") or ""):<12}  '
            f'{(t.get("last_used") or "never"):<12}  '
            f'{tok_preview}...'
        )


def cmd_revoke(args: argparse.Namespace) -> None:
    store = Path(args.store)
    data = _load(store)
    prefix = args.token_prefix
    before = len(data['tokens'])
    data['tokens'] = [t for t in data['tokens'] if not t.get('token', '').startswith(prefix)]
    removed = before - len(data['tokens'])
    if removed == 0:
        print(f'No token matching prefix "{prefix}" found.')
        return
    _save(store, data)
    print(f'Revoked {removed} token(s).')


def cmd_verify(args: argparse.Namespace) -> None:
    store = Path(args.store)
    data = _load(store)
    token = args.token
    match = any(t.get('token') == token for t in data.get('tokens', []))
    print('valid' if match else 'invalid')


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

    sub.add_parser('list', help='List all tokens')

    p_rev = sub.add_parser('revoke', help='Revoke token matching a prefix')
    p_rev.add_argument('token_prefix', metavar='token-prefix')

    p_ver = sub.add_parser('verify', help='Check if a token is valid')
    p_ver.add_argument('token', metavar='token')

    args = parser.parse_args()

    dispatch = {
        'generate': cmd_generate,
        'list': cmd_list,
        'revoke': cmd_revoke,
        'verify': cmd_verify,
    }
    dispatch[args.cmd](args)


if __name__ == '__main__':
    main()
