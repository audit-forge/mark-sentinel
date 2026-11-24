#!/usr/bin/env python3
"""Data pipeline and dataset provenance forwarder for Arckon.

Polls a data pipeline system (DVC, Kubeflow, Apache Airflow, or generic
REST API) and forwards dataset metadata and pipeline events to Arckon's
authenticated ingest endpoint.

Arckon never receives dataset contents — only metadata (dataset ID,
source, version, checksum, lineage) and pipeline events (training runs,
validation tests, schema changes, anomalies).

Supported data pipeline systems:
  - DVC (Data Version Control)
  - Apache Airflow (via REST API)
  - Generic REST API (custom adapter)

Usage:
  pip install requests
  python3 data_pipeline_forwarder.py \
    --pipeline dvc \
    --dvc-repo /path/to/dvc/repo \
    --arckon-url https://arckon.riskraven.ai \
    --arckon-token-file /etc/arckon/ingest-token \
    --state-file /var/lib/arckon-data-provenance/state

Run as a scheduled job every 5 minutes.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
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


# ── DVC adapter ─────────────────────────────────────────────────────────────

def _dvc_fetch_datasets(dvc_repo: str) -> list[dict]:
    """Fetch dataset metadata from DVC."""
    try:
        result = subprocess.run(
            ['dvc', 'list', '--dvc-only', '--recursive', '--json'],
            capture_output=True, text=True, timeout=60, cwd=dvc_repo,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        datasets = []
        for item in data if isinstance(data, list) else data.get('items', []):
            if item.get('isdir', False):
                continue
            path = item.get('path', item.get('relpath', ''))
            if not path:
                continue
            datasets.append({
                'dataset_id': path,
                'source': f'dvc://{path}',
                'owner': os.environ.get('USER', 'unknown'),
                'version': item.get('md5', 'unknown')[:8],
                'checksum': item.get('md5', ''),
                'checksum_algorithm': 'md5',
                'lineage': [],
                'access_policy': 'dvc-managed',
                'approved': True,
                'registered_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'metadata': {'dvc_repo': dvc_repo},
            })
        return datasets
    except Exception as e:
        print(f'DVC fetch error: {e}', file=sys.stderr)
        return []


def _dvc_fetch_events(dvc_repo: str, since: str) -> list[dict]:
    """Fetch DVC pipeline events since the given timestamp."""
    try:
        result = subprocess.run(
            ['dvc', 'exp', 'list', '--json'],
            capture_output=True, text=True, timeout=60, cwd=dvc_repo,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        events = []
        for exp in data if isinstance(data, list) else data.get('experiments', []):
            events.append({
                'dataset_id': exp.get('name', 'dvc-experiment'),
                'event_type': 'training_run',
                'occurred_at': exp.get('timestamp', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())),
                'version': exp.get('rev', '')[:8],
                'actor': exp.get('executor', os.environ.get('USER', 'unknown')),
                'model_id': exp.get('name', ''),
                'details': f'DVC experiment: {exp.get("name", "")}',
            })
        return events
    except Exception as e:
        print(f'DVC events error: {e}', file=sys.stderr)
        return []


# ── Airflow adapter ──────────────────────────────────────────────────────────

def _airflow_fetch_datasets(airflow_url: str, api_key: str) -> list[dict]:
    """Fetch dataset metadata from Apache Airflow."""
    import requests
    headers = {'Authorization': f'Bearer {api_key}'}
    resp = requests.get(f'{airflow_url}/api/v1/datasets', headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    datasets = data.get('datasets', []) if isinstance(data, dict) else data
    return [{
        'dataset_id': d.get('id', d.get('uri', '')),
        'source': d.get('uri', ''),
        'owner': d.get('extra', {}).get('owner', 'unknown'),
        'version': str(d.get('last_updated', '')),
        'checksum': '',
        'approved': True,
        'registered_at': d.get('created_at', ''),
        'metadata': d.get('extra', {}),
    } for d in datasets]


def _airflow_fetch_events(airflow_url: str, api_key: str, since: str) -> list[dict]:
    """Fetch Airflow DAG run events since the given timestamp."""
    import requests
    headers = {'Authorization': f'Bearer {api_key}'}
    params = {'start_date_gte': since} if since else {}
    resp = requests.get(f'{airflow_url}/api/v1/dagRuns', headers=headers,
                        params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    runs = data.get('dag_runs', []) if isinstance(data, dict) else data
    events = []
    for run in runs:
        events.append({
            'dataset_id': run.get('dag_id', 'airflow-dag'),
            'event_type': 'training_run' if 'train' in run.get('dag_id', '').lower() else 'dataset_modified',
            'occurred_at': run.get('start_date', ''),
            'actor': run.get('run_id', 'airflow'),
            'model_id': run.get('conf', {}).get('model_id', '') if isinstance(run.get('conf'), dict) else '',
            'details': f'Airflow DAG: {run.get("dag_id", "")} ({run.get("state", "")})',
        })
    return events


# ── Generic REST API adapter ────────────────────────────────────────────────

def _generic_fetch_datasets(api_url: str, api_key: str) -> list[dict]:
    import requests
    headers = {'Authorization': f'Bearer {api_key}'}
    resp = requests.get(f'{api_url}/datasets', headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else data.get('datasets', [])


def _generic_fetch_events(api_url: str, api_key: str, since: str) -> list[dict]:
    import requests
    headers = {'Authorization': f'Bearer {api_key}'}
    params = {'since': since} if since else {}
    resp = requests.get(f'{api_url}/events', headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else data.get('events', [])


# ── Forward to Arckon ───────────────────────────────────────────────────────

def _forward_to_arckon(datasets: list[dict], events: list[dict],
                        arckon_url: str, token: str) -> dict:
    url = f'{arckon_url.rstrip("/")}/api/data-provenance/events'
    payload = json.dumps({'datasets': datasets, 'events': events}).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f'Forward error: {e}', file=sys.stderr)
        return {'ok': False, 'error': str(e)}


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description='Forward data provenance to Arckon')
    parser.add_argument('--pipeline', choices=['dvc', 'airflow', 'generic'],
                        default='generic', help='Data pipeline system type')
    parser.add_argument('--dvc-repo', help='Path to DVC repository')
    parser.add_argument('--airflow-url', help='Apache Airflow API URL')
    parser.add_argument('--api-url', help='Generic REST API URL')
    parser.add_argument('--api-key', help='Generic REST API key')
    parser.add_argument('--arckon-url', required=True, help='Arckon server URL')
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument('--arckon-token', help='Arckon ingest token')
    token_group.add_argument('--arckon-token-file', help='File containing Arckon ingest token')
    parser.add_argument('--state-file', default='/var/lib/arckon-data-provenance/state',
                        help='Persistent file for last forwarded timestamp')
    args = parser.parse_args()

    token = args.arckon_token
    if args.arckon_token_file:
        try:
            token = Path(args.arckon_token_file).read_text().strip()
        except OSError as e:
            print(f'Could not read token file: {e}', file=sys.stderr)
            return 2

    state_file = Path(args.state_file)
    since = _load_state(state_file)

    try:
        if args.pipeline == 'dvc':
            if not args.dvc_repo:
                print('DVC requires --dvc-repo', file=sys.stderr)
                return 2
            datasets = _dvc_fetch_datasets(args.dvc_repo)
            events = _dvc_fetch_events(args.dvc_repo, since)
        elif args.pipeline == 'airflow':
            if not args.airflow_url:
                print('Airflow requires --airflow-url', file=sys.stderr)
                return 2
            datasets = _airflow_fetch_datasets(args.airflow_url, args.api_key or '')
            events = _airflow_fetch_events(args.airflow_url, args.api_key or '', since)
        else:
            if not args.api_url:
                print('Generic API requires --api-url', file=sys.stderr)
                return 2
            datasets = _generic_fetch_datasets(args.api_url, args.api_key or '')
            events = _generic_fetch_events(args.api_url, args.api_key or '', since)
    except Exception as e:
        print(f'Fetch error: {e}', file=sys.stderr)
        return 1

    if not datasets and not events:
        print('No new datasets or events to forward.')
        return 0

    result = _forward_to_arckon(datasets, events, args.arckon_url, token)
    print(f'Result: {result}')

    _save_state(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), state_file)
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
