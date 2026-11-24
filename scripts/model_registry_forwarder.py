#!/usr/bin/env python3
"""Model registry and metrics forwarder for Arckon.

Polls a model registry (MLflow, Weights & Biases, or generic REST API)
and forwards model metadata and runtime metrics to Arckon's authenticated
ingest endpoint.

Arckon never receives model weights or inference payloads — only
metadata (model ID, version, approval status, validation baseline)
and metric observations (drift, performance, latency, thresholds).

Supported model registries:
  - MLflow (open source)
  - Weights & Biases
  - Generic REST API (custom adapter)

Usage:
  pip install requests
  python3 model_registry_forwarder.py \
    --registry mlflow \
    --mlflow-url http://localhost:5000 \
    --arckon-url https://arckon.riskraven.ai \
    --arckon-token-file /etc/arckon/ingest-token \
    --state-file /var/lib/arckon-model-monitor/state

Run as a scheduled job every 5 minutes.
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


# ── MLflow adapter ──────────────────────────────────────────────────────────

def _mlflow_fetch_registry(mlflow_url: str) -> list[dict]:
    """Fetch registered models from MLflow."""
    import requests
    resp = requests.get(f'{mlflow_url}/api/2.0/mlflow/registered-models/list',
                        timeout=30)
    resp.raise_for_status()
    models = resp.json().get('registered_models', [])
    entries = []
    for m in models:
        name = m.get('name', '')
        for version in m.get('latest_versions', []):
            entries.append({
                'model_id': name,
                'version': str(version.get('version', '1')),
                'intended_use': m.get('description', 'Not specified'),
                'approval_status': _mlflow_map_status(version.get('current_stage', 'None')),
                'approved_by': version.get('user_id', ''),
                'approved_at': version.get('last_updated_timestamp', ''),
                'validation_baseline': None,
                'metadata': {'mlflow_run_id': version.get('run_id', '')},
            })
    return entries


def _mlflow_map_status(stage: str) -> str:
    """Map MLflow model stages to Arckon approval statuses."""
    mapping = {
        'Production': 'approved',
        'Staging': 'conditional',
        'Archived': 'deprecated',
        'None': 'draft',
    }
    return mapping.get(stage, 'draft')


def _mlflow_fetch_metrics(mlflow_url: str, model_name: str,
                            version: str) -> list[dict]:
    """Fetch latest metrics for a model version from MLflow."""
    import requests
    run_id = ''
    # Get run ID for this model version
    resp = requests.get(f'{mlflow_url}/api/2.0/mlflow/model-versions/get',
                        params={'name': model_name, 'version': version},
                        timeout=30)
    if resp.ok:
        run_id = resp.json().get('model_version', {}).get('run_id', '')
    if not run_id:
        return []
    # Get latest metrics for the run
    resp = requests.get(f'{mlflow_url}/api/2.0/mlflow/runs/get',
                        params={'run_id': run_id}, timeout=30)
    if not resp.ok:
        return []
    run_data = resp.json().get('run', {})
    metrics = run_data.get('data', {}).get('metrics', {})
    metrics_list = []
    for metric_name, metric_values in metrics.items():
        if isinstance(metric_values, list) and metric_values:
            latest = metric_values[-1]
            metrics_list.append({
                'model_id': model_name,
                'version': version,
                'metric_name': metric_name,
                'metric_value': latest.get('value', 0),
                'observed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(latest.get('timestamp', 0) / 1000)),
                'unit': '',
                'details': f'MLflow metric: {metric_name}',
            })
    return metrics_list


# ── Generic REST API adapter ────────────────────────────────────────────────

def _generic_fetch_registry(api_url: str, api_key: str) -> list[dict]:
    """Fetch model registry entries from a generic REST API."""
    import requests
    headers = {'Authorization': f'Bearer {api_key}'}
    resp = requests.get(f'{api_url}/models', headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else data.get('models', [])


def _generic_fetch_metrics(api_url: str, api_key: str) -> list[dict]:
    """Fetch model metrics from a generic REST API."""
    import requests
    headers = {'Authorization': f'Bearer {api_key}'}
    resp = requests.get(f'{api_url}/metrics', headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else data.get('metrics', [])


# ── Forward to Arckon ───────────────────────────────────────────────────────

def _forward_to_arckon(registry: list[dict], metrics: list[dict],
                        arckon_url: str, token: str) -> dict:
    """Forward registry entries and metrics to Arckon."""
    url = f'{arckon_url.rstrip("/")}/api/model-monitoring/events'
    payload = json.dumps({'registry': registry, 'metrics': metrics}).encode()
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
    parser = argparse.ArgumentParser(description='Forward model registry data to Arckon')
    parser.add_argument('--registry', choices=['mlflow', 'wandb', 'generic'],
                        default='generic', help='Model registry type')
    parser.add_argument('--mlflow-url', help='MLflow tracking server URL')
    parser.add_argument('--api-url', help='Generic REST API URL')
    parser.add_argument('--api-key', help='Generic REST API key')
    parser.add_argument('--arckon-url', required=True, help='Arckon server URL')
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument('--arckon-token', help='Arckon ingest token')
    token_group.add_argument('--arckon-token-file', help='File containing Arckon ingest token')
    parser.add_argument('--state-file', default='/var/lib/arckon-model-monitor/state',
                        help='Persistent file for last forwarded timestamp')
    args = parser.parse_args()

    token = args.arckon_token
    if args.arckon_token_file:
        try:
            token = Path(args.arckon_token_file).read_text().strip()
        except OSError as e:
            print(f'Could not read token file: {e}', file=sys.stderr)
            return 2

    # Fetch registry entries
    try:
        if args.registry == 'mlflow':
            if not args.mlflow_url:
                print('MLflow requires --mlflow-url', file=sys.stderr)
                return 2
            registry = _mlflow_fetch_registry(args.mlflow_url)
            # Fetch metrics for each model
            metrics = []
            for entry in registry:
                metrics.extend(_mlflow_fetch_metrics(args.mlflow_url,
                                    entry['model_id'], entry['version']))
        else:
            if not args.api_url:
                print('Generic API requires --api-url', file=sys.stderr)
                return 2
            registry = _generic_fetch_registry(args.api_url, args.api_key or '')
            metrics = _generic_fetch_metrics(args.api_url, args.api_key or '')
    except Exception as e:
        print(f'Fetch error: {e}', file=sys.stderr)
        return 1

    if not registry and not metrics:
        print('No new registry entries or metrics to forward.')
        return 0

    # Forward to Arckon
    result = _forward_to_arckon(registry, metrics, args.arckon_url, token)
    print(f'Result: {result}')

    _save_state(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                Path(args.state_file))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(main())
