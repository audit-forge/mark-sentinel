"""Normalize training-data provenance and integrity metadata.

This module is credential-free. A customer-controlled forwarder delivers
dataset registry entries and pipeline events to Arckon's authenticated
ingest endpoint. Arckon never receives dataset contents — only metadata
and pipeline event records.

The normalized data is evaluated to detect:
  - Unapproved source changes (dataset modified outside change control)
  - Checksum mismatches (data integrity violation)
  - Lineage breaks (training run references unapproved dataset)
  - Schema or distribution anomalies
"""
from __future__ import annotations

from typing import Any


_VALID_EVENT_TYPES = frozenset({
    'dataset_registered', 'dataset_modified', 'checksum_verified',
    'checksum_mismatch', 'training_run', 'validation_test',
    'schema_change', 'distribution_anomaly', 'lineage_break',
    'access_policy_change', 'new_contributor',
})

_VALID_INTEGRITY_STATUS = frozenset({
    'verified', 'mismatch', 'pending', 'failed', 'unknown',
})

_MAX_STR = 512


def _clean(value: Any, max_len: int = _MAX_STR) -> str:
    if value is None:
        return ''
    return str(value).strip()[:max_len]


def normalize_dataset_registry(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a dataset registry entry.

    Required: dataset_id, source, owner, version
    Optional: checksum, checksum_algorithm, lineage, access_policy, approved, metadata
    """
    if not isinstance(payload, dict):
        return None

    dataset_id = _clean(payload.get('dataset_id'))
    source = _clean(payload.get('source'), 256)
    owner = _clean(payload.get('owner'))
    version = _clean(payload.get('version'), 128)

    if not dataset_id or not source or not version:
        return None

    lineage = payload.get('lineage')
    clean_lineage = None
    if isinstance(lineage, list):
        clean_lineage = [_clean(item, 256) for item in lineage[:50] if item]
    elif isinstance(lineage, str):
        clean_lineage = [_clean(lineage, 256)]

    return {
        'dataset_id': dataset_id,
        'source': source,
        'owner': owner,
        'version': version,
        'checksum': _clean(payload.get('checksum'), 128),
        'checksum_algorithm': _clean(payload.get('checksum_algorithm'), 32) or 'sha256',
        'lineage': clean_lineage or [],
        'access_policy': _clean(payload.get('access_policy'), 256),
        'approved': bool(payload.get('approved', False)),
        'registered_at': _clean(payload.get('registered_at'), 64),
        'metadata': payload.get('metadata') if isinstance(payload.get('metadata'), dict) else {},
    }


def normalize_pipeline_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a data pipeline event.

    Required: dataset_id, event_type, occurred_at
    Optional: version, actor, checksum, integrity_status, details, model_id
    """
    if not isinstance(payload, dict):
        return None

    dataset_id = _clean(payload.get('dataset_id'))
    event_type = _clean(payload.get('event_type')).lower()
    occurred_at = _clean(payload.get('occurred_at'), 64)

    if not dataset_id or not occurred_at:
        return None
    if event_type and event_type not in _VALID_EVENT_TYPES:
        return None

    integrity_status = _clean(payload.get('integrity_status')).lower()
    if integrity_status and integrity_status not in _VALID_INTEGRITY_STATUS:
        return None

    return {
        'dataset_id': dataset_id,
        'event_type': event_type or 'dataset_modified',
        'occurred_at': occurred_at,
        'version': _clean(payload.get('version'), 128),
        'actor': _clean(payload.get('actor')),
        'checksum': _clean(payload.get('checksum'), 128),
        'integrity_status': integrity_status or 'unknown',
        'model_id': _clean(payload.get('model_id'), 256),
        'details': _clean(payload.get('details'), 1024),
    }
