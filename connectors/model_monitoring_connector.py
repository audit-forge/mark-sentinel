"""Normalize model registry metadata and runtime drift metrics for monitoring.

This module is credential-free. A customer-controlled forwarder delivers
model registry entries and runtime metric observations to Arckon's
authenticated ingest endpoint. Arckon never receives model weights or
inference payloads — only metadata and metric values.

The normalized data is evaluated to detect:
  - Configuration/version drift (running version differs from approved)
  - Metric threshold breaches (performance, data drift, output drift)
  - Missing monitoring for approved models
"""
from __future__ import annotations

from typing import Any


_VALID_APPROVAL_STATUS = frozenset({
    'approved', 'conditional', 'withdrawn', 'deprecated', 'in_review', 'draft',
})

_VALID_METRIC_STATUS = frozenset({
    'normal', 'warning', 'breach', 'unknown',
})

_MAX_STR = 512


def _clean(value: Any, max_len: int = _MAX_STR) -> str:
    if value is None:
        return ''
    return str(value).strip()[:max_len]


def normalize_model_registry_entry(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a model registry entry from a forwarder payload.

    Required: model_id, version, intended_use, approval_status
    Optional: approved_by, approved_at, validation_baseline, metadata
    """
    if not isinstance(payload, dict):
        return None

    model_id = _clean(payload.get('model_id'))
    version = _clean(payload.get('version'), 128)
    intended_use = _clean(payload.get('intended_use'), 1024)
    approval_status = _clean(payload.get('approval_status')).lower()

    if not model_id or not version or not intended_use:
        return None
    if approval_status and approval_status not in _VALID_APPROVAL_STATUS:
        return None

    baseline = payload.get('validation_baseline')
    clean_baseline = None
    if isinstance(baseline, dict):
        clean_baseline = {}
        for k, v in baseline.items():
            clean_baseline[_clean(k, 128)] = _clean(v, 256)

    return {
        'model_id': model_id,
        'version': version,
        'intended_use': intended_use,
        'approval_status': approval_status or 'draft',
        'approved_by': _clean(payload.get('approved_by')),
        'approved_at': _clean(payload.get('approved_at'), 64),
        'validation_baseline': clean_baseline,
        'metadata': payload.get('metadata') if isinstance(payload.get('metadata'), dict) else {},
    }


def normalize_model_metric(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a runtime model metric observation.

    Required: model_id, version, metric_name, metric_value, observed_at
    Optional: threshold, baseline_value, status, unit, details
    """
    if not isinstance(payload, dict):
        return None

    model_id = _clean(payload.get('model_id'))
    version = _clean(payload.get('version'), 128)
    metric_name = _clean(payload.get('metric_name'), 256)
    observed_at = _clean(payload.get('observed_at'), 64)
    status = _clean(payload.get('status')).lower()

    if not model_id or not metric_name or not observed_at:
        return None
    if status and status not in _VALID_METRIC_STATUS:
        return None

    try:
        metric_value = float(payload.get('metric_value'))
    except (TypeError, ValueError):
        return None

    threshold = None
    if payload.get('threshold') is not None:
        try:
            threshold = float(payload.get('threshold'))
        except (TypeError, ValueError):
            pass

    baseline_value = None
    if payload.get('baseline_value') is not None:
        try:
            baseline_value = float(payload.get('baseline_value'))
        except (TypeError, ValueError):
            pass

    return {
        'model_id': model_id,
        'version': version,
        'metric_name': metric_name,
        'metric_value': metric_value,
        'threshold': threshold,
        'baseline_value': baseline_value,
        'status': status or ('breach' if threshold is not None and metric_value > threshold else 'normal'),
        'unit': _clean(payload.get('unit'), 64),
        'observed_at': observed_at,
        'details': _clean(payload.get('details'), 1024),
    }


def assess_metric_drift(metric: dict, baseline: dict | None) -> dict[str, Any]:
    """Assess a single metric against its validation baseline.

    Returns:
      - drift_detected: bool
      - severity: 'normal', 'warning', 'breach'
      - detail: human-readable explanation
    """
    metric_name = metric.get('metric_name', '')
    value = metric.get('metric_value')
    threshold = metric.get('threshold')
    baseline_value = metric.get('baseline_value')

    # If a baseline dict is provided, try to get the baseline for this metric
    if baseline and metric_name in baseline:
        try:
            baseline_value = float(baseline[metric_name])
        except (TypeError, ValueError):
            pass

    if threshold is not None and value is not None and value > threshold:
        return {
            'drift_detected': True,
            'severity': 'breach',
            'detail': f'{metric_name}={value} exceeds threshold={threshold}',
        }

    if baseline_value is not None and value is not None:
        drift_pct = abs(value - baseline_value) / max(abs(baseline_value), 1e-10) * 100
        if drift_pct > 20:
            return {
                'drift_detected': True,
                'severity': 'warning',
                'detail': f'{metric_name}={value} deviates {drift_pct:.1f}% from baseline={baseline_value}',
            }
        if drift_pct > 50:
            return {
                'drift_detected': True,
                'severity': 'breach',
                'detail': f'{metric_name}={value} deviates {drift_pct:.1f}% from baseline={baseline_value}',
            }

    return {
        'drift_detected': False,
        'severity': 'normal',
        'detail': f'{metric_name}={value} within normal range',
    }
