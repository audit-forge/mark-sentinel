"""Model monitoring assessment: drift detection, threshold breaches, and gap analysis.

Evaluates ingested model registry entries and runtime metrics to detect:
  - Version drift: running version differs from approved version
  - Metric threshold breaches: performance, data drift, output drift
  - Missing monitoring: approved models without recent metric observations
  - Approval gaps: models in use without recorded approval

Provides evidence inputs for qualified QA/CSV review — does not replace
human judgment, CSV validation, or regulatory determination.
"""
from __future__ import annotations

from typing import Any

from connectors.model_monitoring_connector import (
    normalize_model_registry_entry,
    normalize_model_metric,
    assess_metric_drift,
)


CATEGORY = "AI-MM"
CHECK_ID_PREFIX = "AI-MM"


def assess_model_monitoring(
    registry_entries: list[dict[str, Any]],
    metric_observations: list[dict[str, Any]],
    monitoring_window_hours: int = 24,
) -> dict[str, Any]:
    """Assess model monitoring status across registry and metrics.

    Args:
        registry_entries: list of normalized model registry entries
        metric_observations: list of normalized metric observations
        monitoring_window_hours: max hours since last metric before flagging gap

    Returns:
        {
          'total_models': int,
          'approved_models': int,
          'monitored_models': int,
          'version_drifts': [...],
          'threshold_breaches': [...],
          'monitoring_gaps': [...],
          'approval_gaps': [...],
          'findings': [...],
          'monitoring_score': float,
        }
    """
    findings = []
    version_drifts = []
    threshold_breaches = []
    monitoring_gaps = []
    approval_gaps = []

    # Index metrics by model_id
    metrics_by_model: dict[str, list[dict]] = {}
    for metric in metric_observations:
        key = metric.get('model_id', '')
        if key:
            metrics_by_model.setdefault(key, []).append(metric)

    # Index registry by model_id (pick the latest version)
    registry_by_model: dict[str, dict] = {}
    for entry in registry_entries:
        mid = entry.get('model_id', '')
        if not mid:
            continue
        existing = registry_by_model.get(mid)
        if not existing or entry.get('version', '') > existing.get('version', ''):
            registry_by_model[mid] = entry

    total_models = len(registry_by_model)
    approved_models = sum(1 for e in registry_by_model.values()
                          if e.get('approval_status') == 'approved')
    monitored_models = sum(1 for mid in registry_by_model if mid in metrics_by_model)

    for mid, entry in registry_by_model.items():
        status = entry.get('approval_status', 'draft')

        # Check for approval gaps on models in use (has metrics but not approved)
        model_metrics = metrics_by_model.get(mid, [])
        if model_metrics and status not in ('approved', 'conditional'):
            approval_gaps.append({
                'model_id': mid,
                'version': entry.get('version', ''),
                'issue': f'Model has runtime metrics but approval status is {status}',
            })
            findings.append({
                'check_id': f'{CHECK_ID_PREFIX}-001',
                'severity': 'HIGH',
                'title': f'Unapproved model in use: {mid}',
                'detail': f'Model {mid} v{entry.get("version","")} has runtime observations but approval status is "{status}". '
                          f'Approved models must have recorded approval before deployment.',
                'frameworks': {
                    'FDA AI/ML SaMD': 'Predetermined Change Control Plan',
                    'ICH E6(R2)': '§5.0',
                    'NIST AI RMF': 'GOVERN 2.2',
                },
            })

        # Check for version drift: metrics reference a different version than approved
        if status == 'approved':
            approved_version = entry.get('version', '')
            for metric in model_metrics:
                metric_version = metric.get('version', '')
                if metric_version and metric_version != approved_version:
                    version_drifts.append({
                        'model_id': mid,
                        'approved_version': approved_version,
                        'observed_version': metric_version,
                        'metric_name': metric.get('metric_name', ''),
                    })
                    findings.append({
                        'check_id': f'{CHECK_ID_PREFIX}-002',
                        'severity': 'HIGH',
                        'title': f'Version drift: {mid}',
                        'detail': f'Approved version is {approved_version} but runtime metric '
                                  f'{metric.get("metric_name","")} was observed for version {metric_version}',
                        'frameworks': {
                            'FDA AI/ML SaMD': 'Action Plan',
                            'ICH E6(R2)': '§5.5.3',
                            'NIST AI RMF': 'MEASURE 2.9',
                        },
                    })

        # Check metric thresholds and drift
        baseline = entry.get('validation_baseline')
        for metric in model_metrics:
            assessment = assess_metric_drift(metric, baseline)
            if assessment['drift_detected']:
                threshold_breaches.append({
                    'model_id': mid,
                    'version': metric.get('version', ''),
                    'metric_name': metric.get('metric_name', ''),
                    'metric_value': metric.get('metric_value'),
                    'severity': assessment['severity'],
                    'detail': assessment['detail'],
                })
                sev = 'CRITICAL' if assessment['severity'] == 'breach' else 'HIGH'
                findings.append({
                    'check_id': f'{CHECK_ID_PREFIX}-003',
                    'severity': sev,
                    'title': f'Metric {assessment["severity"]}: {mid} {metric.get("metric_name","")}',
                    'detail': assessment['detail'],
                    'frameworks': {
                        'FDA AI/ML SaMD': 'Predetermined Change Control Plan',
                        'NIST AI RMF': 'MEASURE 2.6',
                        'GxP ALCOA+': 'accurate',
                    },
                })

        # Check for monitoring gaps (approved model with no metrics)
        if status == 'approved' and not model_metrics:
            monitoring_gaps.append({
                'model_id': mid,
                'version': entry.get('version', ''),
                'issue': 'Approved model has no runtime metric observations',
            })
            findings.append({
                'check_id': f'{CHECK_ID_PREFIX}-004',
                'severity': 'MEDIUM',
                'title': f'Missing monitoring: {mid}',
                'detail': f'Approved model {mid} v{entry.get("version","")} has no runtime metric observations. '
                          f'Approved models require continuous monitoring per the AI/ML SaMD action plan.',
                'frameworks': {
                    'FDA AI/ML SaMd': 'Action Plan',
                    'NIST AI RMF': 'MEASURE 2.6',
                },
            })

    monitoring_score = monitored_models / approved_models if approved_models else 0.0

    return {
        'total_models': total_models,
        'approved_models': approved_models,
        'monitored_models': monitored_models,
        'version_drifts': version_drifts,
        'threshold_breaches': threshold_breaches,
        'monitoring_gaps': monitoring_gaps,
        'approval_gaps': approval_gaps,
        'findings': findings,
        'monitoring_score': round(monitoring_score, 2),
    }
