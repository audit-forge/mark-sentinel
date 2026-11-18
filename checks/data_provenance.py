"""Training-data provenance and integrity assessment.

Evaluates ingested dataset registry entries and pipeline events to detect:
  - Unapproved dataset modifications
  - Checksum mismatches (data integrity violations)
  - Training runs on unapproved datasets
  - Lineage breaks (training references unregistered dataset)
  - Schema or distribution anomalies

Provides evidence inputs for qualified QA/CSV review — does not replace
human judgment, CSV validation, or regulatory determination.
"""
from __future__ import annotations

from typing import Any

from connectors.data_provenance_connector import (
    normalize_dataset_registry,
    normalize_pipeline_event,
)


CATEGORY = "AI-DP"
CHECK_ID_PREFIX = "AI-DP"


def assess_data_provenance(
    datasets: list[dict[str, Any]],
    pipeline_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assess training-data provenance and integrity.

    Args:
        datasets: list of normalized dataset registry entries
        pipeline_events: list of normalized pipeline events

    Returns:
        {
          'total_datasets': int,
          'approved_datasets': int,
          'integrity_violations': [...],
          'unapproved_training': [...],
          'lineage_breaks': [...],
          'anomalies': [...],
          'findings': [...],
          'integrity_score': float,
        }
    """
    findings = []
    integrity_violations = []
    unapproved_training = []
    lineage_breaks = []
    anomalies = []

    # Index datasets by dataset_id (pick the latest version)
    datasets_by_id: dict[str, dict] = {}
    for ds in datasets:
        did = ds.get('dataset_id', '')
        if not did:
            continue
        existing = datasets_by_id.get(did)
        if not existing or ds.get('version', '') > existing.get('version', ''):
            datasets_by_id[did] = ds

    total_datasets = len(datasets_by_id)
    approved_datasets = sum(1 for d in datasets_by_id.values() if d.get('approved'))

    for event in pipeline_events:
        etype = event.get('event_type', '')
        did = event.get('dataset_id', '')

        # Checksum mismatch
        if etype == 'checksum_mismatch' or event.get('integrity_status') == 'mismatch':
            integrity_violations.append({
                'dataset_id': did,
                'version': event.get('version', ''),
                'event_type': etype,
                'detail': event.get('details', 'Checksum mismatch detected'),
            })
            findings.append({
                'check_id': f'{CHECK_ID_PREFIX}-001',
                'severity': 'CRITICAL',
                'title': f'Data integrity violation: {did}',
                'detail': f'Checksum mismatch for dataset {did} v{event.get("version","")}. '
                          f'Training on compromised data may produce unreliable models.',
                'frameworks': {
                    'GxP ALCOA+': 'accurate',
                    'FDA 21 CFR Part 11': '§11.10(e)',
                    'NIST AI RMF': 'MAP 3.5',
                },
            })

        # Unapproved dataset modification
        if etype == 'dataset_modified':
            ds = datasets_by_id.get(did)
            if ds and not ds.get('approved'):
                integrity_violations.append({
                    'dataset_id': did,
                    'version': event.get('version', ''),
                    'event_type': etype,
                    'detail': 'Dataset modified but not approved',
                })
                findings.append({
                    'check_id': f'{CHECK_ID_PREFIX}-002',
                    'severity': 'HIGH',
                    'title': f'Unapproved dataset modification: {did}',
                    'detail': f'Dataset {did} was modified but is not marked as approved. '
                              f'Unapproved data changes may introduce bias or integrity issues.',
                    'frameworks': {
                        'GxP ALCOA+': 'original',
                        'NIST AI RMF': 'MAP 3.5',
                        'ICH E6(R2)': '§5.5.3',
                    },
                })

        # Training run on unapproved dataset
        if etype == 'training_run':
            ds = datasets_by_id.get(did)
            if ds and not ds.get('approved'):
                unapproved_training.append({
                    'dataset_id': did,
                    'version': event.get('version', ''),
                    'model_id': event.get('model_id', ''),
                    'detail': 'Training run on unapproved dataset',
                })
                findings.append({
                    'check_id': f'{CHECK_ID_PREFIX}-003',
                    'severity': 'CRITICAL',
                    'title': f'Training on unapproved data: {did}',
                    'detail': f'Training run for model {event.get("model_id","")} used dataset {did} '
                              f'which is not approved. Models trained on unapproved data '
                              f'may not meet validation requirements.',
                    'frameworks': {
                        'FDA AI/ML SaMD': 'Predetermined Change Control Plan',
                        'GxP ALCOA+': 'original',
                        'NIST AI RMF': 'MAP 3.5',
                    },
                })

        # Training run references unregistered dataset (lineage break)
        if etype == 'training_run' and did not in datasets_by_id:
            lineage_breaks.append({
                'dataset_id': did,
                'model_id': event.get('model_id', ''),
                'detail': 'Training run references unregistered dataset',
            })
            findings.append({
                'check_id': f'{CHECK_ID_PREFIX}-004',
                'severity': 'HIGH',
                'title': f'Lineage break: {did}',
                'detail': f'Training run for model {event.get("model_id","")} references dataset {did} '
                          f'which is not in the registered dataset inventory.',
                'frameworks': {
                    'NIST AI RMF': 'MAP 3.5',
                    'GxP ALCOA+': 'complete',
                },
            })

        # Schema or distribution anomaly
        if etype in ('schema_change', 'distribution_anomaly'):
            anomalies.append({
                'dataset_id': did,
                'version': event.get('version', ''),
                'event_type': etype,
                'detail': event.get('details', ''),
            })
            sev = 'HIGH' if etype == 'distribution_anomaly' else 'MEDIUM'
            findings.append({
                'check_id': f'{CHECK_ID_PREFIX}-005',
                'severity': sev,
                'title': f'Data anomaly: {did} ({etype})',
                'detail': event.get('details', f'{etype} detected for dataset {did}'),
                'frameworks': {
                    'NIST AI RMF': 'MEASURE 2.6',
                    'GxP ALCOA+': 'accurate',
                },
            })

    integrity_score = 1.0
    if total_datasets > 0:
        violation_count = len(integrity_violations) + len(unapproved_training) + len(lineage_breaks)
        integrity_score = max(0.0, 1.0 - (violation_count / total_datasets))

    return {
        'total_datasets': total_datasets,
        'approved_datasets': approved_datasets,
        'integrity_violations': integrity_violations,
        'unapproved_training': unapproved_training,
        'lineage_breaks': lineage_breaks,
        'anomalies': anomalies,
        'findings': findings,
        'integrity_score': round(integrity_score, 2),
    }
