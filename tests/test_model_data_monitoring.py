"""Tests for model monitoring and training-data provenance assessment."""
import tempfile
from pathlib import Path

import pytest

from connectors.model_monitoring_connector import (
    normalize_model_registry_entry,
    normalize_model_metric,
    assess_metric_drift,
)
from connectors.data_provenance_connector import (
    normalize_dataset_registry,
    normalize_pipeline_event,
)
from checks.model_monitoring import assess_model_monitoring
from checks.data_provenance import assess_data_provenance
from storage import AgentStore


# ── Model monitoring normalization tests ────────────────────────────────────

class TestModelMonitoringNormalization:
    def _registry_entry(self, **overrides):
        entry = {
            'model_id': 'gpt-4o-2024',
            'version': '2024-08-06',
            'intended_use': 'Clinical decision support',
            'approval_status': 'approved',
            'approved_by': 'qa@company.com',
            'approved_at': '2026-01-01T00:00:00Z',
        }
        entry.update(overrides)
        return entry

    def test_normalizes_valid_registry_entry(self):
        entry = normalize_model_registry_entry(self._registry_entry())
        assert entry is not None
        assert entry['model_id'] == 'gpt-4o-2024'
        assert entry['approval_status'] == 'approved'

    def test_rejects_missing_model_id(self):
        assert normalize_model_registry_entry(self._registry_entry(model_id='')) is None

    def test_rejects_missing_version(self):
        assert normalize_model_registry_entry(self._registry_entry(version='')) is None

    def test_rejects_invalid_approval_status(self):
        assert normalize_model_registry_entry(self._registry_entry(approval_status='bogus')) is None

    def test_normalizes_validation_baseline(self):
        entry = normalize_model_registry_entry(self._registry_entry(
            validation_baseline={'accuracy': '0.95', 'f1': '0.88'}
        ))
        assert entry is not None
        assert entry['validation_baseline']['accuracy'] == '0.95'

    def _metric(self, **overrides):
        metric = {
            'model_id': 'gpt-4o-2024',
            'version': '2024-08-06',
            'metric_name': 'error_rate',
            'metric_value': 0.05,
            'threshold': 0.10,
            'observed_at': '2026-03-01T10:00:00Z',
        }
        metric.update(overrides)
        return metric

    def test_normalizes_valid_metric(self):
        metric = normalize_model_metric(self._metric())
        assert metric is not None
        assert metric['metric_value'] == 0.05
        assert metric['status'] == 'normal'

    def test_auto_detects_breach(self):
        metric = normalize_model_metric(self._metric(metric_value=0.15, threshold=0.10))
        assert metric['status'] == 'breach'

    def test_rejects_non_numeric_metric_value(self):
        assert normalize_model_metric(self._metric(metric_value='not a number')) is None

    def test_rejects_missing_observed_at(self):
        assert normalize_model_metric(self._metric(observed_at='')) is None


# ── Metric drift assessment tests ────────────────────────────────────────────

class TestMetricDrift:
    def test_threshold_breach(self):
        result = assess_metric_drift(
            {'metric_name': 'error_rate', 'metric_value': 0.15, 'threshold': 0.10},
            None)
        assert result['drift_detected'] is True
        assert result['severity'] == 'breach'

    def test_normal_metric(self):
        result = assess_metric_drift(
            {'metric_name': 'error_rate', 'metric_value': 0.05, 'threshold': 0.10},
            None)
        assert result['drift_detected'] is False

    def test_baseline_drift_warning(self):
        result = assess_metric_drift(
            {'metric_name': 'accuracy', 'metric_value': 0.75, 'baseline_value': 0.95},
            None)
        assert result['drift_detected'] is True
        assert result['severity'] == 'warning'

    def test_baseline_from_dict(self):
        result = assess_metric_drift(
            {'metric_name': 'f1', 'metric_value': 0.60, 'baseline_value': None},
            {'f1': '0.88'})
        assert result['drift_detected'] is True


# ── Model monitoring assessment tests ────────────────────────────────────────

class TestModelMonitoringAssessment:
    def test_empty_inputs(self):
        result = assess_model_monitoring([], [])
        assert result['total_models'] == 0
        assert result['monitoring_score'] == 0.0

    def test_approved_model_with_no_metrics(self):
        registry = [normalize_model_registry_entry({
            'model_id': 'model-1', 'version': '1.0',
            'intended_use': 'test', 'approval_status': 'approved',
        })]
        result = assess_model_monitoring(registry, [])
        assert result['approved_models'] == 1
        assert len(result['monitoring_gaps']) == 1
        assert result['findings'][0]['check_id'] == 'AI-MM-004'

    def test_version_drift(self):
        registry = [normalize_model_registry_entry({
            'model_id': 'model-1', 'version': '2.0',
            'intended_use': 'test', 'approval_status': 'approved',
        })]
        metrics = [normalize_model_metric({
            'model_id': 'model-1', 'version': '1.0',
            'metric_name': 'accuracy', 'metric_value': 0.9,
            'observed_at': '2026-01-01T00:00:00Z',
        })]
        result = assess_model_monitoring(registry, metrics)
        assert len(result['version_drifts']) == 1
        assert result['version_drifts'][0]['approved_version'] == '2.0'
        assert result['version_drifts'][0]['observed_version'] == '1.0'

    def test_threshold_breach_finding(self):
        registry = [normalize_model_registry_entry({
            'model_id': 'model-1', 'version': '1.0',
            'intended_use': 'test', 'approval_status': 'approved',
        })]
        metrics = [normalize_model_metric({
            'model_id': 'model-1', 'version': '1.0',
            'metric_name': 'error_rate', 'metric_value': 0.15,
            'threshold': 0.10, 'observed_at': '2026-01-01T00:00:00Z',
        })]
        result = assess_model_monitoring(registry, metrics)
        assert len(result['threshold_breaches']) == 1
        assert result['threshold_breaches'][0]['severity'] == 'breach'

    def test_unapproved_model_in_use(self):
        registry = [normalize_model_registry_entry({
            'model_id': 'model-1', 'version': '1.0',
            'intended_use': 'test', 'approval_status': 'draft',
        })]
        metrics = [normalize_model_metric({
            'model_id': 'model-1', 'version': '1.0',
            'metric_name': 'latency', 'metric_value': 50,
            'observed_at': '2026-01-01T00:00:00Z',
        })]
        result = assess_model_monitoring(registry, metrics)
        assert len(result['approval_gaps']) == 1

    def test_monitoring_score(self):
        registry = [
            normalize_model_registry_entry({
                'model_id': 'm1', 'version': '1.0',
                'intended_use': 'test', 'approval_status': 'approved',
            }),
            normalize_model_registry_entry({
                'model_id': 'm2', 'version': '1.0',
                'intended_use': 'test', 'approval_status': 'approved',
            }),
        ]
        metrics = [normalize_model_metric({
            'model_id': 'm1', 'version': '1.0',
            'metric_name': 'acc', 'metric_value': 0.9,
            'observed_at': '2026-01-01T00:00:00Z',
        })]
        result = assess_model_monitoring(registry, metrics)
        assert result['approved_models'] == 2
        assert result['monitored_models'] == 1
        assert result['monitoring_score'] == 0.5


# ── Model monitoring storage tests ──────────────────────────────────────────

class TestModelMonitoringStorage:
    def test_upsert_and_retrieve_registry(self, tmp_path):
        store = AgentStore(tmp_path / 'agents.db')
        entry = normalize_model_registry_entry({
            'model_id': 'm1', 'version': '1.0',
            'intended_use': 'test', 'approval_status': 'approved',
        })
        store.upsert_model_registry_entry(entry)
        entries = store.get_model_registry_entries()
        assert len(entries) == 1
        assert entries[0]['model_id'] == 'm1'

    def test_add_and_retrieve_metrics(self, tmp_path):
        store = AgentStore(tmp_path / 'agents.db')
        metric = normalize_model_metric({
            'model_id': 'm1', 'version': '1.0',
            'metric_name': 'accuracy', 'metric_value': 0.95,
            'observed_at': '2026-01-01T00:00:00Z',
        })
        store.add_model_metric(metric)
        metrics = store.get_model_metrics('m1')
        assert len(metrics) == 1
        assert metrics[0]['metric_value'] == 0.95


# ── Data provenance normalization tests ─────────────────────────────────────

class TestDataProvenanceNormalization:
    def _dataset(self, **overrides):
        ds = {
            'dataset_id': 'ds-001',
            'source': 'internal://clinical-records',
            'owner': 'data-team@company.com',
            'version': '2.0',
            'checksum': 'abc123',
            'approved': True,
        }
        ds.update(overrides)
        return ds

    def test_normalizes_valid_dataset(self):
        ds = normalize_dataset_registry(self._dataset())
        assert ds is not None
        assert ds['dataset_id'] == 'ds-001'
        assert ds['approved'] is True

    def test_rejects_missing_dataset_id(self):
        assert normalize_dataset_registry(self._dataset(dataset_id='')) is None

    def test_rejects_missing_source(self):
        assert normalize_dataset_registry(self._dataset(source='')) is None

    def test_normalizes_lineage_list(self):
        ds = normalize_dataset_registry(self._dataset(
            lineage=['ds-000', 'ds-001-raw']
        ))
        assert ds is not None
        assert ds['lineage'] == ['ds-000', 'ds-001-raw']

    def _event(self, **overrides):
        ev = {
            'dataset_id': 'ds-001',
            'event_type': 'training_run',
            'occurred_at': '2026-03-01T10:00:00Z',
            'model_id': 'model-1',
        }
        ev.update(overrides)
        return ev

    def test_normalizes_valid_event(self):
        ev = normalize_pipeline_event(self._event())
        assert ev is not None
        assert ev['event_type'] == 'training_run'

    def test_rejects_invalid_event_type(self):
        assert normalize_pipeline_event(self._event(event_type='bogus')) is None

    def test_rejects_missing_dataset_id(self):
        assert normalize_pipeline_event(self._event(dataset_id='')) is None


# ── Data provenance assessment tests ────────────────────────────────────────

class TestDataProvenanceAssessment:
    def test_empty_inputs(self):
        result = assess_data_provenance([], [])
        assert result['total_datasets'] == 0
        assert result['integrity_score'] == 1.0

    def test_checksum_mismatch(self):
        events = [normalize_pipeline_event({
            'dataset_id': 'ds-1', 'event_type': 'checksum_mismatch',
            'occurred_at': '2026-01-01T00:00:00Z',
            'integrity_status': 'mismatch',
        })]
        result = assess_data_provenance([], events)
        assert len(result['integrity_violations']) == 1
        assert result['findings'][0]['severity'] == 'CRITICAL'

    def test_unapproved_training(self):
        datasets = [normalize_dataset_registry({
            'dataset_id': 'ds-1', 'source': 'test', 'version': '1.0',
            'approved': False,
        })]
        events = [normalize_pipeline_event({
            'dataset_id': 'ds-1', 'event_type': 'training_run',
            'occurred_at': '2026-01-01T00:00:00Z', 'model_id': 'm-1',
        })]
        result = assess_data_provenance(datasets, events)
        assert len(result['unapproved_training']) == 1

    def test_lineage_break(self):
        events = [normalize_pipeline_event({
            'dataset_id': 'unregistered-ds', 'event_type': 'training_run',
            'occurred_at': '2026-01-01T00:00:00Z', 'model_id': 'm-1',
        })]
        result = assess_data_provenance([], events)
        assert len(result['lineage_breaks']) == 1

    def test_distribution_anomaly(self):
        events = [normalize_pipeline_event({
            'dataset_id': 'ds-1', 'event_type': 'distribution_anomaly',
            'occurred_at': '2026-01-01T00:00:00Z',
            'details': 'Label distribution shifted 30%',
        })]
        result = assess_data_provenance([], events)
        assert len(result['anomalies']) == 1
        assert result['findings'][0]['severity'] == 'HIGH'

    def test_integrity_score_with_violations(self):
        datasets = [normalize_dataset_registry({
            'dataset_id': 'ds-1', 'source': 'test', 'version': '1.0', 'approved': True,
        })]
        events = [normalize_pipeline_event({
            'dataset_id': 'ds-1', 'event_type': 'checksum_mismatch',
            'occurred_at': '2026-01-01T00:00:00Z', 'integrity_status': 'mismatch',
        })]
        result = assess_data_provenance(datasets, events)
        assert result['integrity_score'] < 1.0


# ── Data provenance storage tests ───────────────────────────────────────────

class TestDataProvenanceStorage:
    def test_upsert_and_retrieve_dataset(self, tmp_path):
        store = AgentStore(tmp_path / 'agents.db')
        ds = normalize_dataset_registry({
            'dataset_id': 'ds-1', 'source': 'test', 'version': '1.0', 'approved': True,
        })
        store.upsert_dataset_registry_entry(ds)
        entries = store.get_dataset_registry_entries()
        assert len(entries) == 1
        assert entries[0]['dataset_id'] == 'ds-1'
        assert entries[0]['approved'] is True

    def test_add_and_retrieve_pipeline_event(self, tmp_path):
        store = AgentStore(tmp_path / 'agents.db')
        ev = normalize_pipeline_event({
            'dataset_id': 'ds-1', 'event_type': 'training_run',
            'occurred_at': '2026-01-01T00:00:00Z', 'model_id': 'm-1',
        })
        store.add_data_pipeline_event(ev)
        events = store.get_data_pipeline_events('ds-1')
        assert len(events) == 1
        assert events[0]['event_type'] == 'training_run'
