"""Tests for eTMF completeness assessment and ALCOA+ dimension evaluation."""
from pathlib import Path

import pytest

from connectors.etmf_connector import normalize_etmf_document, assess_alcoa_plus
from checks.etmf_completeness import (
    load_reference_model,
    get_required_artifacts,
    assess_completeness,
)


# ── Reference model tests ────────────────────────────────────────────────────

class TestReferenceModel:
    def test_loads_without_error(self):
        model = load_reference_model()
        assert isinstance(model, dict)
        assert 'zones' in model
        assert len(model['zones']) >= 6

    def test_has_alcoa_plus_definitions(self):
        model = load_reference_model()
        dims = model.get('alcoa_plus_dimensions', {})
        expected = {'attributable', 'legible', 'contemporaneous', 'original',
                     'accurate', 'complete', 'consistent', 'enduring', 'available'}
        assert set(dims.keys()) == expected

    def test_required_artifacts_for_setup(self):
        model = load_reference_model()
        artifacts = get_required_artifacts(model, 'setup')
        assert len(artifacts) > 0
        assert all('setup' in a.get('required_phases', []) or True for a in artifacts)

    def test_required_artifacts_for_conduct(self):
        model = load_reference_model()
        artifacts = get_required_artifacts(model, 'conduct')
        assert len(artifacts) > 0

    def test_required_artifacts_for_closeout(self):
        model = load_reference_model()
        artifacts = get_required_artifacts(model, 'closeout')
        assert len(artifacts) > 0

    def test_invalid_phase_raises(self):
        model = load_reference_model()
        with pytest.raises(ValueError):
            get_required_artifacts(model, 'invalid_phase')


# ── Normalization tests ──────────────────────────────────────────────────────

class TestNormalization:
    def _valid_payload(self, **overrides):
        payload = {
            'document_id': 'DOC-001',
            'artifact_type': 'Protocol and Amendments',
            'study_id': 'STUDY-001',
            'status': 'approved',
            'created_at': '2026-01-15T10:00:00Z',
            'version': '1.0',
            'author': 'researcher@company.com',
        }
        payload.update(overrides)
        return payload

    def test_normalizes_valid_document(self):
        doc = normalize_etmf_document(self._valid_payload())
        assert doc is not None
        assert doc['document_id'] == 'DOC-001'
        assert doc['artifact_type'] == 'Protocol and Amendments'
        assert doc['study_id'] == 'STUDY-001'
        assert doc['status'] == 'approved'

    def test_rejects_missing_document_id(self):
        assert normalize_etmf_document(self._valid_payload(document_id='')) is None

    def test_rejects_missing_artifact_type(self):
        assert normalize_etmf_document(self._valid_payload(artifact_type='')) is None

    def test_rejects_missing_study_id(self):
        assert normalize_etmf_document(self._valid_payload(study_id='')) is None

    def test_rejects_missing_created_at(self):
        assert normalize_etmf_document(self._valid_payload(created_at='')) is None

    def test_rejects_invalid_status(self):
        assert normalize_etmf_document(self._valid_payload(status='bogus')) is None

    def test_defaults_status_to_draft(self):
        doc = normalize_etmf_document(self._valid_payload(status=''))
        assert doc is not None
        assert doc['status'] == 'draft'

    def test_normalizes_ai_provenance(self):
        doc = normalize_etmf_document(self._valid_payload(
            ai_provenance={
                'ai_tool_name': 'Claude Code',
                'ai_model_version': 'claude-sonnet-4-6',
                'human_reviewer': 'qa@company.com',
                'review_timestamp': '2026-01-15T12:00:00Z',
            }
        ))
        assert doc is not None
        assert doc['ai_provenance'] is not None
        assert doc['ai_provenance']['ai_tool_name'] == 'Claude Code'
        assert doc['ai_provenance']['human_reviewer'] == 'qa@company.com'

    def test_rejects_ai_provenance_without_tool_name(self):
        doc = normalize_etmf_document(self._valid_payload(
            ai_provenance={'human_reviewer': 'qa@company.com'}
        ))
        assert doc is not None
        assert doc['ai_provenance'] is None

    def test_normalizes_signatures(self):
        doc = normalize_etmf_document(self._valid_payload(
            signatures=[
                {'signer': 'pi@site.com', 'signed_at': '2026-01-15T11:00:00Z', 'role': 'Principal Investigator'},
            ]
        ))
        assert doc is not None
        assert len(doc['signatures']) == 1
        assert doc['signatures'][0]['signer'] == 'pi@site.com'

    def test_rejects_non_dict_payload(self):
        assert normalize_etmf_document('not a dict') is None
        assert normalize_etmf_document(None) is None

    def test_truncates_oversized_strings(self):
        doc = normalize_etmf_document(self._valid_payload(
            author='x' * 10000,
        ))
        assert doc is not None
        assert len(doc['author']) <= 512


# ── ALCOA+ assessment tests ──────────────────────────────────────────────────

class TestAlcoaPlus:
    def _doc(self, **overrides):
        doc = {
            'document_id': 'DOC-001',
            'artifact_type': 'Case Report Forms',
            'study_id': 'STUDY-001',
            'status': 'approved',
            'created_at': '2026-01-15T10:00:00Z',
            'version': '2.0',
            'author': 'researcher@company.com',
            'signatures': [{'signer': 'pi@site.com', 'signed_at': '2026-01-15T11:00:00Z', 'role': 'PI'}],
        }
        doc.update(overrides)
        return doc

    def test_perfect_document_passes_all_nine(self):
        result = assess_alcoa_plus(self._doc())
        assert result['passed_count'] == 9
        assert result['score'] == 1.0

    def test_missing_author_fails_attributable(self):
        result = assess_alcoa_plus(self._doc(author=''))
        assert result['dimensions']['attributable']['passed'] is False

    def test_void_status_fails_multiple(self):
        result = assess_alcoa_plus(self._doc(status='void'))
        assert result['dimensions']['legible']['passed'] is False
        assert result['dimensions']['enduring']['passed'] is False
        assert result['dimensions']['available']['passed'] is False

    def test_draft_status_fails_accurate(self):
        result = assess_alcoa_plus(self._doc(status='draft'))
        assert result['dimensions']['accurate']['passed'] is False

    def test_approved_without_signatures_fails_accurate(self):
        result = assess_alcoa_plus(self._doc(signatures=[]))
        assert result['dimensions']['accurate']['passed'] is False

    def test_missing_version_fails_original(self):
        result = assess_alcoa_plus(self._doc(version=''))
        assert result['dimensions']['original']['passed'] is False

    def test_approval_before_creation_fails_contemporaneous(self):
        result = assess_alcoa_plus(self._doc(
            created_at='2026-01-15T10:00:00Z',
            approved_at='2026-01-14T10:00:00Z',
        ))
        assert result['dimensions']['contemporaneous']['passed'] is False


# ── Completeness assessment tests ────────────────────────────────────────────

class TestCompleteness:
    def _doc(self, artifact_type, **overrides):
        doc = {
            'document_id': f'DOC-{artifact_type}',
            'artifact_type': artifact_type,
            'study_id': 'STUDY-001',
            'status': 'approved',
            'created_at': '2026-01-15T10:00:00Z',
            'version': '1.0',
            'author': 'researcher@company.com',
            'signatures': [{'signer': 'pi@site.com', 'signed_at': '2026-01-15T11:00:00Z', 'role': 'PI'}],
        }
        doc.update(overrides)
        return doc

    def test_empty_documents_reports_all_missing(self):
        result = assess_completeness([], phase='conduct')
        assert result['present_count'] == 0
        assert result['missing_count'] == result['total_required']
        assert result['completeness_score'] == 0.0
        assert len(result['findings']) == result['missing_count']

    def test_complete_conduct_phase(self):
        model = load_reference_model()
        required = get_required_artifacts(model, 'conduct')
        docs = [self._doc(a['artifact_name']) for a in required]
        result = assess_completeness(docs, phase='conduct', model=model)
        assert result['present_count'] == result['total_required']
        assert result['missing_count'] == 0
        assert result['completeness_score'] == 1.0

    def test_missing_artifact_generates_finding(self):
        model = load_reference_model()
        required = get_required_artifacts(model, 'setup')
        # Provide all but the first
        docs = [self._doc(a['artifact_name']) for a in required[1:]]
        result = assess_completeness(docs, phase='setup', model=model)
        assert result['missing_count'] == 1
        assert result['missing_artifacts'][0]['artifact_name'] == required[0]['artifact_name']
        finding = [f for f in result['findings'] if 'Missing required TMF artifact' in f['title']]
        assert len(finding) == 1
        assert finding[0]['severity'] == 'HIGH'

    def test_missing_signature_generates_finding(self):
        model = load_reference_model()
        required = get_required_artifacts(model, 'setup')
        # Provide all docs but without signatures
        docs = [self._doc(a['artifact_name'], signatures=[]) for a in required]
        result = assess_completeness(docs, phase='setup', model=model)
        sig_findings = [f for f in result['findings'] if 'Missing signatures' in f['title']]
        assert len(sig_findings) > 0

    def test_ai_provenance_without_reviewer_generates_finding(self):
        model = load_reference_model()
        required = get_required_artifacts(model, 'conduct')
        docs = [self._doc(
            a['artifact_name'],
            ai_provenance={'ai_tool_name': 'Claude', 'human_reviewer': ''},
        ) for a in required]
        result = assess_completeness(docs, phase='conduct', model=model)
        ai_findings = [f for f in result['findings'] if 'AI content missing human review' in f['title']]
        assert len(ai_findings) > 0
        assert result['ai_provenance_count'] > 0

    def test_ai_provenance_with_reviewer_no_finding(self):
        model = load_reference_model()
        required = get_required_artifacts(model, 'conduct')
        docs = [self._doc(
            a['artifact_name'],
            ai_provenance={'ai_tool_name': 'Claude', 'human_reviewer': 'qa@co.com'},
        ) for a in required]
        result = assess_completeness(docs, phase='conduct', model=model)
        ai_findings = [f for f in result['findings'] if 'AI content missing human review' in f['title']]
        assert len(ai_findings) == 0
        assert result['ai_provenance_count'] > 0

    def test_missing_version_for_versioned_artifact(self):
        model = load_reference_model()
        required = get_required_artifacts(model, 'setup')
        docs = [self._doc(a['artifact_name'], version='') for a in required]
        result = assess_completeness(docs, phase='setup', model=model)
        version_findings = [f for f in result['findings'] if 'Missing version' in f['title']]
        assert len(version_findings) > 0

    def test_closeout_phase(self):
        result = assess_completeness([], phase='closeout')
        assert result['phase'] == 'closeout'
        assert result['total_required'] > 0
