"""Normalize eTMF document metadata for completeness and ALCOA+ assessment.

This module is credential-free. A customer-controlled forwarder polls their
eTMF system (Veeva Vault, PhlexElection, Montrium, etc.) and sends normalized
document metadata to Arckon's authenticated ingest endpoint. Arckon never
receives eTMF system credentials or document contents — only metadata.

The normalized metadata is evaluated against the DIA TMF Reference Model
(see profiles/tmf_reference_model.json) to assess completeness and ALCOA+
data integrity dimensions.
"""
from __future__ import annotations

import re
from typing import Any


_VALID_STATUSES = frozenset({
    'draft', 'submitted', 'in_review', 'approved', 'rejected',
    'superseded', 'archived', 'void',
})

_VALID_PHASES = frozenset({'setup', 'conduct', 'closeout'})

_MAX_STR_LEN = 512
_MAX_META_LEN = 4096


def _clean_str(value: Any, max_len: int = _MAX_STR_LEN) -> str:
    if value is None:
        return ''
    return str(value).strip()[:max_len]


def normalize_etmf_document(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return normalized eTMF document metadata from a forwarder payload, or None.

    Required fields: document_id, artifact_type, study_id, status, created_at
    Optional fields: site_id, version, author, approver, approved_at, signatures,
                    ai_provenance, source_system, metadata

    All string fields are length-limited to prevent stored XSS and DB bloat.
    """
    if not isinstance(payload, dict):
        return None

    doc_id = _clean_str(payload.get('document_id'))
    artifact_type = _clean_str(payload.get('artifact_type'))
    study_id = _clean_str(payload.get('study_id'))
    status = _clean_str(payload.get('status')).lower()

    if not doc_id or not artifact_type or not study_id:
        return None
    if status and status not in _VALID_STATUSES:
        return None

    created_at = _clean_str(payload.get('created_at'), 64)
    if not created_at:
        return None

    version = _clean_str(payload.get('version'), 128)
    author = _clean_str(payload.get('author'))
    approver = _clean_str(payload.get('approver'))
    approved_at = _clean_str(payload.get('approved_at'), 64)
    site_id = _clean_str(payload.get('site_id'), 128)
    source_system = _clean_str(payload.get('source_system'), 128)

    signatures = payload.get('signatures', [])
    if not isinstance(signatures, list):
        signatures = []
    clean_sigs = []
    for sig in signatures[:20]:
        if not isinstance(sig, dict):
            continue
        clean_sigs.append({
            'signer': _clean_str(sig.get('signer')),
            'signed_at': _clean_str(sig.get('signed_at'), 64),
            'role': _clean_str(sig.get('role'), 128),
        })

    ai_provenance = payload.get('ai_provenance')
    clean_ai = None
    if isinstance(ai_provenance, dict):
        clean_ai = {
            'ai_tool_name': _clean_str(ai_provenance.get('ai_tool_name'), 256),
            'ai_model_version': _clean_str(ai_provenance.get('ai_model_version'), 128),
            'ai_inputs': _clean_str(ai_provenance.get('ai_inputs'), 1024),
            'human_reviewer': _clean_str(ai_provenance.get('human_reviewer')),
            'review_timestamp': _clean_str(ai_provenance.get('review_timestamp'), 64),
        }
        if not clean_ai['ai_tool_name']:
            clean_ai = None

    metadata = payload.get('metadata', {})
    if not isinstance(metadata, dict):
        metadata = {}

    return {
        'document_id': doc_id,
        'artifact_type': artifact_type,
        'study_id': study_id,
        'site_id': site_id,
        'version': version,
        'author': author,
        'approver': approver,
        'approved_at': approved_at,
        'created_at': created_at,
        'status': status or 'draft',
        'signatures': clean_sigs,
        'ai_provenance': clean_ai,
        'source_system': source_system or 'unknown',
        'metadata': metadata,
    }


# ALCOA+ dimension checks. Each returns (dimension, passed, detail).
# These are heuristic checks against normalized metadata — they do not
# replace qualified human QA review.

def _check_attributable(doc: dict) -> tuple[str, bool, str]:
    author = doc.get('author', '')
    if not author:
        return 'attributable', False, 'No author recorded'
    return 'attributable', True, f'Author: {author}'


def _check_legible(doc: dict) -> tuple[str, bool, str]:
    status = doc.get('status', '')
    if status in ('void', 'rejected'):
        return 'legible', False, f'Document status is {status}'
    return 'legible', True, 'Retrievable approved record'


def _check_contemporaneous(doc: dict) -> tuple[str, bool, str]:
    created = doc.get('created_at', '')
    approved = doc.get('approved_at', '')
    if not created:
        return 'contemporaneous', False, 'Missing creation timestamp'
    if approved and approved < created:
        return 'contemporaneous', False, 'Approval before creation'
    return 'contemporaneous', True, 'Timestamps are consistent'


def _check_original(doc: dict) -> tuple[str, bool, str]:
    version = doc.get('version', '')
    if not version:
        return 'original', False, 'No version identifier'
    return 'original', True, f'Version: {version}'


def _check_accurate(doc: dict) -> tuple[str, bool, str]:
    status = doc.get('status', '')
    if status in ('draft', 'in_review'):
        return 'accurate', False, f'Document is {status}, not approved'
    sigs = doc.get('signatures', [])
    if not sigs and status == 'approved':
        return 'accurate', False, 'Approved without signatures'
    return 'accurate', True, 'Approved with review'


def _check_complete(doc: dict) -> tuple[str, bool, str]:
    if not doc.get('artifact_type'):
        return 'complete', False, 'Missing artifact type'
    if not doc.get('study_id'):
        return 'complete', False, 'Missing study ID'
    return 'complete', True, 'Required fields present'


def _check_consistent(doc: dict) -> tuple[str, bool, str]:
    status = doc.get('status', '')
    version = doc.get('version', '')
    if status == 'superseded' and not version:
        return 'consistent', False, 'Superseded without version'
    return 'consistent', True, 'Version state is consistent'


def _check_enduring(doc: dict) -> tuple[str, bool, str]:
    status = doc.get('status', '')
    if status == 'void':
        return 'enduring', False, 'Document is voided'
    return 'enduring', True, 'Retained'


def _check_available(doc: dict) -> tuple[str, bool, str]:
    status = doc.get('status', '')
    if status == 'archived':
        return 'available', True, 'Archived and retrievable'
    if status in ('void',):
        return 'available', False, 'Voided, not available'
    return 'available', True, 'Available'

_ALCOA_CHECKS = [
    _check_attributable, _check_legible, _check_contemporaneous,
    _check_original, _check_accurate, _check_complete,
    _check_consistent, _check_enduring, _check_available,
]


def assess_alcoa_plus(doc: dict) -> dict[str, Any]:
    """Assess all nine ALCOA+ dimensions for a normalized document.

    Returns a dict with:
      - dimensions: {dimension: {passed, detail}}
      - passed_count: number of dimensions that passed
      - total: 9
      - score: passed_count / total
    """
    dimensions = {}
    for check in _ALCOA_CHECKS:
        dim, passed, detail = check(doc)
        dimensions[dim] = {'passed': passed, 'detail': detail}
    passed_count = sum(1 for d in dimensions.values() if d['passed'])
    return {
        'dimensions': dimensions,
        'passed_count': passed_count,
        'total': 9,
        'score': passed_count / 9,
    }
