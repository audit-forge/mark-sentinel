"""eTMF completeness assessment against the DIA TMF Reference Model.

Evaluates ingested eTMF document metadata against the expected artifact
matrix for the current study phase. Reports missing artifacts, ALCOA+
dimension gaps, and AI provenance coverage.

This module provides evidence inputs for qualified QA/CSV review — it does
not replace human judgment, CSV validation, or regulatory determination.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from connectors.etmf_connector import normalize_etmf_document, assess_alcoa_plus


CATEGORY = "AI-TMF"
CHECK_ID = "AI-TMF-001"
CHECK_TITLE = "eTMF Completeness and ALCOA+ Assessment"


def load_reference_model(profile_path: Path | None = None) -> dict[str, Any]:
    """Load the DIA TMF Reference Model from a JSON profile file."""
    if profile_path is None:
        profile_path = Path(__file__).parent.parent / 'profiles' / 'tmf_reference_model.json'
    with open(profile_path, encoding='utf-8') as f:
        return json.load(f)


def get_required_artifacts(model: dict[str, Any], phase: str) -> list[dict[str, Any]]:
    """Return the list of artifacts required for the given study phase."""
    if phase not in ('setup', 'conduct', 'closeout'):
        raise ValueError(f'invalid study phase: {phase}')
    artifacts = []
    for zone in model.get('zones', []):
        for section in zone.get('sections', []):
            for artifact in section.get('artifacts', []):
                if phase in artifact.get('required_phases', []):
                    artifacts.append({
                        'artifact_id': artifact['id'],
                        'artifact_name': artifact['name'],
                        'zone': zone['name'],
                        'section': section['name'],
                        'alcoa_dimensions': artifact.get('alcoa_dimensions', []),
                        'require_signature': artifact.get('require_signature', False),
                        'require_version_control': artifact.get('require_version_control', False),
                    })
    return artifacts


def assess_completeness(
    documents: list[dict[str, Any]],
    phase: str = 'conduct',
    model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess eTMF completeness for a study phase.

    Args:
        documents: list of normalized eTMF document metadata dicts
        phase: study phase ('setup', 'conduct', 'closeout')
        model: optional pre-loaded reference model

    Returns:
        {
          'phase': phase,
          'total_required': int,
          'present_count': int,
          'missing_count': int,
          'missing_artifacts': [...],
          'present_artifacts': [...],
          'alcoa_summary': {dim: pass_count},
          'ai_provenance_count': int,
          'ai_provenance_gaps': [...],
          'findings': [...],
          'completeness_score': float,
        }
    """
    if model is None:
        model = load_reference_model()

    required = get_required_artifacts(model, phase)
    required_by_name = {a['artifact_name'].lower(): a for a in required}

    # Group documents by artifact type (case-insensitive match)
    docs_by_type: dict[str, list[dict]] = {}
    for doc in documents:
        key = doc.get('artifact_type', '').lower()
        if key:
            docs_by_type.setdefault(key, []).append(doc)

    missing_artifacts = []
    present_artifacts = []
    alcoa_summary: dict[str, int] = {}
    ai_provenance_count = 0
    ai_provenance_gaps = []
    findings = []

    for req in required:
        name_lower = req['artifact_name'].lower()
        matching_docs = docs_by_type.get(name_lower, [])

        if not matching_docs:
            missing_artifacts.append({
                'artifact_id': req['artifact_id'],
                'artifact_name': req['artifact_name'],
                'zone': req['zone'],
                'section': req['section'],
                'issue': 'missing',
            })
            findings.append({
                'check_id': CHECK_ID,
                'severity': 'HIGH',
                'title': f'Missing required TMF artifact: {req["artifact_name"]}',
                'detail': f'{req["zone"]} > {req["section"]} — required for {phase} phase but not found in eTMF metadata',
                'frameworks': {
                    'DIA TMF Reference Model': req['artifact_id'],
                    'ICH E6(R2)': '§5.5.3',
                    'GxP ALCOA+': 'complete',
                },
            })
            continue

        # Pick the most recent version of this artifact
        latest = max(matching_docs, key=lambda d: d.get('version', '') or '')
        present_artifacts.append({
            'artifact_id': req['artifact_id'],
            'artifact_name': req['artifact_name'],
            'document_id': latest.get('document_id', ''),
            'version': latest.get('version', ''),
            'status': latest.get('status', ''),
            'doc_count': len(matching_docs),
        })

        # Assess ALCOA+ dimensions
        alcoa = assess_alcoa_plus(latest)
        for dim, result in alcoa['dimensions'].items():
            if dim not in alcoa_summary:
                alcoa_summary[dim] = 0
            if result['passed']:
                alcoa_summary[dim] += 1

        # Check signature requirement
        if req['require_signature']:
            sigs = latest.get('signatures', [])
            if not sigs:
                findings.append({
                    'check_id': CHECK_ID,
                    'severity': 'HIGH',
                    'title': f'Missing signatures: {req["artifact_name"]}',
                    'detail': 'This artifact requires signatures per the TMF Reference Model, but none were found in the metadata',
                    'frameworks': {
                        'FDA 21 CFR Part 11': '§11.50',
                        'ICH E6(R2)': '§5.5.3',
                    },
                })

        # Check version control requirement
        if req['require_version_control'] and not latest.get('version'):
            findings.append({
                'check_id': CHECK_ID,
                'severity': 'MEDIUM',
                'title': f'Missing version: {req["artifact_name"]}',
                'detail': 'This artifact requires version control per the TMF Reference Model, but no version was recorded',
                'frameworks': {
                    'GxP ALCOA+': 'original',
                    'FDA 21 CFR Part 11': '§11.10(e)',
                },
            })

        # Check AI provenance
        if latest.get('ai_provenance'):
            ai_provenance_count += 1
            ai = latest['ai_provenance']
            if not ai.get('human_reviewer'):
                ai_provenance_gaps.append({
                    'artifact_name': req['artifact_name'],
                    'document_id': latest.get('document_id', ''),
                    'issue': 'AI-generated content without recorded human reviewer',
                })
                findings.append({
                    'check_id': CHECK_ID,
                    'severity': 'HIGH',
                    'title': f'AI content missing human review: {req["artifact_name"]}',
                    'detail': 'AI-generated content detected but no human reviewer was recorded in the provenance metadata',
                    'frameworks': {
                        'ICH E6(R2)': '§5.5.3',
                        'GxP ALCOA+': 'attributable',
                        'FDA AI/ML SaMD': 'Action Plan',
                    },
                })
        elif latest.get('status') == 'approved':
            # Flag as a potential gap — no AI provenance recorded
            ai_provenance_gaps.append({
                'artifact_name': req['artifact_name'],
                'document_id': latest.get('document_id', ''),
                'issue': 'No AI provenance recorded (may be human-authored)',
            })

    total_required = len(required)
    present_count = len(present_artifacts)
    missing_count = len(missing_artifacts)
    completeness_score = present_count / total_required if total_required else 0.0

    return {
        'phase': phase,
        'total_required': total_required,
        'present_count': present_count,
        'missing_count': missing_count,
        'missing_artifacts': missing_artifacts,
        'present_artifacts': present_artifacts,
        'alcoa_summary': alcoa_summary,
        'ai_provenance_count': ai_provenance_count,
        'ai_provenance_gaps': ai_provenance_gaps,
        'findings': findings,
        'completeness_score': round(completeness_score, 2),
    }
