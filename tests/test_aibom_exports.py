from pathlib import Path

from aibom_generator import generate_aibom_csv, generate_aibom_pdf


def _devices():
    return [{
        'hostname': 'Keith-Laptop',
        '_report': {
            'inventory_findings': [{
                'check_id': 'AI-SUPPLY-005',
                'status': 'WARN',
                'severity': 'MEDIUM',
                'title': 'Model Version Pinned',
                'details': 'Some model references are floating.',
                'evidence': ['Models detected: claude-opus-4-7 (floating), qwen3:4b (pinned)'],
            }],
        },
    }]


def test_aibom_csv_includes_components_and_excel_bom():
    data = generate_aibom_csv(_devices(), 'MF Dynamics')

    assert data.startswith(b'\xef\xbb\xbf')
    text = data.decode('utf-8-sig')
    assert 'record_type,component_type,name,version' in text
    assert 'claude-opus-4-7' in text
    assert 'qwen3:4b' in text
    assert 'Keith-Laptop' in text


def test_aibom_pdf_is_a_pdf_and_includes_org_name():
    data = generate_aibom_pdf(_devices(), 'MF Dynamics')

    assert data.startswith(b'%PDF')
    assert b'MF Dynamics' in data
    assert b'Summary:' in data
    assert b'Devices:' in data


def test_aibom_export_routes_and_controls_are_available():
    server = (Path(__file__).resolve().parents[1] / 'server.py').read_text()

    assert "'/api/fleet/aibom.csv':" in server
    assert "'/api/fleet/aibom.pdf':" in server
    assert "openAibomReport('pdf')" in server
    assert "openAibomReport('csv')" in server
    assert "window.location.href = '/api/fleet/aibom." not in server
