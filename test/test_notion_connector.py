"""
Tests for the Notion wiki connector.

Uses a local mock HTTP server — no real Notion integration token needed.
Same recipe as test/test_gemini_hash_connectors.py: spin up an ephemeral
http.server, monkeypatch the connector's module-level base-URL constant
to point at it, call the function, assert on the (bool, str) result.

Run: pytest test/test_notion_connector.py -v
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import connectors.notion_connector as nc  # noqa: E402


# ---------------------------------------------------------------------------
# Mock Notion server
# ---------------------------------------------------------------------------

class _NotionHandler(BaseHTTPRequestHandler):
    fail_pages: bool = False
    fail_users_me: bool = False
    last_page_body: dict | None = None

    def log_message(self, *args):
        pass  # silence request logs

    def do_GET(self):
        if self.path == '/users/me':
            if self.fail_users_me:
                self._reply(401, {'object': 'error', 'message': 'unauthorized'})
            else:
                self._reply(200, {'object': 'user', 'id': 'bot-123', 'name': 'Arckon Integration',
                                   'bot': {'owner': {'type': 'workspace'}}})
        else:
            self._reply(404, {'object': 'error', 'message': 'not found'})

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length) or b'{}')
        if self.path == '/pages':
            type(self).last_page_body = body
            if self.fail_pages:
                self._reply(400, {'object': 'error', 'message': 'validation_error'})
            else:
                self._reply(200, {'object': 'page', 'id': 'page-abc123'})
        else:
            self._reply(404, {'object': 'error', 'message': 'not found'})

    def _reply(self, status: int, payload: dict):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _start_mock_notion(fail_pages: bool = False, fail_users_me: bool = False) -> tuple[HTTPServer, str]:
    _NotionHandler.fail_pages = fail_pages
    _NotionHandler.fail_users_me = fail_users_me
    _NotionHandler.last_page_body = None
    server = HTTPServer(('127.0.0.1', 0), _NotionHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    return server, f'http://127.0.0.1:{port}'


def _with_mock(fail_pages: bool = False, fail_users_me: bool = False):
    """Context-manager-free helper matching the existing test file's
    try/finally + module-constant-restore style."""
    server, base = _start_mock_notion(fail_pages, fail_users_me)
    orig = nc._API_BASE
    nc._API_BASE = base
    return server, orig


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------

class TestNotionTestConnection:
    def test_missing_token_fails_without_network_call(self):
        ok, msg = nc.test_connection({})
        assert ok is False
        assert 'token' in msg.lower()

    def test_valid_token_succeeds(self):
        server, orig = _with_mock()
        try:
            ok, msg = nc.test_connection({'token': 'secret_fake'})
        finally:
            nc._API_BASE = orig
            server.shutdown()
        assert ok is True
        assert 'Arckon Integration' in msg

    def test_http_error_surfaces_as_failure(self):
        server, orig = _with_mock(fail_users_me=True)
        try:
            ok, msg = nc.test_connection({'token': 'secret_bad'})
        finally:
            nc._API_BASE = orig
            server.shutdown()
        assert ok is False
        assert '401' in msg


# ---------------------------------------------------------------------------
# create_page
# ---------------------------------------------------------------------------

class TestNotionCreatePage:
    _FINDING = {
        'check_id': 'AI-DEPLOY-001',
        'title': 'API keys found in repository',
        'severity': 'CRITICAL',
        'description': 'Category: AI-DEPLOY\nWhat we found: hardcoded key.\nRecommended fix: rotate it.',
    }

    def test_missing_token_fails_without_network_call(self):
        ok, msg = nc.create_page({'parent_type': 'page', 'page_id': 'abc'}, self._FINDING, 'host1')
        assert ok is False
        assert 'token' in msg.lower()

    def test_missing_page_id_fails(self):
        ok, msg = nc.create_page({'token': 'secret_fake', 'parent_type': 'page'}, self._FINDING, 'host1')
        assert ok is False
        assert 'page_id' in msg.lower()

    def test_missing_database_id_fails(self):
        ok, msg = nc.create_page(
            {'token': 'secret_fake', 'parent_type': 'database'}, self._FINDING, 'host1'
        )
        assert ok is False
        assert 'database_id' in msg.lower()

    def test_unknown_parent_type_fails(self):
        ok, msg = nc.create_page(
            {'token': 'secret_fake', 'parent_type': 'spreadsheet', 'page_id': 'abc'},
            self._FINDING, 'host1',
        )
        assert ok is False
        assert 'parent_type' in msg.lower()

    def test_page_parent_creates_successfully_with_correct_body(self):
        server, orig = _with_mock()
        try:
            ok, msg = nc.create_page(
                {'token': 'secret_fake', 'parent_type': 'page', 'page_id': 'parent-page-1'},
                self._FINDING, 'DESKTOP-FIN02',
            )
        finally:
            nc._API_BASE = orig
            server.shutdown()
        assert ok is True
        sent = _NotionHandler.last_page_body
        assert sent['parent'] == {'page_id': 'parent-page-1'}
        assert 'CRITICAL' in sent['properties']['title']['title'][0]['text']['content']
        assert 'AI-DEPLOY-001' in sent['properties']['title']['title'][0]['text']['content']
        assert 'DESKTOP-FIN02' in sent['properties']['title']['title'][0]['text']['content']
        assert len(sent['children']) > 0

    def test_database_parent_uses_configured_title_property(self):
        server, orig = _with_mock()
        try:
            ok, msg = nc.create_page(
                {
                    'token': 'secret_fake', 'parent_type': 'database',
                    'database_id': 'db-1', 'title_property': 'Task Name',
                },
                self._FINDING, 'host1',
            )
        finally:
            nc._API_BASE = orig
            server.shutdown()
        assert ok is True
        sent = _NotionHandler.last_page_body
        assert sent['parent'] == {'database_id': 'db-1'}
        assert 'Task Name' in sent['properties']
        assert 'title' not in sent['properties']

    def test_empty_description_creates_page_with_no_children(self):
        server, orig = _with_mock()
        try:
            ok, msg = nc.create_page(
                {'token': 'secret_fake', 'parent_type': 'page', 'page_id': 'p1'},
                {**self._FINDING, 'description': ''}, 'host1',
            )
        finally:
            nc._API_BASE = orig
            server.shutdown()
        assert ok is True
        assert _NotionHandler.last_page_body['children'] == []

    def test_provider_failure_surfaces_as_failure(self):
        server, orig = _with_mock(fail_pages=True)
        try:
            ok, msg = nc.create_page(
                {'token': 'secret_fake', 'parent_type': 'page', 'page_id': 'p1'},
                self._FINDING, 'host1',
            )
        finally:
            nc._API_BASE = orig
            server.shutdown()
        assert ok is False
        assert '400' in msg


# ---------------------------------------------------------------------------
# _rich_text_for_line / _body_to_blocks (markdown -> Notion blocks)
# ---------------------------------------------------------------------------

class TestRichTextConversion:
    def test_label_value_line_splits_bold_label_plain_value(self):
        runs = nc._rich_text_for_line('**Category:** AI-DEPLOY')
        assert len(runs) == 2
        assert runs[0]['text']['content'] == 'Category: '
        assert runs[0]['annotations']['bold'] is True
        assert runs[1]['text']['content'] == 'AI-DEPLOY'
        assert 'annotations' not in runs[1]

    def test_whole_bold_line(self):
        runs = nc._rich_text_for_line('**Log in to Arckon**')
        assert len(runs) == 1
        assert runs[0]['text']['content'] == 'Log in to Arckon'
        assert runs[0]['annotations']['bold'] is True

    def test_bold_prefix_with_plain_suffix(self):
        runs = nc._rich_text_for_line('**CRITICAL Finding** on `DESKTOP-FIN02`')
        assert len(runs) == 2
        assert runs[0]['text']['content'] == 'CRITICAL Finding'
        assert runs[0]['annotations']['bold'] is True
        assert runs[1]['text']['content'] == ' on `DESKTOP-FIN02`'

    def test_plain_line_no_bold(self):
        runs = nc._rich_text_for_line('Log in to RiskRaven: Arckon to view full details.')
        assert len(runs) == 1
        assert 'annotations' not in runs[0]

    def test_body_to_blocks_splits_on_double_newline(self):
        blocks = nc._body_to_blocks('**A:** 1\n\n**B:** 2\n\nplain line')
        assert len(blocks) == 3
        assert all(b['type'] == 'paragraph' for b in blocks)

    def test_body_to_blocks_skips_empty_segments(self):
        blocks = nc._body_to_blocks('**A:** 1\n\n\n\n**B:** 2')
        assert len(blocks) == 2
