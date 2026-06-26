#!/usr/bin/env python3
"""
Fake MCP server for Sentinel testing.

Simulates a real MCP (Model Context Protocol) server so you can verify
that Sentinel's MCP discovery finds and inventories it correctly.

Run on any machine the Sentinel agent can reach:
    python fake_mcp_server.py                  # default: port 3000, no auth
    python fake_mcp_server.py --port 8080      # different port
    python fake_mcp_server.py --auth           # require Authorization header
    python fake_mcp_server.py --name "CRM Bot" # custom server name

Then click "Scan MCP Servers" on the Sentinel dashboard.
Expected result: a new entry in MCP & Agent Governance section showing
this server's host:port, name, and the tools it exposes.
"""
import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOLS = [
    {"name": "query_database",   "description": "Run a SQL query against the company database",   "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "read_file",        "description": "Read a file from the server filesystem",          "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "send_email",       "description": "Send an email on behalf of the authenticated user","inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
    {"name": "list_directory",   "description": "List files in a directory",                       "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "execute_code",     "description": "Execute arbitrary Python code",                   "inputSchema": {"type": "object", "properties": {"code": {"type": "string"}}}},
    {"name": "call_external_api","description": "Make an HTTP request to an external service",     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
]


def make_handler(server_name: str, require_auth: bool):
    class MCPHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print(f'[MCP] {self.address_string()} — {fmt % args}', flush=True)

        def _send_json(self, data: dict, status: int = 200):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if require_auth:
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer '):
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Bearer realm="mcp"')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return

            length = int(self.headers.get('Content-Length', 0))
            raw    = self.rfile.read(length) if length else b'{}'
            try:
                req = json.loads(raw)
            except Exception:
                self._send_json({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}, 400)
                return

            method = req.get('method', '')
            req_id = req.get('id', 1)

            if method == 'initialize':
                self._send_json({
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'result': {
                        'protocolVersion': '2024-11-05',
                        'capabilities': {'tools': {}, 'resources': {}, 'prompts': {}},
                        'serverInfo': {'name': server_name, 'version': '1.0.0'},
                    },
                })
            elif method == 'tools/list':
                self._send_json({
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'result': {'tools': TOOLS},
                })
            elif method == 'notifications/initialized':
                self._send_json({'jsonrpc': '2.0', 'id': req_id, 'result': {}})
            else:
                self._send_json({
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'error': {'code': -32601, 'message': f'Method not found: {method}'},
                }, 404)

        def do_GET(self):
            self._send_json({'status': 'mcp-server', 'name': server_name})

    return MCPHandler


def main():
    ap = argparse.ArgumentParser(description='Fake MCP server for Sentinel testing')
    ap.add_argument('--port', type=int, default=3000, help='Port to listen on (default: 3000)')
    ap.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    ap.add_argument('--auth', action='store_true', help='Require Bearer token auth (shows as Auth OK in Sentinel)')
    ap.add_argument('--name', default='Fake MCP Server', help='Server name shown in Sentinel')
    args = ap.parse_args()

    auth_label = 'AUTH REQUIRED' if args.auth else 'NO AUTH (will appear as high-risk in Sentinel)'
    print('\nFake MCP server starting:')
    print(f'  Name  : {args.name}')
    print(f'  Listen: http://{args.host}:{args.port}')
    print(f'  Auth  : {auth_label}')
    print(f'  Tools : {len(TOOLS)} tools exposed')
    print('\nExpected Sentinel behavior:')
    print('  - Click "Scan MCP Servers" on the dashboard')
    print('  - Wait ~45s for agents to complete the scan')
    print('  - A new card should appear in MCP & Agent Governance')
    print(f'  - It will show this host:{args.port}, "{args.name}", and the tool list')
    if not args.auth:
        print('  - The card will have a RED "No Auth" badge and a warning')
    else:
        print('  - The card will have a GREEN "Auth OK" badge')
    print('\nPress Ctrl+C to stop.\n')

    handler = make_handler(args.name, args.auth)
    server  = HTTPServer((args.host, args.port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
        sys.exit(0)


if __name__ == '__main__':
    main()
