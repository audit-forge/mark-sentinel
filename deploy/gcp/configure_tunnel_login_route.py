#!/usr/bin/env python3
"""Make one customer Nginx vhost use Cloudflare Tunnel public hostnames."""
from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: configure_tunnel_login_route.py <config> <app-host> <admin-host>")

    path = Path(sys.argv[1])
    app_host, admin_host = sys.argv[2:]
    content = path.read_text(encoding="utf-8")

    # Keep login on the application hostname. The admin service issues a
    # host-only session cookie; redirecting to a sibling hostname would prevent
    # that cookie from being sent back to Arckon's auth_request endpoint.
    redirect = f"return 302 https://{app_host}/login?next=https://{app_host}$request_uri;"
    updated, count = re.subn(
        r"return 302 https?://[^;]+/login\?next=[^;]+;",
        redirect,
        content,
        count=1,
    )
    if count != 1:
        raise SystemExit("expected exactly one existing login redirect")

    if "location = /login" not in updated:
        login_location = """location = /login {
        proxy_pass http://sentinel-admin:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Cookie $http_cookie;
    }

    """
        marker = "location / {"
        if marker not in updated:
            raise SystemExit("expected primary Nginx location block")
        updated = updated.replace(marker, login_location + marker, 1)

    path.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    main()
