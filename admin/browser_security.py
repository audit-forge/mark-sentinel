"""Browser redirect and CSRF checks independent of session authentication."""

import re
from urllib.parse import unquote, urlsplit


def _clean_url(value: str) -> bool:
    return bool(value) and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) and "\\" not in value


def _origin(value: str, *, origin_header: bool = False):
    if not _clean_url(value):
        return None
    try:
        parts = urlsplit(value)
        if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username is not None or parts.password is not None
                or "%" in parts.netloc or parts.netloc.endswith(":")
                or (origin_header and (parts.path or "?" in value or "#" in value))):
            return None
        port = parts.port
        return (parts.scheme, parts.hostname.lower(), port if port is not None else (443 if parts.scheme == "https" else 80))
    except ValueError:
        return None


def safe_return_url(value: str | None, configured_urls) -> str:
    """Return the unchanged safe target, or empty so callers use role fallback.

    Decode defensively for ambiguous slash/control encodings, but never redirect
    to the decoded value. Only root-relative paths and configured origins qualify.
    """
    if not value:
        return ""
    allowed = {origin for url in configured_urls if (origin := _origin(url))}
    candidate = value
    for _ in range(6):
        if not _clean_url(candidate) or re.search(r"%(?![0-9a-fA-F]{2})", candidate):
            return ""
        try:
            parts = urlsplit(candidate)
        except ValueError:
            return ""
        if candidate.startswith("/"):
            if candidate.startswith("//") or parts.netloc or parts.scheme:
                return ""
        elif _origin(candidate) not in allowed:
            return ""
        # Dot segments can expose an encoded network-path after normalization.
        if any(segment in {".", ".."} for segment in parts.path.split("/")):
            return ""
        decoded = unquote(candidate)
        if decoded == candidate:
            return value
        candidate = decoded
    return ""


def browser_mutation_allowed(request, configured_urls) -> bool:
    """No implicit trust in Host, forwarded headers, bearer headers or peer IP.

    Cookie-free machine calls retain endpoint authentication. Cookie mutations
    fail closed without provenance; login always requires Origin or Referer.
    An Origin, even invalid/null, takes precedence over a fallback Referer.
    """
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return True
    if request.url.path.rstrip("/") != "/login" and "token" not in request.cookies:
        return True
    allowed = {origin for url in configured_urls if (origin := _origin(url))}
    origins = request.headers.getlist("origin")
    if origins:
        return len(origins) == 1 and _origin(origins[0], origin_header=True) in allowed
    referers = request.headers.getlist("referer")
    return len(referers) == 1 and _origin(referers[0]) in allowed
