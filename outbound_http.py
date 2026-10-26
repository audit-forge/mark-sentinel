"""SSRF-safe transport for configurable outbound integrations, not internal relays.

Operator-only private access is configured through ARCKON_OUTBOUND_PRIVATE_ORIGINS:
  {"https://siem.example:8088": ["10.20.0.10/32"],
   "http://127.0.0.1:8400": ["127.0.0.1/32"]}
Keys are exact origins (scheme, hostname, effective port), never URL prefixes.
Do not populate this environment variable from tenant/integration configuration.
"""

import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request


class OutboundHTTPError(urllib.error.URLError):
    """An outbound URL or destination violates transport policy."""


_PRIVATE = tuple(ipaddress.ip_network(net) for net in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '127.0.0.0/8', '::1/128', 'fc00::/7',
))
_METADATA = {ipaddress.ip_address(addr) for addr in (
    '168.63.129.16', '100.100.100.200', 'fd00:ec2::254',
)}


def _parse_url(url):
    if (not isinstance(url, str) or not url or
            any(ord(c) <= 32 or ord(c) >= 127 for c in url) or '\\' in url):
        raise OutboundHTTPError('URL must be ASCII without whitespace or controls')
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        port = parts.port
        if (parts.scheme not in ('http', 'https') or not host or
                parts.username is not None or parts.password is not None or
                '@' in parts.netloc or '%' in parts.netloc or '#' in url or
                parts.netloc.endswith(':')):
            raise ValueError('invalid HTTP origin')
        if not re.fullmatch(r'(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(:[0-9]+)?', parts.netloc):
            raise ValueError('invalid authority')
        # Avoid parser/resolver disagreements, scoped IPv6, and legacy numeric IPs.
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if (not re.fullmatch(r'[a-zA-Z0-9.-]+', host) or
                    len(host) > 253 or host.endswith('.') or
                    any(not label or len(label) > 63 or label.startswith('-') or
                        label.endswith('-') for label in host.split('.'))):
                raise ValueError('invalid hostname')
            if re.fullmatch(r'[0-9.]+', host) or host.lower().startswith('0x'):
                raise ValueError('noncanonical numeric address')
        else:
            if address.version == 6 and not parts.netloc.startswith('['):
                raise ValueError('IPv6 requires brackets')
        port = port if port is not None else (443 if parts.scheme == 'https' else 80)
        if not 1 <= port <= 65535:
            raise ValueError('invalid port')
        return parts.scheme, host.lower(), port
    except ValueError as exc:
        raise OutboundHTTPError('Invalid outbound HTTP URL') from exc


class Request(urllib.request.Request):
    """Retain raw input so opening rejects controls urllib silently strips."""

    def __init__(self, url, *args, **kwargs):
        self._outbound_raw_url = url
        super().__init__(url, *args, **kwargs)


def _approved_networks(origin):
    try:
        policy = json.loads(os.environ.get('ARCKON_OUTBOUND_PRIVATE_ORIGINS', '{}'))
        if not isinstance(policy, dict):
            raise ValueError('expected origin mapping')
        result = []
        for url, cidrs in policy.items():
            parsed = urllib.parse.urlsplit(url)
            key = _parse_url(url)
            if parsed.path not in ('', '/') or parsed.query or not isinstance(cidrs, list):
                raise ValueError('expected exact origin and CIDR list')
            networks = [ipaddress.ip_network(cidr, strict=True) for cidr in cidrs]
            if any(not any(net.subnet_of(private) for private in _PRIVATE
                           if net.version == private.version) for net in networks):
                raise ValueError('only private/loopback CIDRs may be approved')
            if key == origin:
                result.extend(networks)
        return result
    except (ValueError, TypeError) as exc:
        raise OutboundHTTPError('Invalid ARCKON_OUTBOUND_PRIVATE_ORIGINS policy') from exc


def _allowed(address, networks):
    # Mapped/transition addresses must not tunnel around the IPv4 policy.
    if address.version == 6 and (address.ipv4_mapped or address.sixtofour or
                                 address.teredo):
        return False
    if (address.is_link_local or address.is_multicast or address.is_unspecified or
            address in _METADATA):
        return False
    if any(address in net for net in _PRIVATE if address.version == net.version):
        return any(address in net for net in networks if address.version == net.version)
    if address.version == 6 and address not in ipaddress.ip_network('2000::/3'):
        return False
    return address.is_global and not address.is_reserved


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OutboundHTTPError('Outbound HTTP redirects are disabled')


def urlopen(request, timeout=15):
    """Open with public-only DNS, numeric socket pinning, verified TLS, no proxy.

    Every DNS answer must pass policy, not just the answer selected for connect.
    Only process environment can approve private access. No caller-supplied TLS
    contexts, proxy settings, or network-policy arguments are accepted.
    """
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise OutboundHTTPError('A finite positive timeout is required')
    req = Request(request) if isinstance(request, str) else request
    _parse_url(getattr(req, '_outbound_raw_url', req.full_url))
    scheme, host, port = origin = _parse_url(req.full_url)
    if req.has_proxy():
        raise OutboundHTTPError('Outbound proxies are disabled')
    networks = _approved_networks(origin)
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OutboundHTTPError('Outbound DNS resolution failed') from exc
    if not answers:
        raise OutboundHTTPError('Outbound DNS returned no addresses')
    for family, socktype, proto, canonname, sockaddr in answers:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise OutboundHTTPError('Invalid DNS address') from exc
        if family not in (socket.AF_INET, socket.AF_INET6) or not _allowed(address, networks):
            raise OutboundHTTPError('Outbound destination blocked by address policy')

    def connect_numeric(address, timeout, source_address=None):
        last_error = None
        for family, socktype, proto, _, sockaddr in answers:
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
        raise last_error

    context = ssl.create_default_context()

    def connection(authority, **kwargs):
        cls = http.client.HTTPSConnection if scheme == 'https' else http.client.HTTPConnection
        if scheme == 'https':
            kwargs['context'] = context
        conn = cls(authority, **kwargs)
        conn._create_connection = connect_numeric
        return conn

    class PinnedHTTP(urllib.request.HTTPHandler):
        def http_open(self, request):
            return self.do_open(connection, request)

    class PinnedHTTPS(urllib.request.HTTPSHandler):
        def https_open(self, request):
            return self.do_open(connection, request)

    # Preserve the logical authority for HTTP Host, TLS SNI and certificate checks.
    # Never trust a caller-provided Host header or mutate the caller's Request.
    headers = {k: v for k, v in req.header_items() if k.lower() != 'host'}
    safe_req = Request(req.full_url, data=req.data, headers=headers, method=req.get_method())
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), PinnedHTTP(), PinnedHTTPS(),
    )
    return opener.open(safe_req, timeout=timeout)
