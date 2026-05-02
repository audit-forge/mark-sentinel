"""
AI service discovery — probes the local network for running AI inference endpoints.
Pure stdlib implementation (asyncio only, no external deps).
"""
import asyncio
import ipaddress
import json
import logging
import socket
from urllib import request as _urlreq

logger = logging.getLogger(__name__)

# (port, service_name, health_path)
_AI_PORTS: list[tuple[int, str, str]] = [
    (11434, 'Ollama',      '/api/tags'),
    (1234,  'LM Studio',   '/v1/models'),
    (8080,  'AI service',  '/'),
    (8000,  'AI service',  '/'),
    (5000,  'AI service',  '/'),
    (3000,  'AI service',  '/'),
    (7331,  'Sentinel',    '/api/status'),
    (8400,  'Hash',        '/health'),
    (11435, 'Ollama alt',  '/api/tags'),
]

_TCP_TIMEOUT  = 0.8
_HTTP_TIMEOUT = 2.0
_MAX_CONCURRENT = 64


async def _tcp_open(host: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=_TCP_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def _http_probe(host: str, port: int, path: str) -> int | None:
    """Synchronous HTTP probe — called via run_in_executor."""
    try:
        url = f'http://{host}:{port}{path}'
        req = _urlreq.Request(url, headers={'User-Agent': 'sentinel-discovery/1.0'})
        with _urlreq.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return resp.status
    except Exception:
        return None


def _local_subnet_hosts(max_hosts: int = 254) -> list[str]:
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        net = ipaddress.IPv4Network(f'{local_ip}/24', strict=False)
        return [str(h) for h in list(net.hosts())[:max_hosts]]
    except Exception:
        return ['127.0.0.1']


async def _discover_async(hosts: list[str]) -> list[dict]:
    sem = asyncio.Semaphore(_MAX_CONCURRENT)
    loop = asyncio.get_event_loop()
    results: list[dict] = []

    async def probe(host: str, port: int, label: str, path: str):
        async with sem:
            if not await _tcp_open(host, port):
                return
            status = await loop.run_in_executor(None, _http_probe, host, port, path)
            results.append({
                'host':      host,
                'port':      port,
                'service':   label,
                'url':       f'http://{host}:{port}',
                'status':    status,
                'reachable': True,
            })

    tasks = [
        probe(host, port, label, path)
        for host in hosts
        for port, label, path in _AI_PORTS
    ]
    await asyncio.gather(*tasks)
    results.sort(key=lambda r: (r['host'], r['port']))
    return results


def discover(hosts: list[str] | None = None) -> list[dict]:
    """
    Probe hosts (default: local /24 subnet) for AI service ports.
    Blocking call — runs asyncio event loop internally.
    Returns sorted list of discovered services.
    """
    target_hosts = hosts or _local_subnet_hosts()
    results = asyncio.run(_discover_async(target_hosts))
    logger.info('Discovery: %d service(s) found across %d host(s)',
                len(results), len(target_hosts))
    return results
