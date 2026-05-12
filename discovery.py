"""
AI service discovery — multi-layer detection of running AI inference services.

Three detection layers:
  1. Network probes  — scan local subnet for open AI ports, fingerprint HTTP responses
                       to identify service type and loaded models
  2. Process scan    — inspect local running processes for known AI service binaries
  3. Env var scan    — detect cloud AI API keys present in the current environment

Pure stdlib implementation (asyncio + subprocess, no external deps).
"""
import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
from urllib import request as _urlreq

logger = logging.getLogger(__name__)

# ── Port definitions: (port, service_hint, health_path) ──────────────────────
_AI_PORTS: list[tuple[int, str, str]] = [
    (11434, 'Ollama',            '/api/tags'),
    (11435, 'Ollama alt',        '/api/tags'),
    (1234,  'LM Studio',         '/v1/models'),
    (8080,  'AI service',        '/v1/models'),
    (8000,  'AI service',        '/v1/models'),
    (5000,  'AI service',        '/v1/models'),
    (4000,  'LocalAI',           '/v1/models'),
    (3000,  'AI service',        '/v1/models'),
    (8888,  'Jupyter / AI app',  '/api/status'),
    (8501,  'Streamlit app',     '/healthz'),
    (7331,  'M.A.R.K. Sentinel', '/api/status'),
    (8400,  'M.A.R.K. Hash',     '/health'),
]

_TCP_TIMEOUT    = 0.8
_HTTP_TIMEOUT   = 2.0
_MAX_CONCURRENT = 64

# Paths tried in order when the primary probe path doesn't identify the service.
# Covers Ollama, OpenAI-compat, HuggingFace TGI, Jan/LocalAI, llama.cpp, and generic roots.
_EXTRA_PATHS: list[str] = [
    '/api/tags',     # Ollama
    '/v1/models',    # OpenAI-compat (LM Studio, llama.cpp, vLLM, LocalAI, etc.)
    '/props',        # llama.cpp server — exposes loaded model path
    '/info',         # HuggingFace TGI
    '/api/version',  # Jan, LocalAI, others
    '/api/ps',       # Ollama — running-model list
    '/api/kernels',  # Jupyter — active kernel list
    '/models',       # some custom inference servers
    '/api/models',   # some custom inference servers
    '/',             # root — Server header often names the framework
]

# ── Model name → vendor mapping ───────────────────────────────────────────────
_VENDOR_PREFIXES: list[tuple[str, str]] = [
    ('gpt-',           'OpenAI'),
    ('o1-',            'OpenAI'),
    ('o3-',            'OpenAI'),
    ('o4-',            'OpenAI'),
    ('chatgpt-',       'OpenAI'),
    ('text-embedding-', 'OpenAI'),
    ('dall-e-',        'OpenAI'),
    ('whisper-',       'OpenAI'),
    ('tts-',           'OpenAI'),
    ('claude-',        'Anthropic'),
    ('gemini-',        'Google'),
    ('palm-',          'Google'),
    ('gemma',          'Google'),
    ('mistral-',       'Mistral AI'),
    ('mixtral-',       'Mistral AI'),
    ('codestral-',     'Mistral AI'),
    ('pixtral-',       'Mistral AI'),
    ('llama',          'Meta (Llama)'),
    ('codellama',      'Meta (Llama)'),
    ('phi-',           'Microsoft'),
    ('phi3',           'Microsoft'),
    ('phi4',           'Microsoft'),
    ('qwen',           'Alibaba (Qwen)'),
    ('deepseek',       'DeepSeek'),
    ('command-',       'Cohere'),
    ('embed-',         'Cohere'),
    ('falcon',         'TII (Falcon)'),
    ('vicuna',         'LMSYS (Vicuna)'),
    ('zephyr',         'HuggingFace'),
    ('solar',          'Upstage'),
    ('yi-',            '01.AI (Yi)'),
    ('granite-',       'IBM (Granite)'),
    ('nomic-',         'Nomic'),
    ('mxbai-',         'MixedBread'),
    ('starcoder',      'HuggingFace'),
    ('wizardcoder',    'WizardLM'),
    ('stable-',        'Stability AI'),
    ('hermes-',        'Nous Research'),
    ('nous-',          'Nous Research'),
    ('orca-',          'Microsoft'),
    ('neural-',        'Intel (Neural)'),
    ('smollm',         'HuggingFace'),
    ('tinyllama',      'TinyLlama'),
]


def _vendor_from_model(model_id: str) -> str:
    name = model_id.lower().split(':')[0].split('/')[-1]
    for prefix, vendor in _VENDOR_PREFIXES:
        if name.startswith(prefix.lower()):
            return vendor
    return 'Unknown'


def _classify_models(model_ids: list[str]) -> dict[str, list[str]]:
    by_vendor: dict[str, list[str]] = {}
    for m in model_ids:
        v = _vendor_from_model(m)
        by_vendor.setdefault(v, []).append(m)
    return by_vendor


# ── HTTP response fingerprinting ──────────────────────────────────────────────

_HEADER_SIGS: list[tuple[str, str]] = [
    ('ollama',              'Ollama'),
    ('lm-studio',           'LM Studio'),
    ('lmstudio',            'LM Studio'),
    ('localai',             'LocalAI'),
    ('vllm',                'vLLM'),
    ('text-generation',     'HuggingFace TGI'),
    ('fastapi',             'FastAPI (AI app)'),
    ('uvicorn',             'Python AI service'),
    ('flask',               'Flask (AI app)'),
    ('gradio',              'Gradio (AI app)'),
    ('streamlit',           'Streamlit (AI app)'),
    ('koboldai',            'KoboldAI'),
    ('tabby',               'TabbyML'),
    ('jan',                 'Jan (local AI)'),
    ('openedai',            'OpenedAI'),
]

_BODY_SIGS: list[tuple[str, str]] = [
    ('"ollama"',            'Ollama'),
    ('"lm studio"',         'LM Studio'),
    ('"lmstudio"',          'LM Studio'),
    ('"localai"',           'LocalAI'),
    ('"vllm"',              'vLLM'),
    ('gradio',              'Gradio (AI app)'),
    ('koboldai',            'KoboldAI'),
    ('tabbyml',             'TabbyML'),
    ('"openai"',            'OpenAI-compatible server'),
]


def _fingerprint(body: bytes, hint: str, headers: dict | None = None) -> tuple[str, list[str]]:
    """
    Parse HTTP response body and headers to identify service and extract model names.
    Returns (service_label, [model_ids]).
    """
    # Check response headers first — Server header often names the framework
    if headers:
        combined = ' '.join(f'{k}:{v}' for k, v in headers.items()).lower()
        for sig, label in _HEADER_SIGS:
            if sig in combined:
                hint = label
                break

    # Try JSON parsing
    try:
        data = json.loads(body)
    except Exception:
        # Check raw body text for known signatures
        body_lower = body[:2048].decode('utf-8', errors='ignore').lower()
        for sig, label in _BODY_SIGS:
            if sig in body_lower:
                return label, []
        return hint, []

    # Ollama /api/tags — {"models": [{"name": "llama3:latest", ...}]}
    if isinstance(data, dict) and 'models' in data and isinstance(data['models'], list):
        models = [
            m.get('name', '') for m in data['models']
            if isinstance(m, dict) and m.get('name')
        ]
        return 'Ollama', models

    # OpenAI-compatible /v1/models — {"object": "list", "data": [{"id": "..."}]}
    if isinstance(data, dict) and data.get('object') == 'list' and 'data' in data:
        models = [
            m.get('id', '') for m in data['data']
            if isinstance(m, dict) and m.get('id')
        ]
        if not models:
            return hint, []
        vendors = {_vendor_from_model(m) for m in models} - {'Unknown'}
        if 'OpenAI' in vendors:
            return 'OpenAI API proxy', models
        if 'Anthropic' in vendors:
            return 'Anthropic API proxy', models
        if 'Google' in vendors:
            return 'Google Gemini proxy', models
        if 'Mistral AI' in vendors:
            return 'Mistral AI proxy', models
        label = 'LM Studio' if hint == 'LM Studio' else 'Local inference server'
        return label, models

    # HuggingFace TGI /info — {"model_id": "org/model", "model_dtype": "..."}
    if isinstance(data, dict) and 'model_id' in data:
        model_id = data['model_id']
        vendor = _vendor_from_model(model_id.split('/')[-1])
        return f'HuggingFace TGI ({vendor})', [model_id]

    # llama.cpp /props — {"default_generation_settings": {"model": "/path/to/model.gguf"}}
    if isinstance(data, dict) and 'default_generation_settings' in data:
        gen = data['default_generation_settings']
        model_path = gen.get('model', '') if isinstance(gen, dict) else ''
        model_name = model_path.replace('\\', '/').split('/')[-1] if model_path else ''
        return 'llama.cpp server', [model_name] if model_name else []

    # Jupyter /api/kernels — [{"id": "...", "name": "python3", "execution_state": "idle"}]
    # Empty list means server is running but no notebooks are open.
    if isinstance(data, list) and all(isinstance(x, dict) for x in data):
        active = [k for k in data if isinstance(k, dict) and 'execution_state' in k]
        if active:
            kernel_names = list(dict.fromkeys(k.get('name', 'unknown') for k in active))
            return 'Jupyter (kernels active)', kernel_names
        if 'jupyter' in hint.lower():
            return 'Jupyter / AI app', ['0 kernels running']

    # Jupyter /api/status — {"kernels": N, "connections": N}
    if isinstance(data, dict) and 'kernels' in data and 'connections' in data:
        n = data['kernels']
        label = f'{n} kernel{"s" if n != 1 else ""} running'
        return 'Jupyter / AI app', [label]

    # Generic single-model field — {"model": "model-name"} used by some custom servers
    if isinstance(data, dict) and isinstance(data.get('model'), str) and data['model']:
        return hint, [data['model']]

    # vLLM /health or generic {"status": "healthy"}
    if isinstance(data, dict) and data.get('status') in ('healthy', 'ok', 'OK'):
        return hint, []

    # Hash/Sentinel status endpoint
    if isinstance(data, dict) and 'server' in data and 'version' in data:
        return data.get('server', hint), []

    # Generic: scan JSON keys/values for known service identifiers
    flat = json.dumps(data).lower()
    for sig, label in _BODY_SIGS:
        if sig in flat:
            return label, []

    return hint, []


# ── TCP + HTTP probing ────────────────────────────────────────────────────────

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


def _http_probe(host: str, port: int, path: str) -> tuple[int | None, bytes, dict]:
    try:
        url = f'http://{host}:{port}{path}'
        req = _urlreq.Request(url, headers={'User-Agent': 'sentinel-discovery/1.0'})
        with _urlreq.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            hdrs = dict(resp.headers)
            return resp.status, resp.read(16384), hdrs
    except Exception:
        return None, b'', {}


def _multi_probe(host: str, port: int, primary_path: str,
                 fallback_label: str) -> tuple[str, list[str], int | None]:
    """Try primary path then fallback paths until the service is identified.

    Returns (service_label, model_ids, http_status).  Falls back to
    (fallback_label, [], None) if no path yields useful information.
    """
    paths = [primary_path] + [p for p in _EXTRA_PATHS if p != primary_path]
    last_status: int | None = None
    for path in paths:
        status, body, hdrs = _http_probe(host, port, path)
        if status is not None:
            last_status = status
        if not body and not hdrs:
            continue
        service, models = _fingerprint(body, fallback_label, hdrs)
        if service != fallback_label or models:
            return service, models, status
    return fallback_label, [], last_status


def _local_subnet_hosts(max_hosts: int = 254) -> list[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
        if local_ip.startswith('127.'):
            raise ValueError('loopback')
        net = ipaddress.IPv4Network(f'{local_ip}/24', strict=False)
        return [str(h) for h in list(net.hosts())[:max_hosts]]
    except Exception:
        return ['127.0.0.1']


def expand_subnets(subnets_str: str, max_hosts_per_subnet: int = 254) -> list[str]:
    """
    Parse a comma-separated list of CIDRs or bare IPs and return a flat host list.
    Examples:
      "10.0.1.0/24"                     → 254 hosts in 10.0.1.x
      "10.0.1.0/24, 10.0.2.0/24"        → up to 508 hosts across two subnets
      "192.168.1.50"                     → single host
      "10.0.1.1-10.0.1.20"              → range (start–end, same /24 only)
    Duplicates are removed while preserving order.
    """
    hosts: list[str] = []
    seen: set[str] = set()

    def _add(ip: str) -> None:
        if ip not in seen:
            seen.add(ip)
            hosts.append(ip)

    for token in subnets_str.split(','):
        token = token.strip()
        if not token:
            continue
        try:
            if '/' in token:
                net = ipaddress.IPv4Network(token, strict=False)
                for h in list(net.hosts())[:max_hosts_per_subnet]:
                    _add(str(h))
            elif '-' in token:
                start_s, end_s = token.split('-', 1)
                start = int(ipaddress.IPv4Address(start_s.strip()))
                end   = int(ipaddress.IPv4Address(end_s.strip()))
                for i in range(start, min(end + 1, start + max_hosts_per_subnet)):
                    _add(str(ipaddress.IPv4Address(i)))
            else:
                ipaddress.IPv4Address(token)  # validate
                _add(token)
        except ValueError:
            logger.warning('expand_subnets: skipping invalid entry %r', token)

    return hosts


async def _discover_async(hosts: list[str]) -> list[dict]:
    sem = asyncio.Semaphore(_MAX_CONCURRENT)
    loop = asyncio.get_running_loop()
    results: list[dict] = []

    async def probe(host: str, port: int, hint: str, path: str):
        async with sem:
            if not await _tcp_open(host, port):
                return
            fallback = hint if hint != 'AI service' else f'Unknown service (port {port})'
            service, models, status = await loop.run_in_executor(
                None, _multi_probe, host, port, path, fallback
            )
            results.append({
                'host':          host,
                'port':          port,
                'service':       service,
                'models':        models,
                'model_vendors': _classify_models(models),
                'url':           f'http://{host}:{port}',
                'status':        status,
                'reachable':     True,
                'source':        'network_probe',
            })

    tasks = [
        probe(host, port, hint, path)
        for host in hosts
        for port, hint, path in _AI_PORTS
    ]
    await asyncio.gather(*tasks)
    results.sort(key=lambda r: (r['host'], r['port']))
    return results


# ── Local process detection ───────────────────────────────────────────────────

_PROCESS_SIGS: list[tuple[str, str]] = [
    ('ollama',                    'Ollama'),
    ('lms ',                      'LM Studio'),
    ('lm-studio',                 'LM Studio'),
    ('text-generation-launcher',  'HuggingFace TGI'),
    ('text-generation-server',    'HuggingFace TGI'),
    ('vllm.entrypoints',          'vLLM'),
    ('localai',                   'LocalAI'),
    ('llama-server',              'llama.cpp server'),
    ('llama.cpp',                 'llama.cpp'),
    ('koboldcpp',                 'KoboldCPP'),
    ('comfyui',                   'ComfyUI (image AI)'),
    ('sd_webui',                  'Stable Diffusion WebUI'),
    ('tabby',                     'TabbyML (code completion)'),
    ('jan ',                      'Jan (local AI)'),
    ('lmstudio',                  'LM Studio'),
]


def _scan_processes() -> list[dict]:
    found = []
    try:
        if sys.platform == 'win32':
            r = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                               capture_output=True, text=True, timeout=10)
        else:
            r = subprocess.run(['ps', 'aux'],
                               capture_output=True, text=True, timeout=10)
        text = r.stdout.lower()
        seen: set[str] = set()
        for sig, label in _PROCESS_SIGS:
            if sig in text and label not in seen:
                seen.add(label)
                found.append({
                    'service':       label,
                    'models':        [],
                    'model_vendors': {},
                    'process_sig':   sig.strip(),
                    'source':        'process_scan',
                })
    except Exception:
        pass
    return found


# ── Environment variable scanning ────────────────────────────────────────────

_ENV_SIGNALS: list[tuple[str, str, str]] = [
    ('OPENAI_API_KEY',        'OpenAI API',          'OpenAI'),
    ('ANTHROPIC_API_KEY',     'Anthropic Claude',    'Anthropic'),
    ('GEMINI_API_KEY',        'Google Gemini',       'Google'),
    ('GOOGLE_API_KEY',        'Google AI',           'Google'),
    ('AZURE_OPENAI_KEY',      'Azure OpenAI',        'Microsoft (Azure)'),
    ('AZURE_OPENAI_API_KEY',  'Azure OpenAI',        'Microsoft (Azure)'),
    ('GROQ_API_KEY',          'Groq',                'Groq'),
    ('TOGETHER_API_KEY',      'Together AI',         'Together AI'),
    ('MISTRAL_API_KEY',       'Mistral AI',          'Mistral AI'),
    ('COHERE_API_KEY',        'Cohere',              'Cohere'),
    ('REPLICATE_API_TOKEN',   'Replicate',           'Replicate'),
    ('HUGGINGFACE_TOKEN',     'HuggingFace Hub',     'HuggingFace'),
    ('HF_TOKEN',              'HuggingFace Hub',     'HuggingFace'),
    ('PERPLEXITY_API_KEY',    'Perplexity AI',       'Perplexity'),
    ('FIREWORKS_API_KEY',     'Fireworks AI',        'Fireworks AI'),
    ('DEEPSEEK_API_KEY',      'DeepSeek API',        'DeepSeek'),
    ('XAI_API_KEY',           'xAI Grok',            'xAI'),
    ('AWS_BEDROCK_REGION',    'AWS Bedrock',         'AWS (Bedrock)'),
    ('VERTEX_PROJECT',        'Google Vertex AI',    'Google (Vertex)'),
    ('GOOGLE_CLOUD_PROJECT',  'Google Cloud AI',     'Google (Cloud)'),
    ('OPENROUTER_API_KEY',    'OpenRouter',          'OpenRouter'),
    ('ANYSCALE_API_KEY',      'Anyscale Endpoints',  'Anyscale'),
]


def _scan_env_vars() -> list[dict]:
    found = []
    seen: set[str] = set()
    for env_key, service_label, vendor in _ENV_SIGNALS:
        val = os.environ.get(env_key, '')
        if len(val) > 8 and service_label not in seen:
            seen.add(service_label)
            found.append({
                'service':       service_label,
                'models':        [],
                'model_vendors': {vendor: []},
                'env_var':       env_key,
                'source':        'env_var',
            })
    return found


# ── Public API ────────────────────────────────────────────────────────────────

def discover(
    hosts: list[str] | None = None,
    include_processes: bool = True,
    include_env: bool = True,
) -> list[dict]:
    """
    Multi-layer AI service discovery.

    Returns a list of dicts, each with:
      service       — identified service name (e.g. "Ollama", "OpenAI API proxy")
      models        — list of model IDs loaded on that service
      model_vendors — {vendor: [model_ids]} grouping
      source        — "network_probe" | "process_scan" | "env_var"
      url           — (network probes) base URL
      host/port     — (network probes)
      status        — (network probes) HTTP status code
      process_sig   — (process scan) matching process string
      env_var       — (env scan) environment variable name
    """
    target_hosts = hosts or _local_subnet_hosts()

    # asyncio.run() uses ProactorEventLoop on Windows (Python 3.8+), which fails
    # when called from a non-main thread (e.g. inside ThreadingHTTPServer handlers).
    # Explicitly use SelectorEventLoop — works correctly in any thread on all platforms.
    if sys.platform == 'win32':
        loop = asyncio.SelectorEventLoop()
    else:
        loop = asyncio.new_event_loop()
    try:
        results = loop.run_until_complete(_discover_async(target_hosts))
    finally:
        loop.close()

    if include_processes:
        net_labels = {r['service'].lower() for r in results}
        for p in _scan_processes():
            label_lower = p['service'].lower()
            if not any(label_lower in nl or nl in label_lower for nl in net_labels):
                results.append(p)

    if include_env:
        results.extend(_scan_env_vars())

    net = sum(1 for r in results if r.get('source') == 'network_probe')
    proc = sum(1 for r in results if r.get('source') == 'process_scan')
    env = sum(1 for r in results if r.get('source') == 'env_var')
    logger.info('Discovery: %d total (%d network, %d process, %d env)',
                len(results), net, proc, env)
    return results
