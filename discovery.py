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

def _fingerprint(body: bytes, hint: str) -> tuple[str, list[str]]:
    """
    Parse HTTP response body to identify service and extract model names.
    Returns (service_label, [model_ids]).
    """
    try:
        data = json.loads(body)
    except Exception:
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

    # vLLM /health or generic {"status": "healthy"}
    if isinstance(data, dict) and data.get('status') in ('healthy', 'ok', 'OK'):
        return hint, []

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


def _http_probe(host: str, port: int, path: str) -> tuple[int | None, bytes]:
    try:
        url = f'http://{host}:{port}{path}'
        req = _urlreq.Request(url, headers={'User-Agent': 'sentinel-discovery/1.0'})
        with _urlreq.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return resp.status, resp.read(16384)
    except Exception:
        return None, b''


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


async def _discover_async(hosts: list[str]) -> list[dict]:
    sem = asyncio.Semaphore(_MAX_CONCURRENT)
    loop = asyncio.get_running_loop()
    results: list[dict] = []

    async def probe(host: str, port: int, hint: str, path: str):
        async with sem:
            if not await _tcp_open(host, port):
                return
            status, body = await loop.run_in_executor(None, _http_probe, host, port, path)
            service, models = _fingerprint(body, hint)
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
    results = asyncio.run(_discover_async(target_hosts))

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
