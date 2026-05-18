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


# ── Docker container detection ───────────────────────────────────────────────

_DOCKER_AI_IMAGES: list[tuple[str, str]] = [
    ('ollama/ollama',                                'Ollama'),
    ('ghcr.io/ggerganov/llama.cpp',                  'llama.cpp server'),
    ('vllm/vllm-openai',                             'vLLM'),
    ('huggingface/text-generation-inference',        'HuggingFace TGI'),
    ('ghcr.io/huggingface/text-generation-inference','HuggingFace TGI'),
    ('localai/localai',                              'LocalAI'),
    ('quay.io/go-skynet/local-ai',                   'LocalAI'),
    ('koboldai/koboldcpp',                           'KoboldCPP'),
    ('ghcr.io/open-webui/open-webui',                'Open WebUI'),
    ('tabbyml/tabby',                                'TabbyML'),
    ('nvcr.io/nvidia/tritonserver',                  'Triton Inference Server'),
    ('jupyter/base-notebook',                        'Jupyter'),
    ('jupyter/scipy-notebook',                       'Jupyter'),
    ('jupyter/tensorflow-notebook',                  'TensorFlow/Jupyter'),
    ('jupyter/pytorch-notebook',                     'PyTorch/Jupyter'),
    ('tensorflow/tensorflow',                        'TensorFlow'),
    ('pytorch/pytorch',                              'PyTorch'),
    ('nvidia/cuda',                                  'CUDA/GPU environment'),
    ('deepjavalibrary/djl-serving',                  'DJL Serving'),
]

_DOCKER_AI_KEYWORDS = ('llm', 'ollama', 'gpt', 'inference', 'model-server', 'vllm',
                       'langchain', 'llamacpp', 'whisper', 'diffusion', 'comfyui')


def _match_ai_image(image: str) -> str:
    base = image.lower().split(':')[0]
    for pattern, label in _DOCKER_AI_IMAGES:
        if pattern.lower() in base:
            return label
    name_part = base.split('/')[-1]
    for kw in _DOCKER_AI_KEYWORDS:
        if kw in name_part:
            return f'AI container ({name_part})'
    return ''


def _scan_docker_containers() -> tuple[list[dict], list[str]]:
    """
    Query Docker for running containers in ~10ms per container.
    Returns (ai_image_findings, all_container_ips).
    No exceptions bubble out — Docker absence is silently ignored.
    """
    ai_findings: list[dict] = []
    container_ips: list[str] = []

    try:
        ps = subprocess.run(
            ['docker', 'ps', '--no-trunc',
             '--format', '{{.ID}}\t{{.Image}}\t{{.Names}}'],
            capture_output=True, text=True, timeout=10,
        )
        if ps.returncode != 0 or not ps.stdout.strip():
            return ai_findings, container_ips
    except (FileNotFoundError, PermissionError):
        return ai_findings, container_ips
    except Exception:
        return ai_findings, container_ips

    for line in ps.stdout.strip().splitlines():
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        cid, image, name = parts[0][:12], parts[1], parts[2]

        ips: list[str] = []
        try:
            insp = subprocess.run(
                ['docker', 'inspect', '--format',
                 '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}', cid],
                capture_output=True, text=True, timeout=5,
            )
            if insp.returncode == 0:
                ips = [ip for ip in insp.stdout.split() if ip]
                container_ips.extend(ips)
        except Exception:
            pass

        service_label = _match_ai_image(image)
        if service_label:
            ai_findings.append({
                'service':         service_label,
                'models':          [],
                'model_vendors':   {},
                'container_name':  name,
                'container_image': image,
                'container_ips':   ips,
                'source':          'docker_container',
            })

    return ai_findings, container_ips


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
    ('claude ',                   'Anthropic Claude CLI'),
    ('claude.exe',                'Anthropic Claude CLI'),
    ('cursor ',                   'Cursor (AI code editor)'),
    ('copilot',                   'GitHub Copilot'),
    ('continue ',                 'Continue (AI code assistant)'),
    ('codeium',                   'Codeium (AI code assistant)'),
    ('aider',                     'Aider (AI coding)'),
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


_CONFIG_FILE_SIGNALS: list[tuple[str, str, str]] = [
    ('~/.claude/config.json',              'Anthropic Claude CLI',    'Anthropic'),
    ('~/.claude/.credentials.json',        'Anthropic Claude CLI',    'Anthropic'),
    ('~/AppData/Roaming/Claude/config.json', 'Anthropic Claude (Desktop)', 'Anthropic'),
    ('~/.config/claude/config.json',       'Anthropic Claude CLI',    'Anthropic'),
    ('~/.cursor/config.json',              'Cursor (AI code editor)', 'Cursor'),
    ('~/AppData/Roaming/Cursor/config.json', 'Cursor (AI code editor)', 'Cursor'),
    ('~/.continue/config.json',            'Continue (AI assistant)', 'Continue'),
    ('~/.config/aider/aider.conf.yml',     'Aider (AI coding)',       'Aider'),
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
    for path_str, service_label, vendor in _CONFIG_FILE_SIGNALS:
        if service_label in seen:
            continue
        try:
            if Path(path_str).expanduser().exists():
                seen.add(service_label)
                found.append({
                    'service':       service_label,
                    'models':        [],
                    'model_vendors': {vendor: []},
                    'env_var':       f'config: {path_str}',
                    'source':        'env_var',
                })
        except Exception:
            pass
    return found


# ── DNS cache inspection ──────────────────────────────────────────────────────

_AI_DNS_HOSTNAMES: list[tuple[str, str, str]] = [
    ('api.anthropic.com',                    'Anthropic Claude',     'Anthropic'),
    ('api.openai.com',                       'OpenAI / ChatGPT',     'OpenAI'),
    ('chat.openai.com',                      'ChatGPT (browser)',     'OpenAI'),
    ('generativelanguage.googleapis.com',    'Google Gemini API',    'Google'),
    ('gemini.google.com',                    'Google Gemini',        'Google'),
    ('api.mistral.ai',                       'Mistral AI',           'Mistral AI'),
    ('api.groq.com',                         'Groq',                 'Groq'),
    ('api.together.xyz',                     'Together AI',          'Together AI'),
    ('api.cohere.com',                       'Cohere',               'Cohere'),
    ('api.replicate.com',                    'Replicate',            'Replicate'),
    ('huggingface.co',                       'HuggingFace',          'HuggingFace'),
    ('api-inference.huggingface.co',         'HuggingFace Inference','HuggingFace'),
    ('api.perplexity.ai',                    'Perplexity AI',        'Perplexity'),
    ('api.fireworks.ai',                     'Fireworks AI',         'Fireworks AI'),
    ('api.deepseek.com',                     'DeepSeek API',         'DeepSeek'),
    ('api.x.ai',                             'xAI Grok',             'xAI'),
    ('bedrock-runtime.amazonaws.com',        'AWS Bedrock',          'AWS'),
    ('aiplatform.googleapis.com',            'Google Vertex AI',     'Google'),
    ('openrouter.ai',                        'OpenRouter',           'OpenRouter'),
    ('api.azure.com',                        'Azure OpenAI',         'Microsoft'),
    ('cognitiveservices.azure.com',          'Azure OpenAI',         'Microsoft'),
    ('claude.ai',                            'Anthropic Claude (web)','Anthropic'),
    ('copilot.microsoft.com',                'Microsoft Copilot',    'Microsoft'),
    ('github.com',                           'GitHub Copilot',       'GitHub'),
    ('api.githubcopilot.com',               'GitHub Copilot API',   'GitHub'),
]

_DNS_PROBE_TIMEOUT = 1.0


def _scan_dns_cache() -> list[dict]:
    """
    Check the local DNS cache for recent lookups to known AI API hostnames.
    Uses the OS DNS cache (platform-specific) plus a fast socket probe.
    Returns findings in env_var format so they flow through existing pipeline.
    """
    found: list[dict] = []

    # ── Platform-native cache dump ────────────────────────────────────────────
    cached_hosts: set[str] = set()

    if sys.platform == 'win32':
        try:
            r = subprocess.run(
                ['ipconfig', '/displaydns'],
                capture_output=True, text=True, timeout=10,
            )
            text = r.stdout.lower()
            for hostname, _, _ in _AI_DNS_HOSTNAMES:
                if hostname.lower() in text:
                    cached_hosts.add(hostname)
        except Exception:
            pass

    elif sys.platform == 'darwin':
        try:
            r = subprocess.run(
                ['dscacheutil', '-cachedump', '-entries', 'Host'],
                capture_output=True, text=True, timeout=10,
            )
            text = r.stdout.lower()
            for hostname, _, _ in _AI_DNS_HOSTNAMES:
                if hostname.lower() in text:
                    cached_hosts.add(hostname)
        except Exception:
            pass

    else:
        # Linux — query systemd-resolved cache if available
        try:
            r = subprocess.run(
                ['resolvectl', 'statistics'],
                capture_output=True, text=True, timeout=5,
            )
            # resolvectl doesn't expose full cache contents, so we fall through
            # to the socket timing probe below for Linux.
        except Exception:
            pass

    # ── Socket timing probe ───────────────────────────────────────────────────
    # A cached DNS response resolves in <5ms. Uncached takes 50-300ms.
    # We probe each hostname with a tight timeout and treat a fast response
    # as evidence the hostname is in cache (i.e., was recently accessed).
    # This works on all platforms without elevated permissions.
    for hostname, service_label, vendor in _AI_DNS_HOSTNAMES:
        if hostname in cached_hosts:
            continue
        try:
            t0 = __import__('time').monotonic()
            socket.getaddrinfo(hostname, None, socket.AF_INET,
                               socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
            elapsed = __import__('time').monotonic() - t0
            if elapsed < 0.05:
                cached_hosts.add(hostname)
        except Exception:
            pass

    # ── Build findings ────────────────────────────────────────────────────────
    seen_labels: set[str] = set()
    for hostname, service_label, vendor in _AI_DNS_HOSTNAMES:
        if hostname in cached_hosts and service_label not in seen_labels:
            seen_labels.add(service_label)
            found.append({
                'service':       service_label,
                'models':        [],
                'model_vendors': {vendor: []},
                'env_var':       f'dns: {hostname}',
                'source':        'env_var',
            })

    return found


# ── Public API ────────────────────────────────────────────────────────────────

# ── MCP (Model Context Protocol) server detection ─────────────────────────────

_MCP_PORTS: list[int] = [3000, 3001, 3333, 4000, 8000, 8080, 9000]

_MCP_INIT_PAYLOAD: bytes = json.dumps({
    'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
    'params': {
        'protocolVersion': '2024-11-05',
        'capabilities': {},
        'clientInfo': {'name': 'sentinel', 'version': '1.0'},
    },
}).encode()

_MCP_TOOLS_PAYLOAD: bytes = json.dumps({
    'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {},
}).encode()

_MCP_PROCESS_SIGS: list[str] = [
    'uvx mcp', '@modelcontextprotocol', 'mcp-server', 'fastmcp',
    'mcp serve', 'python -m mcp', 'mcp run',
]


def _probe_mcp_http(host: str, port: int) -> dict | None:
    """Send MCP JSON-RPC initialize handshake. Returns server info dict or None."""
    for path in ('/', '/mcp', '/api/mcp'):
        try:
            url = f'http://{host}:{port}{path}'
            req = _urlreq.Request(
                url, data=_MCP_INIT_PAYLOAD,
                headers={'Content-Type': 'application/json',
                         'User-Agent':   'sentinel-discovery/1.0'},
                method='POST',
            )
            from urllib import error as _urlerr
            try:
                with _urlreq.urlopen(req, timeout=3) as resp:
                    if resp.status == 401:
                        return {'server_name': '', 'tools': [], 'auth_status': 'required'}
                    raw  = resp.read(16384)
                    data = json.loads(raw)
                    if 'result' not in data:
                        continue
                    result = data['result']
                    if 'protocolVersion' not in result:
                        continue
                    info  = result.get('serverInfo', {})
                    caps  = result.get('capabilities', {})
                    tools: list[str] = []
                    if isinstance(caps.get('tools'), dict):
                        try:
                            treq = _urlreq.Request(
                                url, data=_MCP_TOOLS_PAYLOAD,
                                headers={'Content-Type': 'application/json',
                                         'User-Agent':   'sentinel-discovery/1.0'},
                                method='POST',
                            )
                            with _urlreq.urlopen(treq, timeout=3) as tr:
                                tdata = json.loads(tr.read(16384))
                                tools = [t.get('name', '') for t in
                                         tdata.get('result', {}).get('tools', [])
                                         if t.get('name')]
                        except Exception:
                            pass
                    return {
                        'server_name': info.get('name', ''),
                        'tools':       tools,
                        'auth_status': 'none',
                    }
            except _urlerr.HTTPError as e:
                if e.code == 401:
                    return {'server_name': '', 'tools': [], 'auth_status': 'required'}
        except Exception:
            pass
    return None


def _scan_mcp_processes() -> list[dict]:
    """Scan local process list for running MCP server signatures."""
    findings: list[dict] = []
    try:
        if sys.platform == 'win32':
            r = subprocess.run(
                ['wmic', 'process', 'get', 'commandline', '/format:csv'],
                capture_output=True, text=True, timeout=10,
            )
        else:
            r = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
        text = r.stdout
    except Exception:
        return findings
    sigs = [re.compile(s, re.IGNORECASE) for s in _MCP_PROCESS_SIGS]
    seen: set[str] = set()
    for line in text.splitlines():
        if any(sig.search(line) for sig in sigs):
            key = line.strip()[:150]
            if key not in seen:
                seen.add(key)
                findings.append({
                    'source':       'mcp_process',
                    'host':         'localhost',
                    'port':         0,
                    'server_name':  '',
                    'tools':        [],
                    'auth_status':  'unknown',
                    'process_info': key,
                })
    return findings


async def _discover_mcp_async(hosts: list[str]) -> list[dict]:
    sem = asyncio.Semaphore(_MAX_CONCURRENT)
    loop = asyncio.get_running_loop()
    results: list[dict] = []

    async def probe(host: str, port: int):
        async with sem:
            if not await _tcp_open(host, port):
                return
            info = await loop.run_in_executor(None, _probe_mcp_http, host, port)
            if info:
                results.append({
                    'source':       'mcp_network',
                    'host':         host,
                    'port':         port,
                    'server_name':  info.get('server_name', ''),
                    'tools':        info.get('tools', []),
                    'auth_status':  info.get('auth_status', 'unknown'),
                    'process_info': '',
                })

    await asyncio.gather(*[probe(h, p) for h in hosts for p in _MCP_PORTS])
    results.sort(key=lambda r: (r['host'], r['port']))
    return results


def discover_mcp_servers(hosts: list[str] | None = None) -> list[dict]:
    """
    Scan for MCP (Model Context Protocol) servers via network probe + process scan.

    Returns list of dicts with:
      source       — 'mcp_network' | 'mcp_process'
      host / port  — location (host='localhost' for process findings)
      server_name  — name from initialize handshake
      tools        — list of tool names the server exposes
      auth_status  — 'required' | 'none' | 'unknown'
      process_info — (process scan only) raw cmdline snippet
    """
    target_hosts = list(hosts) if hosts else _local_subnet_hosts()
    loop = asyncio.SelectorEventLoop() if sys.platform == 'win32' else asyncio.new_event_loop()
    try:
        net_results = loop.run_until_complete(_discover_mcp_async(target_hosts))
    finally:
        loop.close()
    proc_results = _scan_mcp_processes()
    results = net_results + proc_results
    logger.info('MCP discovery: %d servers (%d network, %d process)',
                len(results),
                sum(1 for r in results if r['source'] == 'mcp_network'),
                sum(1 for r in results if r['source'] == 'mcp_process'))
    return results


def discover(
    hosts: list[str] | None = None,
    include_processes: bool = True,
    include_env: bool = True,
    include_docker: bool = True,
) -> list[dict]:
    """
    Multi-layer AI service discovery.

    Returns a list of dicts, each with:
      service       — identified service name (e.g. "Ollama", "OpenAI API proxy")
      models        — list of model IDs loaded on that service
      model_vendors — {vendor: [model_ids]} grouping
      source        — "network_probe" | "process_scan" | "env_var" | "docker_container"
      url           — (network probes) base URL
      host/port     — (network probes)
      status        — (network probes) HTTP status code
      process_sig   — (process scan) matching process string
      env_var       — (env scan) environment variable name
      container_name/container_image — (docker) container metadata
    """
    target_hosts = list(hosts) if hosts else _local_subnet_hosts()

    # Docker: get container IPs and AI-image findings before the probe so
    # container IPs are included in the same async scan pass (no extra scan loop).
    docker_ai_findings: list[dict] = []
    docker_ip_set: set[str] = set()
    if include_docker and sys.platform != 'win32':
        docker_ai_findings, docker_ips = _scan_docker_containers()
        for ip in docker_ips:
            if ip and ip not in set(target_hosts):
                target_hosts.append(ip)
                docker_ip_set.add(ip)
        docker_ip_set.update(docker_ips)

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

    # Re-tag any network probe result whose host is a known container IP.
    probed_container_hosts: set[str] = set()
    for r in results:
        if r.get('host') in docker_ip_set:
            r['source'] = 'docker_container'
            probed_container_hosts.add(r['host'])

    # Add image-matched container findings that had no open/reachable port.
    already_probed_ips: set[str] = {r.get('host') for r in results if r.get('source') == 'docker_container'}
    for df in docker_ai_findings:
        c_ips = set(df.get('container_ips', []))
        if not c_ips or not c_ips.intersection(already_probed_ips):
            results.append(df)

    if include_processes:
        net_labels = {r['service'].lower() for r in results}
        for p in _scan_processes():
            label_lower = p['service'].lower()
            if not any(label_lower in nl or nl in label_lower for nl in net_labels):
                results.append(p)

    if include_env:
        results.extend(_scan_env_vars())
        results.extend(_scan_dns_cache())

    net    = sum(1 for r in results if r.get('source') == 'network_probe')
    proc   = sum(1 for r in results if r.get('source') == 'process_scan')
    env    = sum(1 for r in results if r.get('source') == 'env_var')
    docker = sum(1 for r in results if r.get('source') == 'docker_container')
    logger.info('Discovery: %d total (%d network, %d process, %d env, %d docker)',
                len(results), net, proc, env, docker)
    return results
