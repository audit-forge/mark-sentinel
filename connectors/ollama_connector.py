"""
M.A.R.K. Sentinel — Ollama Connector
Connects to a local Ollama instance via its OpenAI-compatible /v1 endpoint.
"""
from connectors.config_connector import ScanContext
from connectors import api_connector

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3"


def connect(host: str = DEFAULT_HOST, model: str = DEFAULT_MODEL, target_dir: str = ".") -> ScanContext:
    """
    Scan target_dir for config issues and run live probes against a local Ollama instance.
    Ollama exposes an OpenAI-compatible API at <host>/v1.
    """
    endpoint = f"{host.rstrip('/')}/v1"
    ctx = api_connector.connect(endpoint=endpoint, api_key="", model=model, target_dir=target_dir)
    ctx.mode = "local"
    return ctx
