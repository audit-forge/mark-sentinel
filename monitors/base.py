#!/usr/bin/env python3
"""RiskRaven Arckon — Shared base for protected-files access collectors.

Provides:
  - AI process name matching (reuses discovery.py signatures)
  - Path canonicalization and protected-path matching
  - Event formatting (the schema the server expects)
  - Bounded event queue (drop-oldest under memory pressure)

FedRAMP SI-4: system monitoring — detects AI access to protected resources.
"""
from __future__ import annotations

import logging
import os
import time
from collections import deque
from threading import Lock
from typing import Iterable

log = logging.getLogger('arckon.monitors.base')

# AI process names — kept in sync with discovery.py:_PROCESS_SIGS and
# _MCP_PROCESS_SIGS. A process matches if its name (lowercased, basename)
# contains any of these substrings. This is intentionally broad: we want
# to catch variants like "claude-2", "Cursor Helper", "ollama_llama_server".
_AI_PROCESS_NAMES = frozenset({
    'ollama', 'lms', 'lm-studio', 'lmstudio',
    'text-generation-launcher', 'text-generation-server', 'tgi',
    'vllm', 'vllm.entrypoints', 'localai', 'localai-llama',
    'llama-server', 'llama.cpp', 'llamacpp', 'llamafile',
    'koboldcpp', 'kobold',
    'comfyui', 'sd_webui', 'stable-diffusion',
    'tabby', 'tabbyml',
    'jan', 'jan-server',
    'claude', 'claude-code', 'claude-helper',
    'cursor', 'cursor-helper',
    'copilot', 'github-copilot',
    'continue', 'continue-proxy',
    'codeium', 'codeium-language-server',
    'aider',
    # MCP servers
    'mcp-server', 'fastmcp', 'mcp',
    # SaaS AI clients
    'chatgpt', 'gemini', 'poe', 'perplexity', 'grok', 'you.com', 'phind',
    # Additional
    'anythingllm', 'open-webui', 'openwebui', 'lmchat',
})

# Actions we monitor — mapped from platform-specific event types to these
# canonical actions for consistent storage and alerting.
_VALID_ACTIONS = frozenset({'read', 'write', 'open', 'rename', 'unlink', 'login'})


def is_ai_process(process_name: str) -> bool:
    """Return True if the process name matches a known AI/LLM tool.

    Matching is case-insensitive and substring-based to catch variants.
    """
    if not process_name:
        return False
    lower = process_name.lower()
    # Strip common platform suffixes for matching
    for suffix in ('.exe', '.app', ' helper', ' helper.exe'):
        if lower.endswith(suffix):
            lower = lower[:-len(suffix)]
    return any(sig in lower for sig in _AI_PROCESS_NAMES)


def canonicalize_path(path: str) -> str:
    """Resolve a path to its canonical absolute form (symlinks resolved).

    Falls back to os.path.abspath if realpath fails (e.g. path doesn't
    exist yet — common for 'unlink' events where the file was deleted).
    """
    try:
        return os.path.realpath(path)
    except Exception:
        return os.path.abspath(path)


def path_matches_protected(path: str, protected_paths: list[dict]) -> dict | None:
    """Check if a path matches any protected path entry.

    Returns the matching protected-path dict, or None.

    Matching rules:
    - Exact match on canonical path
    - If protected entry is recursive, any path under it matches
    - If actions filter is set, the event action must be in the list
    """
    canon = canonicalize_path(path)
    for pp in protected_paths:
        pp_path = canonicalize_path(pp['path'])
        matched = False
        if canon == pp_path:
            matched = True
        elif pp.get('recursive', True) and canon.startswith(pp_path + os.sep):
            matched = True
        if matched:
            # The actions filter itself is applied by the caller
            # (AccessCollector._should_report), which has the event's
            # actual action to check against pp['actions'].
            return pp
    return None


def format_event(ts: int, device_id: str, hostname: str, platform: str,
                 process: str, pid: int, path: str, action: str,
                 source: str) -> dict:
    """Format a collector event into the server's expected schema.

    No file contents are ever included — only metadata (FedRAMP MP-3).
    """
    if action not in _VALID_ACTIONS:
        action = 'open'  # safe default for unknown action types
    return {
        'ts': int(ts),
        'device_id': str(device_id),
        'hostname': str(hostname),
        'platform': str(platform),
        'process': str(process),
        'pid': int(pid),
        'path': str(path),
        'action': action,
        'source': str(source),
    }


class EventQueue:
    """Thread-safe bounded queue for access events.

    Drop-oldest when full — a burst of access events can't grow memory
    without limit (FedRAMP availability consideration).
    """

    def __init__(self, max_size: int = 5000):
        self._events: deque[dict] = deque(maxlen=max_size)
        self._lock = Lock()

    def push(self, event: dict) -> None:
        with self._lock:
            self._events.append(event)

    def drain(self, limit: int | None = None) -> list[dict]:
        """Return and clear queued events (insertion order preserved)."""
        with self._lock:
            if limit is None or limit >= len(self._events):
                out = list(self._events)
                self._events.clear()
            else:
                out = [self._events.popleft() for _ in range(limit)]
        return out

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


class AccessCollector:
    """Base class for platform-specific access collectors.

    Subclasses implement start(), stop(), and _collect_events().
    The base class handles process correlation and event queuing.
    """

    def __init__(self, device_id: str, hostname: str, platform: str,
                 protected_paths: list[dict], queue: EventQueue):
        self.device_id = device_id
        self.hostname = hostname
        self.platform = platform
        self.protected_paths = protected_paths
        self.queue = queue
        self._running = False

    def update_protected_paths(self, paths: list[dict]) -> None:
        """Update the protected-paths policy (called when agent receives
        a new policy via command poll). Thread-safe."""
        self.protected_paths = paths

    def _should_report(self, process_name: str, path: str,
                       action: str) -> bool:
        """Return True if this event should be reported:
        - process must be an AI process
        - path must match a protected path
        - action must be in the protected path's actions filter
        """
        if not is_ai_process(process_name):
            return False
        pp = path_matches_protected(path, self.protected_paths)
        if not pp:
            return False
        actions_str = pp.get('actions', 'read,write,open')
        if not actions_str or actions_str == '*':
            return True
        allowed = {a.strip() for a in actions_str.split(',') if a.strip()}
        return action in allowed

    def _emit(self, ts: int, process: str, pid: int, path: str,
              action: str, source: str) -> None:
        """Format and queue an event if it passes the filter."""
        if not self._should_report(process, path, action):
            return
        event = format_event(
            ts=ts, device_id=self.device_id, hostname=self.hostname,
            platform=self.platform, process=process, pid=pid,
            path=canonicalize_path(path), action=action, source=source)
        self.queue.push(event)

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        self._running = False
