#!/usr/bin/env python3
"""Verify a packaged agent can execute its AI session monitoring cycle."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--wait', type=float, default=10.0)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix='arckon-agent-smoke-') as tmpdir:
        root = Path(tmpdir)
        with tarfile.open(args.artifact, 'r:gz') as archive:
            archive.extractall(root, filter='data')

        agent = root / 'sentinel' / ('agent.exe' if sys.platform == 'win32' else 'agent')
        if not agent.is_file():
            raise RuntimeError(f'packaged agent not found: {agent}')

        config = root / 'agent_config.json'
        config.write_text(json.dumps({'interval': 86400, 'target': str(root)}), encoding='utf-8')
        process = subprocess.Popen(
            [str(agent), '--daemon', '--config', str(config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            time.sleep(args.wait)
        finally:
            if process.poll() is None:
                process.terminate()
            output, _ = process.communicate(timeout=15)

    if 'Daemon mode' not in output:
        raise RuntimeError(f'agent did not enter daemon mode:\n{output}')
    if 'AI session scan error' in output or "No module named 'psutil'" in output:
        raise RuntimeError(f'AI session monitoring dependency failed:\n{output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
