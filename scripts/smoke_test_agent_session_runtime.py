#!/usr/bin/env python3
"""Verify a packaged agent can execute its AI session monitoring cycle."""
from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('artifact', type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix='arckon-agent-smoke-') as tmpdir:
        root = Path(tmpdir)
        with tarfile.open(args.artifact, 'r:gz') as archive:
            archive.extractall(root, filter='data')

        agent = root / 'sentinel' / ('agent.exe' if sys.platform == 'win32' else 'agent')
        if not agent.is_file():
            raise RuntimeError(f'packaged agent not found: {agent}')

        result = subprocess.run(
            [str(agent), '--verify-ai-session-runtime'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )

    if result.returncode != 0:
        raise RuntimeError(f'AI session monitoring dependency failed:\n{result.stdout}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
