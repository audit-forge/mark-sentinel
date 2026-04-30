#!/usr/bin/env python3
"""
M.A.R.K. Sentinel — AI Security Audit Tool
Powered by Hash

Usage:
  python audit.py --mode config --profile smb --output plain
  python audit.py --mode config --target ./my-app --profile fedramp --output json,plain
  python audit.py --mode api --endpoint https://api.openai.com/v1 --api-key OPENAI_API_KEY --model gpt-4o
  python audit.py --mode local --ollama-host http://localhost:11434 --model llama3 --output plain,sarif
"""
from pathlib import Path
import runpy

# execute the original audit.py in this directory but with a harmless docstring
runpy.run_path(str(Path(__file__).parent / 'audit.py'), run_name='__main__')
