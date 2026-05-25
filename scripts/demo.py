#!/usr/bin/env python3
"""
M.A.R.K. Sentinel — Multi-Provider Demo Runner

Auto-detects available AI services and audits each in sequence.
Generates a timestamped report bundle in output/demo_<timestamp>/
then prints a side-by-side comparison table split by check type.

Usage:
  python scripts/demo.py [--target PATH] [--profile PROFILE]
                         [--openai-model MODEL] [--claude-model MODEL]
                         [--local-models MODEL,...] [--all-local]

Providers auto-detected from:
  OPENAI_API_KEY      → ChatGPT
  ANTHROPIC_API_KEY   → Claude
  Ollama running      → local models (default: qwen2.5:7b)
  hash-ai start       → Hash-AI gateway (port 8400)

Keys are loaded automatically from ~/hash/.env if not set in the shell.
"""
import sys
if sys.version_info < (3, 11):
    sys.exit(
        "M.A.R.K. Sentinel requires Python 3.11 or later.\n"
        f"Running: Python {sys.version.split()[0]}\n"
        "Install: https://python.org/downloads/"
    )
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
import argparse
import json
import os
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_DIR))

_HASH_ENV    = Path.home() / 'hash' / '.env'
_HASH_CONFIG = Path.home() / 'hash' / 'config' / 'hash.json'
_SKIP_OLLAMA = frozenset({'nomic-embed-text:latest'})

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  M.A.R.K. Sentinel — Multi-Provider Security Demo           ║
║  Powered by Hash                                             ║
╚══════════════════════════════════════════════════════════════╝"""


def _load_hash_env():
    if _HASH_ENV.exists():
        for line in _HASH_ENV.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, val = line.partition('=')
            key = key.strip()
            if key not in os.environ and val.strip():
                os.environ[key] = val.strip().strip('"\'')

    if 'HASH_TOKEN' not in os.environ and _HASH_CONFIG.exists():
        try:
            cfg = json.loads(_HASH_CONFIG.read_text())
            token = cfg.get('gateway', {}).get('auth', {}).get('token', '')
            if token:
                os.environ['HASH_TOKEN'] = token
        except Exception:
            pass


_load_hash_env()

from checks import FAIL, WARN, PASS, SKIP  # noqa: E402
from checks.deploy import run_all as deploy_checks  # noqa: E402
from checks.input_safety import run_all as inp_checks  # noqa: E402
from checks.output_safety import run_all as out_checks  # noqa: E402
from checks.agentic import run_all as agent_checks  # noqa: E402
from checks.supply_chain import run_all as supply_checks  # noqa: E402
from checks.governance import run_all as gov_checks  # noqa: E402
from checks.runtime import run_all as runtime_checks  # noqa: E402
from output.plain_english import format_report  # noqa: E402
from output.json_report import format_json  # noqa: E402
from output.sarif import format_sarif  # noqa: E402


# ── service detection ──────────────────────────────────────────────────────

def _is_ollama_up(host: str) -> bool:
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/api/tags", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def _ollama_models(host: str) -> list:
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/api/tags", timeout=3) as r:
            data = json.loads(r.read().decode())
            return [m['name'] for m in data.get('models', []) if m['name'] not in _SKIP_OLLAMA]
    except Exception:
        return []


def _is_hash_up(host: str) -> bool:
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/health", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


# ── audit helpers ──────────────────────────────────────────────────────────

_SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']


def _load_profile(name: str) -> dict:
    path = PROJECT_DIR / 'profiles' / f'{name}.json'
    if not path.exists():
        available = sorted(p.stem for p in (PROJECT_DIR / 'profiles').glob('*.json')
                           if not p.stem.endswith('_controls'))
        print(f"[ERROR] Profile '{name}' not found. Available: {', '.join(available)}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        profile = json.load(f)
    emphasis = profile.get('framework_emphasis')
    if emphasis:
        controls_path = PROJECT_DIR / 'profiles' / f'{emphasis}_controls.json'
        if controls_path.exists():
            with open(controls_path) as f:
                profile['_controls'] = json.load(f)
    return profile


def _run_checks(ctx) -> list:
    results = []
    results.extend(deploy_checks(ctx))
    results.extend(inp_checks(ctx))
    results.extend(out_checks(ctx))
    results.extend(agent_checks(ctx))
    results.extend(supply_checks(ctx))
    results.extend(gov_checks(ctx))
    results.extend(runtime_checks(ctx))
    return results


def _filter(results: list, profile: dict) -> list:
    if profile.get('checks') != 'all':
        allowed = set(profile['checks'])
        results = [r for r in results if r.check_id in allowed]
    threshold = profile.get('severity_threshold', 'LOW')
    if threshold in _SEV_ORDER:
        cutoff = _SEV_ORDER.index(threshold)
        results = [r for r in results
                   if r.severity not in _SEV_ORDER or _SEV_ORDER.index(r.severity) <= cutoff]
    return results


def _save_reports(results, profile, target, mode, model, out_dir, label):
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = (label.replace('/', '-').replace(' ', '_')
                 .replace(':', '-').replace('(', '').replace(')', ''))
    plain = format_report(results, profile, target, mode=mode, model=model)
    json_text = format_json(results, profile, target, mode)
    json_data = json.loads(json_text)
    json_data['_provider_label'] = label.strip()
    json_data['_model'] = model or ''
    (out_dir / f"{safe}.txt").write_text(plain)
    (out_dir / f"{safe}.json").write_text(json.dumps(json_data, indent=2))
    (out_dir / f"{safe}.sarif").write_text(format_sarif(results, profile, target, mode))
    return plain


def _summary(label: str, results: list, mode: str) -> dict:
    active = [r for r in results if r.status != SKIP]
    config_checks = [r for r in active if not r.check_id.startswith(('AI-INP', 'AI-OUT'))]
    probe_checks  = [r for r in active if r.check_id.startswith(('AI-INP', 'AI-OUT'))]
    return {
        'label':         label,
        'mode':          mode,
        'cfg_fail':      sum(1 for r in config_checks if r.status == FAIL),
        'cfg_warn':      sum(1 for r in config_checks if r.status == WARN),
        'cfg_pass':      sum(1 for r in config_checks if r.status == PASS),
        'probe_fail':    sum(1 for r in probe_checks if r.status == FAIL),
        'probe_pass':    sum(1 for r in probe_checks if r.status == PASS),
        'probe_total':   len(probe_checks),
        'skip':          sum(1 for r in results if r.status == SKIP),
    }


def _probe_line(ctx) -> str:
    if ctx.live_error:
        return f"connection error: {ctx.live_error}"
    passed = sum(1 for r in ctx.probe_results.values() if r.passed)
    total = len(ctx.probe_results)
    return f"{total} probes  {passed}/{total} passed"


# ── comparison table ───────────────────────────────────────────────────────

def _print_comparison(rows: list):
    W = 78
    print("\n" + "═" * W)
    print("  MULTI-PROVIDER AUDIT RESULTS")
    print("═" * W)

    # Separate config from probe rows
    config_rows = [r for r in rows if r['mode'] == 'config']
    live_rows   = [r for r in rows if r['mode'] != 'config']

    if config_rows:
        print("\n  ── Infrastructure & Config Checks (same for all providers) ──")
        print(f"  {'Provider':<28}  {'FAIL':>5}  {'WARN':>5}  {'PASS':>5}")
        print("  " + "─" * (W - 2))
        for row in config_rows:
            f = _red(row['cfg_fail']) if row['cfg_fail'] else f"{row['cfg_fail']:>5}"
            w = _yel(row['cfg_warn']) if row['cfg_warn'] else f"{row['cfg_warn']:>5}"
            print(f"  {row['label']:<28}  {f}  {w}  {row['cfg_pass']:>5}")
        print()
        print("  Why are these the same? Infrastructure checks audit your deployment")
        print("  config, credentials, and governance docs — not the AI model itself.")
        print("  They're identical because every provider runs against the same codebase.")

    if live_rows:
        print("\n  ── Live Adversarial Probe Results (per-provider behavior) ──")
        print(f"  {'Provider':<30}  {'Cfg FAIL':>8}  {'Cfg WARN':>8}  {'Probe PASS':>10}  {'Probe FAIL':>10}")
        print("  " + "─" * (W - 2))
        for row in live_rows:
            cf = _red(row['cfg_fail'])  if row['cfg_fail']   else f"{row['cfg_fail']:>8}"
            cw = _yel(row['cfg_warn'])  if row['cfg_warn']   else f"{row['cfg_warn']:>8}"
            pt = row['probe_total']
            pp = f"{row['probe_pass']}/{pt}" if pt else "n/a"
            pf = f"{row['probe_fail']}/{pt}" if pt else "n/a"
            pf_str = _red(pf) if row['probe_fail'] else f"{pf:>10}"
            print(f"  {row['label']:<30}  {cf}  {cw}  {pp:>10}  {pf_str}")
        print()
        print("  Probe checks test real behavior: prompt injection, jailbreak attempts,")
        print("  system prompt leakage, PII exposure, and harmful content refusals.")
        print("  Different models fail different probes — that's the story here.")

    print("\n" + "═" * W)


def _red(val) -> str:
    return f"\033[91m{val:>5}\033[0m" if isinstance(val, int) else f"\033[91m{str(val):>10}\033[0m"


def _yel(val) -> str:
    return f"\033[93m{val:>5}\033[0m" if isinstance(val, int) else f"\033[93m{str(val):>8}\033[0m"


# ── provider audit ─────────────────────────────────────────────────────────

def _audit(p: dict, target: str, profile: dict, out_dir: Path) -> dict | None:
    label = p['label']
    model = p.get('model', '')
    mode  = p['mode']
    print(f"\n{'─' * 56}")
    print(f"  Provider : {label}")
    if model:
        print(f"  Model    : {model}")

    try:
        if mode == 'config':
            from connectors.config_connector import scan_directory
            ctx = scan_directory(target, mode='config')
            print(f"  Files    : {ctx.total_files_scanned} scanned")

        elif mode == 'openai':
            from connectors.api_connector import connect
            print("  Probing  : ", end='', flush=True)
            ctx = connect(endpoint='https://api.openai.com/v1',
                          api_key=p['api_key'], model=model, target_dir=target)
            print(_probe_line(ctx))

        elif mode == 'anthropic':
            from connectors.claude_connector import connect
            print("  Probing  : ", end='', flush=True)
            ctx = connect(api_key=p['api_key'], model=model, target_dir=target)
            print(_probe_line(ctx))

        elif mode == 'local':
            from connectors.ollama_connector import connect
            print("  Probing  : ", end='', flush=True)
            ctx = connect(host=p['host'], model=model, target_dir=target)
            print(_probe_line(ctx))

        elif mode == 'hash':
            from connectors.hash_connector import connect
            print("  Probing  : ", end='', flush=True)
            ctx = connect(host=p['host'], token=p.get('token', ''), target_dir=target)
            print(_probe_line(ctx))

        else:
            print(f"  [SKIP] unknown mode: {mode}")
            return None

    except Exception as e:
        print(f"  [ERROR]  {e}")
        return None

    results = _filter(_run_checks(ctx), profile)
    _save_reports(results, profile, target, mode, model, out_dir, label)

    active = [r for r in results if r.status != SKIP]
    probe_checks = [r for r in active if r.check_id.startswith(('AI-INP', 'AI-OUT'))]
    probe_fails  = [r for r in probe_checks if r.status == FAIL]
    config_fails = [r for r in active if r.status == FAIL and not r.check_id.startswith(('AI-INP', 'AI-OUT'))]

    if probe_fails:
        ids = ', '.join(r.check_id for r in probe_fails[:3])
        print(f"  Probe    : {len(probe_fails)} FAIL — {ids}{'...' if len(probe_fails) > 3 else ''}")
    elif probe_checks:
        print(f"  Probe    : all {len(probe_checks)} probes passed")

    if config_fails:
        ids = ', '.join(r.check_id for r in config_fails[:3])
        print(f"  Config   : {len(config_fails)} FAIL — {ids}{'...' if len(config_fails) > 3 else ''}")
    elif mode == 'config':
        print(f"  Config   : {sum(1 for r in active if r.status == PASS)} passed, "
              f"{sum(1 for r in active if r.status == WARN)} warn, "
              f"{sum(1 for r in active if r.status == FAIL)} fail")

    return _summary(label, results, mode)


# ── main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='M.A.R.K. Sentinel — Multi-Provider Demo Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    _default_target = str(PROJECT_DIR / 'demo_target')
    parser.add_argument('--target', default=_default_target, metavar='PATH',
                        help='Directory to scan (default: demo_target/ — fictional vulnerable deployment)')
    parser.add_argument('--profile', default='default',
                        help='Audit profile: default, fedramp, cmmc, financial, healthcare, biotech, owasp_agentic, eu_ai_act (default: default)')
    parser.add_argument('--openai-model', default='gpt-4o', metavar='MODEL',
                        help='OpenAI model to audit (default: gpt-4o)')
    parser.add_argument('--claude-model', default='claude-opus-4-7', metavar='MODEL',
                        help='Anthropic model to audit (default: claude-opus-4-7)')
    parser.add_argument('--local-models', default='', metavar='MODELS',
                        help='Comma-separated Ollama models (default: qwen2.5:7b)')
    parser.add_argument('--all-local', action='store_true',
                        help='Audit every installed Ollama model')
    args = parser.parse_args()

    print(BANNER)

    target = str(Path(args.target).resolve())
    profile = _load_profile(args.profile)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir = PROJECT_DIR / 'output' / f'demo_{ts}'

    openai_key    = os.environ.get('OPENAI_API_KEY', '')
    anthropic_key = os.environ.get('ANTHROPIC_API_KEY', '')
    ollama_host   = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
    hash_host     = os.environ.get('HASH_HOST', 'http://127.0.0.1:8400')
    hash_token    = os.environ.get('HASH_TOKEN', '')

    print(f"\nTarget  : {target}")
    print(f"Profile : {profile['name']}")
    print(f"Output  : {out_dir}")
    print("\nDetecting providers...")

    providers = []

    providers.append({'label': 'Config scan', 'mode': 'config'})
    print("  ✓  Config scan")

    if openai_key:
        providers.append({'label': f'ChatGPT  ({args.openai_model})', 'mode': 'openai',
                          'api_key': openai_key, 'model': args.openai_model})
        print(f"  ✓  ChatGPT — key found  [{args.openai_model}]")
    else:
        print("  ✗  ChatGPT — OPENAI_API_KEY not set")

    if anthropic_key:
        providers.append({'label': f'Anthropic ({args.claude_model})', 'mode': 'anthropic',
                          'api_key': anthropic_key, 'model': args.claude_model})
        print(f"  ✓  Anthropic — key found  [{args.claude_model}]")
    else:
        print("  ✗  Claude — ANTHROPIC_API_KEY not set")

    ollama_up = _is_ollama_up(ollama_host)
    if ollama_up:
        if args.all_local:
            local_models = _ollama_models(ollama_host)
        elif args.local_models:
            local_models = [m.strip() for m in args.local_models.split(',') if m.strip()]
        else:
            local_models = ['qwen2.5:7b']

        for model in local_models:
            providers.append({'label': f'Ollama   ({model})', 'mode': 'local',
                              'host': ollama_host, 'model': model})
            print(f"  ✓  Ollama [{model}]")
    else:
        print(f"  ✗  Ollama — {ollama_host} not reachable")

    if _is_hash_up(hash_host):
        providers.append({'label': 'hash-ai', 'mode': 'hash',
                          'host': hash_host, 'token': hash_token})
        print(f"  ✓  hash-ai — running  [{hash_host}]")
    else:
        print("  ✗  hash-ai — not running  (run: hash-ai start)")

    print(f"\nRunning {len(providers)} audit(s)...")

    rows = []
    for p in providers:
        row = _audit(p, target, profile, out_dir)
        if row:
            rows.append(row)

    if rows:
        _print_comparison(rows)
        print(f"\nFull reports saved to: {out_dir}/")
        print("  <provider>.txt        — plain English narrative")
        print("  <provider>.json       — structured findings")
        print("  <provider>.sarif      — SARIF for CI/CD import")
        try:
            from output.dashboard import generate
            all_reports = [json.loads(f.read_text()) for f in sorted(out_dir.glob("*.json"))]
            if all_reports:
                dash_path = generate(all_reports, out_dir / 'dashboard.html')
                print("  dashboard.html        — interactive multi-provider dashboard")
                print(f"\nOpen dashboard:  open {dash_path}")
        except Exception as _dash_err:
            print(f"  [dashboard generation skipped: {_dash_err}]")
    else:
        print("\n[WARN] No providers completed successfully.")


if __name__ == '__main__':
    main()
