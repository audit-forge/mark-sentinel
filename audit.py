#!/usr/bin/env python3
"""
M.A.R.K. Sentinel — AI Security Audit Tool
Powered by Hash

Usage:
  python audit.py --mode config --profile smb --output plain
  python audit.py --mode config --target ./my-app --profile fedramp --output json,plain
  python audit.py --mode api --endpoint https://api.openai.com/v1 --api-key $OPENAI_API_KEY --model gpt-4o
  python audit.py --mode local --ollama-host http://localhost:11434 --model llama3 --output plain,sarif
"""
import argparse
import json
import os
import sys
from pathlib import Path

from connectors.config_connector import scan_directory
from checks.deploy import run_all as deploy_checks
from checks.input_safety import run_all as inp_checks
from checks.output_safety import run_all as out_checks
from checks.agentic import run_all as agent_checks
from checks.supply_chain import run_all as supply_checks
from checks.governance import run_all as gov_checks
from checks import FAIL, SKIP
from output.plain_english import format_report
from output.json_report import format_json
from output.sarif import format_sarif


BANNER = """
╔══════════════════════════════════════════════════╗
║  M.A.R.K. Sentinel — AI Security Audit Tool     ║
║  Powered by Hash                                 ║
╚══════════════════════════════════════════════════╝"""


def load_profile(name: str) -> dict:
    profile_path = Path(__file__).parent / 'profiles' / f'{name}.json'
    if not profile_path.exists():
        available = [p.stem for p in (Path(__file__).parent / 'profiles').glob('*.json')]
        print(f"[ERROR] Profile '{name}' not found. Available: {', '.join(available)}", file=sys.stderr)
        sys.exit(1)
    with open(profile_path) as f:
        return json.load(f)


def filter_results(results: list, profile: dict) -> list:
    if profile.get('checks') == 'all':
        return results
    allowed = set(profile['checks'])
    return [r for r in results if r.check_id in allowed]


def build_scan_context(args):
    mode = args.mode
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"[ERROR] Target not found: {target}", file=sys.stderr)
        sys.exit(1)

    if mode == "api":
        from connectors.api_connector import connect as api_connect
        api_key = args.api_key or os.environ.get("OPENAI_API_KEY", "")
        if not args.endpoint:
            print("[ERROR] --endpoint is required for --mode api", file=sys.stderr)
            sys.exit(1)
        if not api_key:
            print("[WARN] No API key provided. Set --api-key or OPENAI_API_KEY env var.", file=sys.stderr)
        return api_connect(
            endpoint=args.endpoint,
            api_key=api_key,
            model=args.model,
            target_dir=str(target),
        )

    if mode == "local":
        from connectors.ollama_connector import connect as ollama_connect
        return ollama_connect(
            host=args.ollama_host,
            model=args.model,
            target_dir=str(target),
        )

    if mode == "gemini":
        from connectors.gemini_connector import connect as gemini_connect
        import os as _os
        api_key = args.gemini_api_key or _os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            print("[ERROR] --gemini-api-key or GEMINI_API_KEY env var required for --mode gemini", file=sys.stderr)
            sys.exit(1)
        model = args.model if args.model != "gpt-4o" else "gemini-1.5-flash"
        return gemini_connect(api_key=api_key, model=model, target_dir=str(target))

    if mode == "hash":
        from connectors.hash_connector import connect as hash_connect
        return hash_connect(
            host=args.hash_host,
            token=args.hash_token,
            target_dir=str(target),
        )

    # config mode
    return scan_directory(str(target), mode="config")


def main():
    parser = argparse.ArgumentParser(
        description='M.A.R.K. Sentinel — AI Security Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python audit.py --mode config --profile smb --output plain
  python audit.py --mode config --target ./my-app --profile default --output json,plain
  python audit.py --mode api --endpoint https://api.openai.com/v1 --api-key sk-... --model gpt-4o
  python audit.py --mode local --ollama-host http://localhost:11434 --model llama3 --output plain,sarif
        """,
    )
    parser.add_argument(
        '--mode',
        choices=['config', 'api', 'local', 'gemini', 'hash', 'docker', 'kubectl'],
        default='config',
        help='Scan mode (default: config)',
    )
    parser.add_argument(
        '--target', '--fixture',
        default='.',
        metavar='PATH',
        help='Directory to scan for config issues (default: current directory)',
    )
    parser.add_argument(
        '--profile',
        default='default',
        help='Audit profile: smb, fedramp, cmmc, default (default: default)',
    )
    parser.add_argument(
        '--output',
        default='plain',
        help='Output format(s), comma-separated: plain, json, sarif (default: plain)',
    )
    parser.add_argument(
        '--out-file',
        default=None,
        metavar='FILE',
        help='Write output to this file (in addition to stdout)',
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress banner and progress output',
    )
    # API mode args
    parser.add_argument(
        '--endpoint',
        default=None,
        metavar='URL',
        help='OpenAI-compatible API endpoint (for --mode api)',
    )
    parser.add_argument(
        '--api-key',
        default=None,
        metavar='KEY',
        help='API key for the endpoint (or set OPENAI_API_KEY env var)',
    )
    parser.add_argument(
        '--model',
        default='gpt-4o',
        help='Model name to probe (default: gpt-4o)',
    )
    # Local/Ollama args
    parser.add_argument(
        '--ollama-host',
        default='http://localhost:11434',
        metavar='URL',
        help='Ollama host URL (for --mode local, default: http://localhost:11434)',
    )
    # Gemini args
    parser.add_argument(
        '--gemini-api-key',
        default=None,
        metavar='KEY',
        help='Google AI API key (for --mode gemini; or set GEMINI_API_KEY env var)',
    )
    # Hash/openclaw args
    parser.add_argument(
        '--hash-host',
        default='http://127.0.0.1:8400',
        metavar='URL',
        help='hash runtime host URL (for --mode hash, default: http://127.0.0.1:8400)',
    )
    parser.add_argument(
        '--hash-token',
        default='',
        metavar='TOKEN',
        help='hash bearer token if auth is enabled (for --mode hash)',
    )
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    if args.mode in ('docker', 'kubectl'):
        print(f"\n[INFO] '{args.mode}' mode will be available in Phase 3. Running config mode scan.\n")
        args.mode = 'config'

    profile = load_profile(args.profile)
    target = Path(args.target).resolve()

    if not args.quiet:
        mode_label = args.mode
        if args.mode == "api" and args.endpoint:
            mode_label = f"api ({args.endpoint})"
        elif args.mode == "local":
            mode_label = f"local ({args.ollama_host})"
        elif args.mode == "gemini":
            model_label = args.model if args.model != "gpt-4o" else "gemini-1.5-flash"
            mode_label = f"gemini ({model_label})"
        elif args.mode == "hash":
            mode_label = f"hash ({args.hash_host})"
        print(f"\nTarget:  {target}")
        print(f"Profile: {profile['name']}  |  Mode: {mode_label}")
        print(f"{'─' * 52}")
        if args.mode in ("api", "local", "gemini", "hash"):
            print("Connecting and running probes...", end='', flush=True)
        else:
            print("Scanning...", end='', flush=True)

    ctx = build_scan_context(args)

    if not args.quiet:
        if args.mode in ("api", "local", "gemini", "hash"):
            probe_count = len(ctx.probe_results)
            if ctx.live_error:
                print(f" connection error: {ctx.live_error}")
            else:
                print(f" {probe_count} probes run. Config scan: {ctx.total_files_scanned} files.\n")
        else:
            print(f" {ctx.total_files_scanned} files scanned.\n")

    # Run all check modules
    results = []
    results.extend(deploy_checks(ctx))
    results.extend(inp_checks(ctx))
    results.extend(out_checks(ctx))
    results.extend(agent_checks(ctx))
    results.extend(supply_checks(ctx))
    results.extend(gov_checks(ctx))

    # Apply profile filter
    results = filter_results(results, profile)

    # Format and output
    output_formats = [f.strip().lower() for f in args.output.split(',')]

    output_text = None
    if 'plain' in output_formats:
        output_text = format_report(results, profile, str(target))
        print(output_text)

    if 'json' in output_formats:
        json_text = format_json(results, profile, str(target), args.mode)
        if 'plain' not in output_formats:
            print(json_text)
        if args.out_file:
            out_path = args.out_file
            if not out_path.endswith('.json'):
                out_path += '.json'
            with open(out_path, 'w') as f:
                f.write(json_text)
            print(f"\n[JSON report written to {out_path}]")

    if 'sarif' in output_formats:
        sarif_text = format_sarif(results, profile, str(target), args.mode)
        if not set(output_formats) & {'plain', 'json'}:
            print(sarif_text)
        out_path = args.out_file
        if out_path:
            if not out_path.endswith('.sarif') and not out_path.endswith('.json'):
                out_path += '.sarif'
            with open(out_path, 'w') as f:
                f.write(sarif_text)
            print(f"\n[SARIF report written to {out_path}]")

    # Compliance output (Phase 3)
    if 'compliance' in output_formats:
        try:
            from output.compliance import write_compliance_report
        except Exception:
            write_compliance_report = None
        if write_compliance_report:
            # Convert CheckResult dataclasses into dicts expected by compliance.generate_compliance_report
            findings = []
            for r in results:
                f = {
                    'id': getattr(r, 'check_id', ''),
                    'title': getattr(r, 'title', ''),
                    'category': getattr(r, 'category', ''),
                    'severity': getattr(r, 'severity', '').lower(),
                    'result': getattr(r, 'status', ''),
                    'description': getattr(r, 'details', ''),
                    'remediation': getattr(r, 'remediation', ''),
                    'evidence': getattr(r, 'evidence', []),
                }
                frameworks = getattr(r, 'frameworks', {}) or {}
                # convert frameworks dict to list of {framework,control}
                fmap = []
                for k, v in frameworks.items():
                    if isinstance(v, str):
                        controls = [c.strip() for c in str(v).split(',')]
                        for c in controls:
                            fmap.append({'framework': k, 'control': c})
                    elif isinstance(v, list):
                        for c in v:
                            fmap.append({'framework': k, 'control': c})

                # Augment with FedRAMP/NIST control IDs from a machine-readable mapping file if present
                try:
                    fed_map_path = Path(__file__).parent / 'profiles' / 'fedramp_controls.json'
                    if fed_map_path.exists():
                        fedmap = json.loads(fed_map_path.read_text())
                        extra = fedmap.get(f.get('id')) or fedmap.get(getattr(r, 'check_id', ''))
                        if extra:
                            for c in extra:
                                # avoid duplicates
                                if not any(x for x in fmap if x.get('framework') == 'FedRAMP' and x.get('control') == c):
                                    fmap.append({'framework': 'FedRAMP', 'control': c})
                except Exception:
                    pass

                f['frameworks'] = fmap
                findings.append(f)

            artifacts_dir = Path(__file__).parent / 'output' / 'artifacts'
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            out_md = artifacts_dir / f'compliance_{profile["name"].lower().replace(" ", "_")}.md'
            write_compliance_report(str(out_md), findings, profile_name=profile.get('name'))
            print(f"\n[Compliance report written to {out_md}]")

    if args.out_file and 'json' not in output_formats and 'sarif' not in output_formats and output_text:
        with open(args.out_file, 'w') as f:
            f.write(output_text)
        print(f"\n[Report written to {args.out_file}]")

    has_fail = any(r.status == FAIL for r in results)
    sys.exit(1 if has_fail else 0)


if __name__ == '__main__':
    main()
