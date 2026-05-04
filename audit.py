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
import sys
if sys.version_info < (3, 11):
    sys.exit(
        "M.A.R.K. Sentinel requires Python 3.11 or later.\n"
        f"Running: Python {sys.version.split()[0]}\n"
        "Install: https://python.org/downloads/"
    )
import argparse
import json
import os
import socket
from pathlib import Path

from connectors.config_connector import scan_directory
from checks.deploy import run_all as deploy_checks
from checks.input_safety import run_all as inp_checks
from checks.output_safety import run_all as out_checks
from checks.agentic import run_all as agent_checks
from checks.supply_chain import run_all as supply_checks
from checks.governance import run_all as gov_checks
from checks.ai_tools import run_all as tool_checks
from checks import FAIL
from output.plain_english import format_report
from output.json_report import format_json
from output.sarif import format_sarif


BANNER = """
╔══════════════════════════════════════════════════╗
║  M.A.R.K. Sentinel — AI Security Audit Tool     ║
║  Powered by Hash                                 ║
╚══════════════════════════════════════════════════╝"""


_SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']


def load_profile(name: str) -> dict:
    profile_path = Path(__file__).parent / 'profiles' / f'{name}.json'
    if not profile_path.exists():
        available = sorted(p.stem for p in (Path(__file__).parent / 'profiles').glob('*.json')
                           if not p.stem.endswith('_controls'))
        print(f"[ERROR] Profile '{name}' not found. Available: {', '.join(available)}", file=sys.stderr)
        sys.exit(1)
    with open(profile_path) as f:
        profile = json.load(f)
    emphasis = profile.get('framework_emphasis')
    if emphasis:
        controls_path = Path(__file__).parent / 'profiles' / f'{emphasis}_controls.json'
        if controls_path.exists():
            with open(controls_path) as f:
                profile['_controls'] = json.load(f)
    return profile


def filter_results(results: list, profile: dict) -> list:
    if profile.get('checks') != 'all':
        allowed = set(profile['checks'])
        results = [r for r in results if r.check_id in allowed]
    threshold = profile.get('severity_threshold', 'LOW')
    if threshold in _SEV_ORDER:
        cutoff = _SEV_ORDER.index(threshold)
        results = [r for r in results
                   if r.severity not in _SEV_ORDER or _SEV_ORDER.index(r.severity) <= cutoff]
    return results


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
        api_key = args.gemini_api_key or _os.environ.get("GEMINI_API_KEY", "") or _os.environ.get("GOOGLE_API_KEY", "")
        if not api_key:
            print("[ERROR] --gemini-api-key or GEMINI_API_KEY/GOOGLE_API_KEY env var required for --mode gemini", file=sys.stderr)
            sys.exit(1)
        model = args.model if args.model != "gpt-4o-2024-11-20" else "gemini-1.5-flash"
        return gemini_connect(api_key=api_key, model=model, target_dir=str(target))

    if mode == "vertex":
        from connectors.vertex_connector import connect as vertex_connect
        import os as _os
        key_file = args.vertex_key_file or _os.environ.get("VERTEX_SA_KEY_FILE", "")
        project = args.vertex_project or _os.environ.get("VERTEX_PROJECT", "")
        if not key_file:
            print("[ERROR] --vertex-key-file or VERTEX_SA_KEY_FILE env var required for --mode vertex", file=sys.stderr)
            sys.exit(1)
        if not project:
            print("[ERROR] --vertex-project or VERTEX_PROJECT env var required for --mode vertex", file=sys.stderr)
            sys.exit(1)
        model = args.model if args.model != "gpt-4o-2024-11-20" else "gemini-1.5-flash"
        region = args.vertex_region
        return vertex_connect(key_file=key_file, project=project, model=model, region=region, target_dir=str(target))

    if mode == "anthropic":
        from connectors.claude_connector import connect as claude_connect
        import os as _os
        api_key = args.anthropic_api_key or _os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print("[ERROR] --anthropic-api-key or ANTHROPIC_API_KEY env var required for --mode anthropic", file=sys.stderr)
            sys.exit(1)
        model = args.model if args.model != "gpt-4o-2024-11-20" else "claude-opus-4-7"
        return claude_connect(api_key=api_key, model=model, target_dir=str(target))

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
  python audit.py --mode gemini --gemini-api-key AIza... --model gemini-1.5-flash
  python audit.py --mode anthropic --anthropic-api-key sk-ant-... --model claude-opus-4-7
  python audit.py --mode local --ollama-host http://localhost:11434 --model qwen2.5:7b --output plain,sarif
        """,
    )
    parser.add_argument(
        '--mode',
        choices=['config', 'api', 'local', 'gemini', 'vertex', 'anthropic', 'hash', 'docker', 'kubectl'],
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
        help='Output format(s), comma-separated: plain, json, sarif, compliance, rego, kyverno, defectdojo (default: plain)',
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
        default='gpt-4o-2024-11-20',
        help='Model name to probe (default: gpt-4o-2024-11-20)',
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
    # Vertex AI args
    parser.add_argument(
        '--vertex-key-file',
        default=None,
        metavar='FILE',
        help='Path to GCP service account JSON key (for --mode vertex; or set VERTEX_SA_KEY_FILE env var)',
    )
    parser.add_argument(
        '--vertex-project',
        default=None,
        metavar='PROJECT_ID',
        help='GCP project ID (for --mode vertex; or set VERTEX_PROJECT env var)',
    )
    parser.add_argument(
        '--vertex-region',
        default='us-central1',
        metavar='REGION',
        help='Vertex AI region (for --mode vertex, default: us-central1)',
    )
    # Anthropic/Claude args
    parser.add_argument(
        '--anthropic-api-key',
        default=None,
        metavar='KEY',
        help='Anthropic API key (for --mode anthropic; or set ANTHROPIC_API_KEY env var)',
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
    # DefectDojo args (used when --output includes "defectdojo")
    parser.add_argument(
        '--defectdojo-url',
        default=None,
        metavar='URL',
        help='DefectDojo base URL (or set DEFECTDOJO_URL env var)',
    )
    parser.add_argument(
        '--defectdojo-key',
        default=None,
        metavar='KEY',
        help='DefectDojo API token (or set DEFECTDOJO_API_KEY env var)',
    )
    parser.add_argument(
        '--defectdojo-product',
        default=None,
        metavar='NAME',
        help='DefectDojo product name (default: "M.A.R.K. Sentinel — <target>")',
    )
    parser.add_argument(
        '--defectdojo-engagement',
        default=None,
        metavar='NAME',
        help='DefectDojo engagement name (default: "<profile> — <date>")',
    )
    parser.add_argument(
        '--defectdojo-push-all',
        action='store_true',
        help='Push PASS findings to DefectDojo in addition to FAIL/WARN (default: FAIL/WARN only)',
    )
    parser.add_argument(
        '--alerts',
        default=None,
        metavar='FILE',
        help='Path to alerts_config.json — send email/webhook notifications for new critical findings',
    )
    args = parser.parse_args()

    # history subcommand — delegate to audit_history.py CLI
    if len(sys.argv) > 1 and sys.argv[1] == 'history':
        import subprocess as _sp
        _sp.run([sys.executable, str(Path(__file__).parent / 'audit_history.py')] + sys.argv[2:])
        return

    if not args.quiet:
        print(BANNER, file=sys.stderr)

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
            model_label = args.model if args.model != "gpt-4o-2024-11-20" else "gemini-1.5-flash"
            mode_label = f"gemini ({model_label})"
        elif args.mode == "vertex":
            model_label = args.model if args.model != "gpt-4o-2024-11-20" else "gemini-1.5-flash"
            mode_label = f"vertex ({model_label} / {args.vertex_region})"
        elif args.mode == "anthropic":
            model_label = args.model if args.model != "gpt-4o-2024-11-20" else "claude-opus-4-7"
            mode_label = f"anthropic ({model_label})"
        elif args.mode == "hash":
            mode_label = f"hash ({args.hash_host})"
        print(f"\nTarget:  {target}", file=sys.stderr)
        print(f"Profile: {profile['name']}  |  Mode: {mode_label}", file=sys.stderr)
        print(f"{'─' * 52}", file=sys.stderr)
        if args.mode in ("api", "local", "gemini", "vertex", "anthropic", "hash"):
            print("Connecting and running probes...", end='', flush=True, file=sys.stderr)
        else:
            print("Scanning...", end='', flush=True, file=sys.stderr)

    ctx = build_scan_context(args)

    if not args.quiet:
        if args.mode in ("api", "local", "gemini", "vertex", "anthropic", "hash"):
            probe_count = len(ctx.probe_results)
            if ctx.live_error:
                print(f" connection error: {ctx.live_error}", file=sys.stderr)
            else:
                print(f" {probe_count} probes run. Config scan: {ctx.total_files_scanned} files.\n", file=sys.stderr)
        else:
            print(f" {ctx.total_files_scanned} files scanned.\n", file=sys.stderr)

    # Run all check modules
    results = []
    results.extend(deploy_checks(ctx))
    results.extend(inp_checks(ctx))
    results.extend(out_checks(ctx))
    results.extend(agent_checks(ctx))
    results.extend(supply_checks(ctx))
    results.extend(gov_checks(ctx))
    results.extend(tool_checks(ctx))

    # Apply profile filter
    results = filter_results(results, profile)

    # Format and output
    output_formats = [f.strip().lower() for f in args.output.split(',')]

    output_text = None
    if 'plain' in output_formats:
        _model = args.model if args.mode not in ('config', 'hash') else ''
        output_text = format_report(results, profile, str(target), mode=args.mode, model=_model)
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
            print(f"\n[JSON report written to {out_path}]", file=sys.stderr)

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
            print(f"\n[SARIF report written to {out_path}]", file=sys.stderr)

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

    if 'rego' in output_formats:
        from output.rego import format_rego
        rego_text = format_rego(results, profile, str(target), args.mode)
        out_path = args.out_file
        if out_path:
            rego_path = out_path if out_path.endswith('.rego') else out_path + '.rego'
            with open(rego_path, 'w') as f:
                f.write(rego_text)
            print(f"\n[Rego policy written to {rego_path}]")
        else:
            print(rego_text)

    if 'kyverno' in output_formats:
        from output.kyverno import format_kyverno
        kyverno_text = format_kyverno(results, profile, str(target), args.mode)
        out_path = args.out_file
        if out_path:
            kyverno_path = out_path if out_path.endswith('.yaml') else out_path + '_kyverno.yaml'
            with open(kyverno_path, 'w') as f:
                f.write(kyverno_text)
            print(f"\n[Kyverno policies written to {kyverno_path}]")
        else:
            print(kyverno_text)

    if 'defectdojo' in output_formats:
        from connectors.defectdojo_connector import push_findings as dojo_push
        dojo_url = args.defectdojo_url or os.environ.get('DEFECTDOJO_URL', '')
        dojo_key = args.defectdojo_key or os.environ.get('DEFECTDOJO_API_KEY', '')
        if not dojo_url or not dojo_key:
            print(
                "\n[ERROR] DefectDojo output requires --defectdojo-url and --defectdojo-key "
                "(or DEFECTDOJO_URL / DEFECTDOJO_API_KEY env vars).",
                file=sys.stderr,
            )
        else:
            print("\nPushing findings to DefectDojo...", end='', flush=True)
            try:
                summary = dojo_push(
                    results=results,
                    profile=profile,
                    target=str(target),
                    mode=args.mode,
                    url=dojo_url,
                    api_key=dojo_key,
                    product_name=args.defectdojo_product or None,
                    engagement_name=args.defectdojo_engagement or None,
                    push_passing=args.defectdojo_push_all,
                )
                print(" done.")
                print(f"  Pushed:  {summary['pushed']} findings")
                print(f"  Skipped: {summary['skipped']} (PASS/SKIP not pushed)")
                if summary['errors']:
                    print(f"  Errors:  {len(summary['errors'])}")
                    for err in summary['errors']:
                        print(f"    - {err}")
                print(f"  Engagement: {summary['engagement_url']}")
            except Exception as exc:
                print(f" failed: {exc}", file=sys.stderr)

    if 'dashboard' in output_formats:
        from output.dashboard import generate
        _model = getattr(args, 'model', '') or ''
        _label = args.mode
        json_data = json.loads(format_json(results, profile, str(target), args.mode))
        json_data['_provider_label'] = _label
        json_data['_model'] = _model
        dash_file = (args.out_file.rsplit('.', 1)[0] + '_dashboard.html') if args.out_file else str(target.name) + '_dashboard.html'
        dash_path = generate([json_data], dash_file)
        print(f"\n[Dashboard written to {dash_path}]", file=sys.stderr)

    if args.out_file and 'json' not in output_formats and 'sarif' not in output_formats and output_text:
        with open(args.out_file, 'w') as f:
            f.write(output_text)
        print(f"\n[Report written to {args.out_file}]")

    if args.alerts:
        try:
            from alerts import load_alert_config, fire_alerts
            alert_cfg = load_alert_config(Path(args.alerts))
            if alert_cfg:
                report_dict = json.loads(format_json(results, profile, str(target), args.mode))
                fire_alerts(report_dict, socket.gethostname(), socket.gethostname(), alert_cfg)
            else:
                print(f"[WARN] Could not load alerts config: {args.alerts}", file=sys.stderr)
        except Exception as _ae:
            print(f"[WARN] Alerts failed: {_ae}", file=sys.stderr)

    has_fail = any(r.status == FAIL for r in results)
    sys.exit(1 if has_fail else 0)


if __name__ == '__main__':
    main()
