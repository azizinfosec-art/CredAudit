import sys, argparse, os, time
from .config import Config, DEFAULT_CONFIG_PATH
from .orchestrator import collect_files, scan_paths
from .utils.common import load_ignore_file
from . import __version__ as _VERSION

def print_banner(when: str = 'default', verbose: bool = False):
    # Only print banner in interactive terminals
    if not sys.stdout.isatty():
        return
    if when == 'scan' and not verbose:
        return
    try:
        # Attempt to load banner.txt from project root relative to this file
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
        p = os.path.join(root, 'banner.txt')
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            tmpl = f.read()
        rendered = tmpl.format(VERSION=_VERSION, URL='https://github.com/azizinfosec-art/CredAudit')
        lines = rendered.splitlines()
        if lines:
            max_len = max(len(l) for l in lines)
            fixed = []
            for i, l in enumerate(lines):
                s = l.strip()
                # Expand any full-width border line of '=' to match max content width
                if s and all(ch == '=' for ch in s):
                    fixed.append('=' * max_len)
                    continue
                # Center version/tagline/URL lines for nicer layout
                if s.startswith('CredAudit v') or s == 'Credential & Secret Scanner' or s.startswith('http') or s.startswith('github.com'):
                    fixed.append(s.center(max_len))
                else:
                    fixed.append(l)
            # Optionally remove a blank line immediately after the top border for a tighter frame
            if len(fixed) >= 2 and fixed[0].strip('=') == '' and fixed[1].strip() == '':
                del fixed[1]
            print("\n".join(fixed))
        else:
            print(rendered)
    except Exception:
        # Silently skip if banner can't be loaded or formatted
        pass

HELP_TEXT = """Usage: credaudit <command> [options]
Commands:
  validate               Check config.yaml and show enabled parsers
  rules                  Show all built-in detection rules
  scan                   Run a scan on files/folders
Scan Options:
  -p, --path PATH        File or folder to scan
  -o, --output-dir DIR   Output directory (default: ./credaudit_out)
  --formats FMT [...]    Report formats: json, csv, html, sarif
  --list                 Dry-run: only list files to be scanned
  --timestamp            Append timestamp to report filenames
  --fail-on LEVEL        Exit non-zero if findings ≥ LEVEL
                         (choices: Low, Medium, High)
File Filtering:
  --include-ext EXT [...]    Only scan these extensions (.txt .json .env ...)
  --include-glob PATTERN [...] Include files matching glob(s)
  --exclude-glob PATTERN [...] Exclude files matching glob(s)
  --ignore-file FILE          Use ignore list (like .credauditignore)
  --max-size MB               Skip files larger than MB
  Supports scanning .har files exported with content (Burp/ZAP/DevTools)
Performance:
  --threads N             Threads for file discovery
  --workers N             Processes for scanning
  --verbose               Show progress and skip reasons
Advanced Features:
  --scan-archives         Enable scanning inside ZIP/RAR archives (optional)
  --archive-depth N       How deep to unpack nested archives
  --no-cache              Force full rescan (ignore cache)
HAR Options:
  --har-include {both,responses,requests}
                         What bodies to scan inside .har (default: both)
  --har-max-body-bytes N  Max size per HAR body in bytes (default: 2097152; env CREDAUDIT_HAR_MAX_BODY_BYTES)
Examples:
  credaudit validate
      Validate config.yaml and show active parsers
  credaudit rules
      List all built-in detection rules
  credaudit scan -p ./secrets --formats html json --timestamp
      Scan a folder and save timestamped HTML+JSON reports
  credaudit scan -p ./app/config.env --include-ext .env --fail-on High
      Scan a single .env file and exit non-zero if High severity secrets found
  credaudit scan -p ./ --no-cache --formats sarif -o ./reports
      Force rescan of all files and export results in SARIF format
"""
def print_rules():
    print("- PrivateKey: PEM-encoded private key material (e.g., -----BEGIN PRIVATE KEY----- ...)")
    print("- AWSAccessKeyID: AWS Access Key ID (e.g., AKIA...)")
    print("- GitHubToken: GitHub-style token (e.g., ghp_...)")
    print("- JWT: JSON Web Token (e.g., eyJ...)")
    print("- PasswordAssignment: Password/secret assignment (explicit) (e.g., password: secret123)")
    print("- PasswordAssignmentLoose: Password with whitespace or separators (guarded) (e.g., password secret123)")
    print("- APIKeyGeneric: Generic API key (e.g., sk-abc123...)")
    print("- SlackWebhook: Slack Incoming Webhook URL (e.g., https://hooks.slack.com/services/...)")
def do_validate(cfg: Config):
    print("Configuration OK")
    print("Enabled parsers: .txt .json .env .docx .pdf .xlsx")
    print(f"Workers: {cfg.workers or 'auto'} | Threads: {cfg.threads}")
    print(f"Include extensions: {', '.join(cfg.include_ext)}")
def parse_common_args(p: argparse.ArgumentParser):
    p.add_argument('-p','--path', required=False, help='File or directory to scan')
    p.add_argument('-o','--output-dir', default='./credaudit_out', help='Output directory')
    p.add_argument('--formats', nargs='+', choices=['json','csv','html','sarif'], default=['json','csv','html'])
    p.add_argument('--include-ext', nargs='*', help='Only scan these extensions (.txt .json .env ...)')
    p.add_argument('--include-glob', action='append', default=[], help='Include files matching glob (repeatable)')
    p.add_argument('--exclude-glob', action='append', default=[], help='Exclude files matching glob (repeatable)')
    p.add_argument('--ignore-file', help='Path to .credauditignore glob list')
    p.add_argument('--max-size', type=int, help='Skip files larger than MB')
    p.add_argument('--threads', type=int, help='Threads for file discovery')
    p.add_argument('--workers', type=int, help='Processes for scanning')
    p.add_argument('--list', action='store_true', help='Dry-run: only list files')
    p.add_argument('--timestamp', action='store_true', help='Append timestamp to report filename')
    p.add_argument('--fail-on', choices=['Low','Medium','High'], help='Exit non-zero if any finding >= threshold')
    p.add_argument('--config', default=DEFAULT_CONFIG_PATH, help='Path to config.yaml')
    p.add_argument('--entropy-min-length', type=int, dest='entropy_min_length', help='Entropy min token length')
    p.add_argument('--entropy-threshold', type=float, dest='entropy_threshold', help='Entropy threshold')
    p.add_argument('--cache-file', help='Cache file name/path')
    p.add_argument('--verbose', action='store_true', help='Verbose logging with skip reasons')
    p.add_argument('--scan-archives', action='store_true', help='Scan inside ZIP/RAR archives (optional)')
    p.add_argument('--archive-depth', type=int, default=1, help='How deep to unpack nested archives')
    p.add_argument('--no-cache', action='store_true', help='Force full rescan (ignore cache)')
    # HAR options
    p.add_argument('--har-include', choices=['both','responses','requests'], default='both',
                   help='When scanning .har: include responses, requests, or both (default: both)')
    p.add_argument('--har-max-body-bytes', type=int,
                   default=None,
                   help='Maximum size of a single HAR body to scan in bytes (default: 2097152; env CREDAUDIT_HAR_MAX_BODY_BYTES)')
    return p
def main(argv=None)->int:
    argv = argv or sys.argv[1:]
    # Version flag (short and long) handled before argparse setup
    if any(a in ('-V','--version') for a in argv):
        print(f"CredAudit v{_VERSION}")
        return 0
    parser=argparse.ArgumentParser(
        prog='credaudit',
        description='CredAudit secret scanner',
        epilog=(
            'Environment:\n'
            '  CREDAUDIT_HTML_MAX_ROWS   Limit rows rendered in HTML report (default: 500)'
        ),
    )
    sub=parser.add_subparsers(dest='command')
    rules_p=sub.add_parser('rules', help='Show built-in detection rules')
    rules_p.add_argument('--no-banner', action='store_true', help='Suppress ASCII banner output')
    validate_p=sub.add_parser('validate', help='Check config and show enabled parsers')
    validate_p.add_argument('--no-banner', action='store_true', help='Suppress ASCII banner output')
    validate_p.add_argument('--config', default=DEFAULT_CONFIG_PATH, help='Path to config.yaml')
    scan_p=sub.add_parser(
        'scan',
        help='Run a scan',
        description='Run a scan and export reports',
        epilog=(
            'Environment:\n'
            '  CREDAUDIT_HTML_MAX_ROWS   Limit rows rendered in HTML report (default: 500)'
        ),
    )
    parse_common_args(scan_p)
    scan_p.add_argument('--no-banner', action='store_true', help='Suppress ASCII banner output')
    if not argv:
        print_banner('default')
        parser.print_help(); return 0
    args=parser.parse_args(argv)
    if args.command=='rules':
        if not getattr(args, 'no_banner', False):
            print_banner('default')
        print_rules(); return 0
    elif args.command=='validate':
        if not getattr(args, 'no_banner', False):
            print_banner('default')
        cfg = Config.from_yaml(args.config or DEFAULT_CONFIG_PATH)
        do_validate(cfg); return 0
    elif args.command=='scan':
        cfg = Config.from_yaml(args.config or DEFAULT_CONFIG_PATH)
        cfg.merge_cli_overrides(vars(args))
        ignore_globs = load_ignore_file(args.ignore_file) if args.ignore_file else []
        if not getattr(args, 'no_banner', False):
            print_banner('scan', verbose=bool(args.verbose))
        files = collect_files(args.path or '.', cfg.include_ext, cfg.include_glob, cfg.exclude_glob,
                              threads=cfg.threads, ignore_globs=ignore_globs,
                              max_size_bytes=(args.max_size*1024*1024 if args.max_size else None),
                              verbose=args.verbose)
        if args.list:
            for f in files: print(f)
            return 0
        t_start = time.perf_counter()
        findings, code = scan_paths(files, args.output_dir, args.formats, args.timestamp,
                                    cfg.cache_file, cfg.entropy_min_length, cfg.entropy_threshold,
                                    cfg.workers, args.fail_on, args.scan_archives, args.archive_depth,
                                    args.verbose, args.no_cache,
                                    har_include=args.har_include,
                                    har_max_body_bytes=args.har_max_body_bytes)
        t_end = time.perf_counter()
        elapsed = t_end - t_start
        # Friendly end-of-run summary
        sev_order = {'Low': 1, 'Medium': 2, 'High': 3}
        cH = sum(1 for f in findings if (f.get('severity') or 'Low') == 'High')
        cM = sum(1 for f in findings if (f.get('severity') or 'Low') == 'Medium')
        cL = sum(1 for f in findings if (f.get('severity') or 'Low') == 'Low')
        fmts = ','.join(args.formats)
        print(f"Scanned {len(files)} files | Findings: {len(findings)} (H:{cH} M:{cM} L:{cL}) | Time: {elapsed:.2f}s | Reports: {args.output_dir} (formats: {fmts})")
        return code
    else:
        parser.print_help(); return 0
if __name__=='__main__':
    raise SystemExit(main())
