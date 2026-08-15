import sys, argparse, os, time
from pathlib import Path
from .detection.rules import build_rules
from .config import Config, DEFAULT_CONFIG_PATH
from .orchestrator import collect_files, scan_paths
from .utils.common import load_ignore_file, redact_finding_records
from . import __version__ as _VERSION

def _shorten(value, limit=80):
    text = str(value or '')
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + '...'

def _green(value):
    if sys.stdout.isatty() and not os.environ.get('NO_COLOR'):
        return f"\033[32m{value}\033[0m"
    return value

def _color_severity(value, severity=None):
    text = str(value or '')
    if not sys.stdout.isatty() or os.environ.get('NO_COLOR'):
        return text
    sev = str(severity or text).strip()
    colors = {
        'Critical': '35',
        'Low': '34',
        'Medium': '38;5;208',
        'High': '31',
    }
    code = colors.get(sev)
    if not code:
        return text
    return f"\033[{code}m{text}\033[0m"

def _format_confidence(value):
    try:
        return f"{int(value)}%"
    except Exception:
        return ""

def print_console_findings(findings, limit=50, show_evidence=False):
    safe = redact_finding_records(findings)
    if not safe:
        print("No findings.")
        return
    shown = safe[: max(0, int(limit or 0))]
    print("\nFindings (redacted)")
    print("-" * 112)
    print(f"{'Severity':<8} {'Rule':<24} {'Line':<6} {'File':<80} {'Value':<24} Score")
    print("-" * 112)
    for f in shown:
        sev = _shorten(f.get('severity', ''), 8)
        sev_display = _color_severity(f"{sev:<8}", sev)
        rule = _shorten(f.get('rule', ''), 24)
        line = _shorten(f.get('line', ''), 6)
        value = _shorten(f.get('redacted', ''), 24)
        path = _shorten(f.get('file', ''), 80)
        score = _format_confidence(f.get('confidence', ''))
        print(f"{sev_display} {rule:<24} {line:<6} {path:<80} {_green(value):<24} {score}")
        if show_evidence:
            evidence = f.get('evidence') or []
            if isinstance(evidence, list) and evidence:
                print(f"  Evidence: {_shorten('; '.join(str(x) for x in evidence), 140)}")
    if len(safe) > len(shown):
        print(f"... showing {len(shown)} of {len(safe)} findings. Use --console-limit to show more.")
    print("Use --formats html csv json to save final reports.")

def _file_url(path):
    try:
        return Path(path).resolve().as_uri()
    except Exception:
        return os.path.abspath(path)

def _generated_report_path(output_dir, fmt, timestamp, started_at=None):
    out_dir = os.path.abspath(output_dir)
    if not timestamp:
        path = os.path.join(out_dir, f"report.{fmt}")
        return path if os.path.exists(path) else None
    try:
        suffix = f".{fmt}"
        candidates = [
            os.path.join(out_dir, name)
            for name in os.listdir(out_dir)
            if name.startswith("report_") and name.endswith(suffix)
        ]
        if started_at is not None:
            recent = [
                p for p in candidates
                if os.path.getmtime(p) >= max(0, float(started_at) - 1.0)
            ]
            if recent:
                candidates = recent
        if not candidates:
            return None
        return max(candidates, key=lambda p: os.path.getmtime(p))
    except Exception:
        return None

def print_report_links(output_dir, formats, timestamp, started_at=None):
    links = []
    for fmt in formats:
        path = _generated_report_path(output_dir, fmt, timestamp, started_at)
        if path:
            links.append((fmt.upper(), _file_url(path)))
    if not links:
        return
    print("Report URLs:")
    for label, url in links:
        print(f"  {label}: {url}")

def _default_ndjson_path(output_dir, timestamp=False, wall_started_at=None):
    out_dir = os.path.abspath(output_dir)
    if timestamp:
        ts = time.strftime('%Y%m%d_%H%M%S', time.localtime(wall_started_at or time.time()))
        return os.path.join(out_dir, f'findings_{ts}.ndjson')
    return os.path.join(out_dir, 'findings.ndjson')

def print_ndjson_link(path):
    if path:
        print(f"NDJSON: {_file_url(path)}")

FAST_EXCLUDE_GLOBS = [
    "**/.git/**",
    "**/__pycache__/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/env/**",
    "**/build/**",
    "**/dist/**",
    "**/*.egg-info/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/credaudit_out/**",
]

PASSWORD_INTENT_COMMANDS = {"password", "passwords", "cred", "creds", "credentials"}
PASSWORD_INTENT_RULES = [
    "CredentialPair",
    "PasswordValueAssignment",
    "PasswordValueAssignmentLoose",
    "UsernameNearPassword",
    "PasswordCandidate",
]

PASSWORD_CONFIG_RULES = {
    "PasswordAssignment",
    "PasswordAssignmentLoose",
    "PasswordValueAssignment",
    "PasswordValueAssignmentLoose",
    "PasswordKeyword",
}
PRIVATE_KEY_CONFIG_RULES = {"PrivateKey"}
JWT_CONFIG_RULES = {"JWT"}
CLOUD_TOKEN_CONFIG_RULES = {
    "APIKeyGeneric",
    "AWSAccessKeyID",
    "AWSSecretAccessKey",
    "AzureSAS",
    "GitHubToken",
    "GitLabPAT",
    "GoogleAPIKey",
    "NpmToken",
    "OpenAIKey",
    "SendGridKey",
    "SlackToken",
    "SlackWebhook",
    "StripeKey",
    "TelegramBotToken",
    "TwilioAccountSID",
    "TwilioAuthToken",
}

def _has_cli_option(argv, names):
    for arg in argv:
        for name in names:
            if arg == name or arg.startswith(name + "="):
                return True
    return False

def _parse_only_rules(tokens, rule_level):
    if not tokens:
        return None
    names = [r.name for r in build_rules(rule_level)]
    selected = []
    for part in tokens:
        for token in str(part).split(','):
            token = token.strip()
            if not token:
                continue
            if token.isdigit() and 1 <= int(token) <= len(names):
                selected.append(names[int(token) - 1])
            else:
                selected.append(token)
    return list(dict.fromkeys(selected))

def _configured_only_rules(cfg: Config, rule_level, tokens):
    selected = _parse_only_rules(tokens, rule_level)
    toggles = getattr(cfg, "rules", None)
    disabled = set()
    if toggles is not None:
        if not getattr(toggles, "enable_password_assignment", True):
            disabled.update(PASSWORD_CONFIG_RULES)
        if not getattr(toggles, "enable_jwt", True):
            disabled.update(JWT_CONFIG_RULES)
        if not getattr(toggles, "enable_private_keys", True):
            disabled.update(PRIVATE_KEY_CONFIG_RULES)
        if not getattr(toggles, "enable_cloud_tokens", True):
            disabled.update(CLOUD_TOKEN_CONFIG_RULES)
        if not getattr(toggles, "enable_entropy", True):
            disabled.add("HighEntropyString")
    if not disabled:
        return selected
    if selected is None:
        selected = [r.name for r in build_rules(rule_level)]
        if (rule_level or 2) >= 2:
            selected.append("HighEntropyString")
    return [name for name in selected if name not in disabled]

def _expand_password_intent(argv):
    if not argv or argv[0] not in PASSWORD_INTENT_COMMANDS:
        return argv, None
    rest = list(argv[1:])
    if rest and rest[0] in ("-h", "--help"):
        return ["scan", "--help"], "passwords"
    defaults = []
    if not _has_cli_option(rest, ["--include-ext", "--include-glob", "--full", "--standard"]):
        defaults.extend(["--include-ext", ".txt"])
    if not _has_cli_option(rest, ["--max-size", "--max-size-kb"]):
        defaults.extend(["--max-size", "5"])
    if not _has_cli_option(rest, ["--only-rules"]):
        defaults.extend(["--only-rules", *PASSWORD_INTENT_RULES])
    if not _has_cli_option(rest, ["--min-confidence", "--high-confidence"]):
        defaults.extend(["--min-confidence", "50"])
    return ["scan", *rest, *defaults], "passwords"

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
  passwords              Find password-like values in small .txt files
Scan Options:
  -p, --path PATH        File or folder to scan
  -o, --output-dir DIR   Output directory (default: ./credaudit_out)
  --formats FMT [...]    Final report formats: json, csv, html, sarif
  --safe                 Redacted reports and no raw-secret cache writes (default)
  --raw                  Allow raw findings in reports/cache for internal remediation
  --list                 Dry-run: only list files to be scanned
  --timestamp            Append timestamp to report filenames (default with --formats)
  --no-timestamp         Use fixed report filenames such as report.html
  --fail-on LEVEL        Exit non-zero if findings >= LEVEL
                         (choices: Low, Medium, High, Critical)
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
  --fast                  Fast directory defaults: .txt only, 10 KB max files, short timeout
                          Explicit file targets are scanned directly.
  --full, --standard      Use full configured scan scope instead of fast defaults
Rule Selection:
  --only-rules R1 [R2 ...]  Restrict scanning to specific rule names or indices (from `credaudit rules`).
                            Accepts comma- or space-separated values, e.g., "PasswordAssignment,HighEntropyString" or "1 4 6".
Evidence:
  --high-confidence      Show/export only findings with confidence >= 80
  --min-confidence N     Show/export only findings with confidence >= N (0-100)
  --show-evidence        Print confidence evidence reasons in console mode
Sensitivity:
  --sensitivity {1,2,3}   Rule sensitivity: 1=cautious, 2=balanced (default), 3=aggressive
                           Aliases: L1/L2/L3 or low/medium/high
HAR Options:
  --har-include {both,responses,requests}
                         What bodies to scan inside .har (default: both)
  --har-max-body-bytes N  Max size per HAR body in bytes (default: 2097152; env CREDAUDIT_HAR_MAX_BODY_BYTES)
NDJSON Options:
  --ndjson-out PATH       Stream findings to NDJSON during scan
                          (default: ./credaudit_out/findings.ndjson)
  --no-ndjson             Disable the default NDJSON stream
  --ndjson-truncate       Truncate explicit NDJSON file before writing
  --ndjson-flush-sec SEC  Flush NDJSON at least every SEC seconds (default: 1.0)
  --ndjson-buffer N       Flush NDJSON after N findings (default: 100)
  --ndjson-include-raw    Include raw matched values (redacted-only by default)
Timeouts:
  --per-file-timeout SEC  Kill and skip a file if scanning exceeds SEC seconds (default: 2; 0=disable)
User Experience:
  Spinner shown in TTY (suppressed with --verbose). End-of-run summary includes elapsed time.
Examples:
  credaudit validate
      Validate config.yaml and show active parsers
  credaudit rules
      List all built-in detection rules
  credaudit scan -p ./secrets --formats html json
      Scan a folder and save timestamped HTML+JSON reports
  credaudit passwords ./client-data
      Find password-like entries in .txt files up to 5 MB with balanced confidence
  credaudit scan -p ./app/config.env --include-ext .env --fail-on High
      Scan a single .env file and exit non-zero if High severity secrets found
  credaudit scan -p ./ --no-cache --formats sarif -o ./reports
      Force rescan of all files and export results in SARIF format
"""

EXAMPLES_TEXT = """CredAudit example commands

Quick safe scan:
  credaudit ./client-data

Save HTML and JSON reports:
  credaudit ./client-data --formats html json

Scan a single file:
  credaudit ./secrets.txt

Run the full configured scope:
  credaudit scan ./project --full --safe --formats html json

Password-focused audit:
  credaudit passwords ./client-data

CI/SARIF scan:
  credaudit scan -p . --full --safe --formats sarif --no-timestamp --fail-on High
"""

def print_rules():
    try:
        rules = build_rules(3)
    except Exception:
        rules = []
    if not rules:
        print("No rules available.")
        return
    print("Active rules (index: name - description)")
    for i, r in enumerate(rules, start=1):
        desc = getattr(r, 'description', '') or ''
        print(f"{i}) {r.name} - {desc}")
def do_validate(cfg: Config):
    print("Configuration OK")
    supported = [
        ".txt", ".json", ".env", ".log", ".cfg", ".ini", ".yaml", ".yml",
        ".py", ".js", ".toml", ".docx", ".pdf", ".xlsx", ".har",
    ]
    configured = ", ".join(cfg.include_ext or [])
    print(f"Configured include extensions: {configured or '(none)'}")
    print(f"Supported parser extensions: {', '.join(supported)}")
    print(f"Workers: {cfg.workers or 'auto'} | Threads: {cfg.threads}")
def parse_common_args(p: argparse.ArgumentParser):
    p.add_argument('target', nargs='?', help='File or directory to scan')
    p.add_argument('-p','--path', required=False, help='File or directory to scan')
    p.add_argument('-o','--output-dir', default='./credaudit_out', help='Output directory')
    p.add_argument('--formats', nargs='+', choices=['json','csv','html','sarif'], default=None)
    privacy = p.add_mutually_exclusive_group()
    privacy.add_argument('--safe', '--redacted-only', dest='safe', action='store_true',
                         help='Write redacted-only reports and avoid raw-secret cache writes (default)')
    privacy.add_argument('--raw', action='store_true',
                         help='Allow raw matched values in reports and cache; use only for internal remediation')
    speed = p.add_mutually_exclusive_group()
    speed.add_argument('--fast', action='store_true',
                       help='Fast directory defaults: .txt only, max 10 KB per file, short timeout; explicit file targets are scanned directly (default)')
    speed.add_argument('--full', '--standard', dest='full', action='store_true',
                       help='Use full configured scan scope instead of fast defaults')
    p.add_argument('--include-ext', nargs='*', help='Only scan these extensions (.txt .json .env ...)')
    p.add_argument('--include-glob', action='append', default=[], help='Include files matching glob (repeatable)')
    p.add_argument('--exclude-glob', action='append', default=[], help='Exclude files matching glob (repeatable)')
    p.add_argument('--ignore-file', help='Path to .credauditignore glob list')
    p.add_argument('--max-size', type=int, help='Skip files larger than MB')
    p.add_argument('--max-size-kb', type=int, dest='max_size_kb', help='Skip files larger than KB')
    p.add_argument('--threads', type=int, help='Threads for file discovery')
    p.add_argument('--workers', type=int, help='Processes for scanning')
    p.add_argument('--list', action='store_true', help='Dry-run: only list files')
    p.add_argument('--console-limit', type=int, default=50,
                   help='Max findings shown on screen when --formats is not used')
    p.add_argument('--high-confidence', action='store_true',
                   help='Show/export only findings with confidence >= 80')
    p.add_argument('--min-confidence', type=int,
                   help='Show/export only findings with confidence >= N (0-100)')
    p.add_argument('--show-evidence', action='store_true',
                   help='Print confidence evidence reasons in console output')
    p.add_argument('--timestamp', dest='timestamp', action='store_true', default=None,
                   help='Append timestamp to report filenames (default when --formats is used)')
    p.add_argument('--no-timestamp', dest='timestamp', action='store_false',
                   help='Use fixed report filenames such as report.html')
    p.add_argument('--fail-on', choices=['Low','Medium','High','Critical'], help='Exit non-zero if any finding >= threshold')
    p.add_argument('--config', default=DEFAULT_CONFIG_PATH, help='Path to config.yaml')
    p.add_argument('--entropy-min-length', type=int, dest='entropy_min_length', help='Entropy min token length')
    p.add_argument('--entropy-threshold', type=float, dest='entropy_threshold', help='Entropy threshold')
    p.add_argument('--cache-file', help='Cache file name/path')
    p.add_argument('--verbose', action='store_true', help='Verbose logging with skip reasons')
    p.add_argument('--scan-archives', action='store_true', help='Scan inside ZIP/RAR archives (optional)')
    p.add_argument('--archive-depth', type=int, default=1, help='How deep to unpack nested archives')
    p.add_argument('--no-cache', action='store_true', help='Force full rescan (ignore cache)')
    # Sensitivity (rule level)
    p.add_argument('--sensitivity', choices=['1','2','3','L1','L2','L3','low','medium','high','cautious','balanced','aggressive'],
                   help='Rule sensitivity: 1/L1/low (cautious), 2/L2/medium (balanced), 3/L3/high (aggressive)')
    # HAR options
    p.add_argument('--har-include', choices=['both','responses','requests'], default='both',
                   help='When scanning .har: include responses, requests, or both (default: both)')
    p.add_argument('--har-max-body-bytes', type=int,
                   default=None,
                   help='Maximum size of a single HAR body to scan in bytes (default: 2097152; env CREDAUDIT_HAR_MAX_BODY_BYTES)')
    # NDJSON live output
    p.add_argument('--ndjson-out', dest='ndjson_out', help='Stream findings to NDJSON file (default: output-dir/findings.ndjson)')
    p.add_argument('--no-ndjson', action='store_true', help='Disable the default NDJSON stream')
    p.add_argument('--ndjson-truncate', action='store_true', help='Truncate explicit NDJSON output file before writing')
    p.add_argument('--ndjson-flush-sec', type=float, help='Flush NDJSON at least every SEC seconds (default: 1.0)')
    p.add_argument('--ndjson-buffer', type=int, help='Flush NDJSON after N findings (default: 100)')
    p.add_argument('--ndjson-include-raw', action='store_true', help='Include raw matched values in NDJSON (redacted only by default)')
    # Timeouts
    p.add_argument('--per-file-timeout', type=float, default=None,
                   help='Kill and skip a file if scanning exceeds SEC seconds (default: 2; 0 disables)')
    return p
def main(argv=None)->int:
    argv = argv or sys.argv[1:]
    # Version flag (short and long) handled before argparse setup
    if any(a in ('-V','--version') for a in argv):
        print(f"CredAudit v{_VERSION}")
        return 0
    argv, intent_name = _expand_password_intent(argv)
    known_commands = {'scan', 'rules', 'validate', 'convert', 'examples'}
    if argv and argv[0] not in known_commands and argv[0] not in ('-h', '--help'):
        argv = ['scan'] + argv
    parser=argparse.ArgumentParser(
        prog='credaudit',
        description='CredAudit secret scanner',
        epilog=(
            'Intent shortcuts:\n'
            '  credaudit passwords PATH   Find password-like entries in .txt files up to 5 MB\n'
            '\n'
            'Environment:\n'
            '  CREDAUDIT_HTML_MAX_ROWS   Limit rows rendered in HTML report (default: 500)\n'
            '\n'
            'UX:\n'
            '  Shows a minimal spinner in TTY (suppressed with --verbose).\n'
            '  Prints a compact end-of-run summary with elapsed time.'
        ),
    )
    sub=parser.add_subparsers(dest='command')
    rules_p=sub.add_parser('rules', help='Show built-in detection rules')
    rules_p.add_argument('--no-banner', action='store_true', help='Suppress ASCII banner output')
    examples_p=sub.add_parser('examples', help='Show copy-paste example commands')
    examples_p.add_argument('--no-banner', action='store_true', help='Suppress ASCII banner output')
    validate_p=sub.add_parser('validate', help='Check config and show enabled parsers')
    validate_p.add_argument('--no-banner', action='store_true', help='Suppress ASCII banner output')
    validate_p.add_argument('--config', default=DEFAULT_CONFIG_PATH, help='Path to config.yaml')
    scan_p=sub.add_parser(
        'scan',
        help='Run a scan',
        description='Run a scan and export reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Folder size examples:\n'
            '  Light:  credaudit ./client-data\n'
            '  Medium: credaudit ./client-data --include-ext .txt .json .env .yaml .yml .log .cfg .ini --max-size 10 --per-file-timeout 10 --workers 4 --formats html csv json\n'
            '  Docs:   credaudit ./client-data --include-ext .docx .pdf .xlsx .har --max-size 5 --per-file-timeout 30 --workers 2 --formats html csv json --verbose\n'
            '  Huge:   credaudit ./large-share --include-ext .txt .json .env .yaml .yml .log .cfg .ini --max-size 10 --sensitivity 1 --threads 32 --workers 8 --per-file-timeout 10 --ndjson-out credaudit_out/large_findings.ndjson --ndjson-truncate --no-banner\n'
            '\n'
            'Environment:\n'
            '  CREDAUDIT_HTML_MAX_ROWS   Limit rows rendered in HTML report (default: 500)\n'
            '\n'
            'UX:\n'
            '  Minimal spinner appears in interactive terminals; use --verbose to see tips instead.\n'
            '  Summary line includes severity counts and elapsed time.'
        ),
    )
    parse_common_args(scan_p)
    scan_p.add_argument('--only-rules', nargs='+', help='Restrict scanning to specific rule names or indices (from `credaudit rules`). Comma- or space-separated')
    scan_p.add_argument('--no-banner', action='store_true', help='Suppress ASCII banner output')
    convert_p=sub.add_parser('convert', help='Convert NDJSON findings to reports')
    convert_p.add_argument('--in', dest='inp', required=True, help='Input NDJSON path')
    convert_p.add_argument('--out', dest='out', required=True, help='Output base path (without extension)')
    convert_p.add_argument('--formats', nargs='+', choices=['html','csv'], default=['html'])
    convert_p.add_argument('--safe', '--redacted-only', dest='safe', action='store_true',
                           help='Write redacted-only converted reports')
    if not argv:
        print_banner('default')
        parser.print_help(); return 0
    args=parser.parse_args(argv)
    if args.command=='rules':
        if not getattr(args, 'no_banner', False):
            print_banner('default')
        print_rules(); return 0
    elif args.command=='examples':
        if not getattr(args, 'no_banner', False):
            print_banner('default')
        print(EXAMPLES_TEXT); return 0
    elif args.command=='validate':
        if not getattr(args, 'no_banner', False):
            print_banner('default')
        cfg = Config.from_yaml(args.config or DEFAULT_CONFIG_PATH)
        do_validate(cfg); return 0
    elif args.command=='convert':
        from .exporters.html_exporter import export_html
        from .exporters.csv_exporter import export_csv
        import json
        def _load_ndjson(pth: str):
            out = []
            with open(pth, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        rec = obj.get('finding') if 'finding' in obj else obj
                        rec2 = {
                            'file': rec.get('file',''),
                            'rule': rec.get('rule',''),
                            'match': rec.get('match',''),
                            'redacted': rec.get('redacted', rec.get('value','')),
                            'context': rec.get('context',''),
                            'severity': rec.get('severity','Low'),
                            'confidence': rec.get('confidence', 0),
                            'finding_class': rec.get('finding_class', ''),
                            'validity': rec.get('validity', ''),
                            'evidence': rec.get('evidence', []),
                            'line': rec.get('line',''),
                        }
                        out.append(rec2)
                    except Exception:
                        continue
            return out
        findings = _load_ndjson(args.inp)
        os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
        if 'html' in args.formats:
            export_html(findings, args.out + '.html', redacted_only=bool(getattr(args, 'safe', False)))
        if 'csv' in args.formats:
            export_csv(findings, args.out + '.csv')
        print(f"Converted {len(findings)} findings -> {args.out}.({' '.join(args.formats)})")
        return 0
    elif args.command=='scan':
        cfg = Config.from_yaml(args.config or DEFAULT_CONFIG_PATH)
        cfg.merge_cli_overrides(vars(args))
        if not getattr(args, 'raw', False):
            args.safe = True
        if not getattr(args, 'full', False):
            args.fast = True
        min_confidence = getattr(args, 'min_confidence', None)
        if getattr(args, 'high_confidence', False):
            min_confidence = max(80, int(min_confidence or 0))
        if min_confidence is not None and not (0 <= int(min_confidence) <= 100):
            parser.error("--min-confidence must be between 0 and 100")
        if getattr(args, 'no_ndjson', False) and getattr(args, 'ndjson_out', None):
            parser.error("--no-ndjson cannot be used with --ndjson-out")
        ignore_globs = load_ignore_file(args.ignore_file) if args.ignore_file else []
        target_path = args.path or args.target or '.'
        target_is_file = os.path.isfile(target_path)
        console_mode = args.formats is None
        formats = args.formats or []
        timestamp_reports = bool(formats) if args.timestamp is None else bool(args.timestamp)
        if args.fast and not args.include_ext and not args.include_glob:
            include_exts = [] if target_is_file else ['.txt']
        elif args.include_glob and not args.include_ext:
            include_exts = []
        else:
            include_exts = cfg.include_ext
        exclude_globs = cfg.exclude_glob
        if args.fast:
            exclude_globs = list(dict.fromkeys((exclude_globs or []) + FAST_EXCLUDE_GLOBS))
        if args.max_size_kb is not None:
            max_size_bytes = args.max_size_kb * 1024
        elif args.max_size is not None:
            max_size_bytes = args.max_size * 1024 * 1024
        elif args.fast and target_is_file:
            max_size_bytes = None
        elif args.fast:
            max_size_bytes = 10 * 1024
        else:
            max_size_bytes = None
        per_file_timeout = args.per_file_timeout
        if per_file_timeout is None:
            per_file_timeout = 2.0
        scan_workers = cfg.workers
        if args.fast and args.workers is None:
            scan_workers = min(4, os.cpu_count() or 2)
        if not getattr(args, 'no_banner', False):
            print_banner('scan', verbose=bool(args.verbose))
        files = collect_files(target_path, include_exts, cfg.include_glob, exclude_globs,
                              threads=cfg.threads, ignore_globs=ignore_globs,
                              max_size_bytes=max_size_bytes,
                              verbose=args.verbose)
        if args.list:
            for f in files: print(f)
            return 0
        wall_started_at = time.time()
        t_start = time.perf_counter()
        ndjson_out = getattr(args, 'ndjson_out', None)
        auto_ndjson = False
        if not getattr(args, 'no_ndjson', False) and not ndjson_out:
            ndjson_out = _default_ndjson_path(args.output_dir, timestamp_reports, wall_started_at)
            auto_ndjson = True
        ndjson_truncate = bool(getattr(args, 'ndjson_truncate', False) or auto_ndjson)
        # Map sensitivity to numeric rule level
        sens_map = {
            None: None,
            '1': 1, 'L1': 1, 'low': 1, 'cautious': 1,
            '2': 2, 'L2': 2, 'medium': 2, 'balanced': 2,
            '3': 3, 'L3': 3, 'high': 3, 'aggressive': 3,
        }
        rule_level = sens_map.get(getattr(args, 'sensitivity', None))
        try:
            findings, code = scan_paths(files, args.output_dir, formats, timestamp_reports,
                                        cfg.cache_file, cfg.entropy_min_length, cfg.entropy_threshold,
                                        scan_workers, args.fail_on, args.scan_archives, args.archive_depth,
                                        args.verbose, args.no_cache,
                                        har_include=args.har_include,
                                        har_max_body_bytes=args.har_max_body_bytes,
                                        rule_level=rule_level,
                                        ndjson_out=ndjson_out,
                                        ndjson_truncate=ndjson_truncate,
                                        ndjson_flush_sec=getattr(args,'ndjson_flush_sec',None),
                                        ndjson_buffer=getattr(args,'ndjson_buffer',None),
                                        ndjson_include_raw=bool(getattr(args,'ndjson_include_raw',False)),
                                        per_file_timeout=per_file_timeout,
                                        safe_report=bool(getattr(args,'safe',False)),
                                        min_confidence=min_confidence,
                                        max_size_bytes=max_size_bytes,
                                        only_rules=_configured_only_rules(
                                            cfg,
                                            rule_level,
                                            getattr(args, 'only_rules', None),
                                        ))
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            return 130
        t_end = time.perf_counter()
        elapsed = t_end - t_start
        # Friendly end-of-run summary
        sev_order = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        cC = sum(1 for f in findings if (f.get('severity') or 'Low') == 'Critical')
        cH = sum(1 for f in findings if (f.get('severity') or 'Low') == 'High')
        cM = sum(1 for f in findings if (f.get('severity') or 'Low') == 'Medium')
        cL = sum(1 for f in findings if (f.get('severity') or 'Low') == 'Low')
        fmts = ','.join(formats)
        sens_txt = {1:'L1/cautious',2:'L2/balanced',3:'L3/aggressive'}.get(rule_level or 2, 'L2/balanced')
        mode_txt = f"{'fast' if args.fast else 'standard'} {'safe/redacted' if getattr(args, 'safe', False) else 'raw'}"
        if intent_name == "passwords" and args.verbose:
            print("Intent: passwords | .txt <= 5 MB | rules: " + ", ".join(PASSWORD_INTENT_RULES))
        if console_mode:
            print_console_findings(findings, getattr(args, 'console_limit', 50), bool(getattr(args, 'show_evidence', False)))
            report_txt = 'console + ndjson' if ndjson_out else 'console only'
        else:
            report_txt = f"{args.output_dir} (formats: {fmts})"
        conf_txt = f" | Min confidence: {min_confidence}%" if min_confidence is not None else ""
        print(f"Scanned {len(files)} files | Findings: {len(findings)} (C:{cC} H:{cH} M:{cM} L:{cL}) | Sensitivity: {sens_txt}{conf_txt} | Mode: {mode_txt} | Time: {elapsed:.2f}s | Reports: {report_txt}")
        if not console_mode:
            print_report_links(args.output_dir, formats, timestamp_reports, wall_started_at)
        if ndjson_out:
            print_ndjson_link(ndjson_out)
        return code
    else:
        parser.print_help(); return 0
if __name__=='__main__':
    raise SystemExit(main())
