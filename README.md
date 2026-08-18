# CredAudit

CredAudit is a Python command-line tool for finding exposed credentials, API keys,
tokens, private keys, database passwords, and password-like values in local files.

It is built for security reviews, client audits, evidence triage, and CI checks.
The safest way to use it is redacted-first: scan locally, avoid storing raw
secrets by default, and export shareable reports only when needed.

## Best Default Workflow

Use this for most first-pass audits:

```sh
credaudit ./client-data
```

That command uses safe fast defaults:

- Redacts findings in console output.
- Streams redacted findings to `credaudit_out/findings.ndjson`.
- Scans directory targets as small `.txt` files only, up to 10 KB each.
- Scans explicit file targets directly, regardless of extension.
- Uses a 2 second per-file timeout.
- Skips common generated folders such as `.git`, `.venv`, `node_modules`,
  `build`, `dist`, and `credaudit_out`.
- Does not write a raw findings cache.

When you need a browser report:

```sh
credaudit ./client-data --formats html csv json
```

Open the `HTML: file:///...` link printed at the end of the scan.

Use `--raw` only for internal remediation evidence where exact secret values are
required:

```sh
credaudit ./client-data --full --raw --formats html json
```

Raw mode can write secret values into JSON, HTML data, and the cache. Treat those
outputs as sensitive.

## Installation

CredAudit requires Python 3.10 or newer.

From this repository:

```sh
python -m pip install --upgrade pip
python -m pip install -e .
credaudit --version
credaudit examples
```

If the `credaudit` command is not on `PATH`, run it as a module:

```sh
python -m credaudit --version
python -m credaudit examples
python -m credaudit ./client-data
```

On Kali or Debian/Ubuntu:

```sh
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

RAR archive scanning may require an external `unrar` or `unar` utility.

## Python Engine API

CredAudit can also be embedded in another Python application. Install the
package, then call the stable public API:

```python
from credaudit import scan

result = scan("./project", mode="fast", min_confidence=70)

for finding in result.findings:
    print(finding["file"], finding["severity"], finding["rule"])
```

`result.findings` is redacted by default. Use `result.counts` for severity
totals and `result.files_scanned` for the number of selected files. Supported
scan modes are `fast` and `full`.

## First Audit Checklist

1. Validate configuration:

   ```sh
   credaudit validate
   ```

2. Review available rules:

   ```sh
   credaudit rules
   ```

3. Preview scope before scanning a large folder:

   ```sh
   credaudit ./client-data --list
   ```

4. Run the default safe scan:

   ```sh
   credaudit ./client-data
   ```

5. Generate reports when findings need review or sharing:

   ```sh
   credaudit ./client-data --formats html csv json
   ```

6. Remediate by rotating or revoking exposed credentials. Removing them from
   files is not enough once they have been exposed.

## Commands

### `credaudit PATH`

Shortcut for a safe fast scan. This is the recommended normal command.

```sh
credaudit ./client-data
credaudit ./client-data --formats html csv json
```

### `credaudit scan`

Full scan command with all options. The path can be positional or passed with
`-p`.

```sh
credaudit scan ./client-data
credaudit scan -p ./client-data --full --safe --formats html csv json
```

### `credaudit passwords`

Password-focused shortcut for small `.txt` evidence dumps. It scans `.txt` files
up to 5 MB and focuses on password-shaped values, `username:password` pairs, and
nearby username/password lines.

```sh
credaudit passwords ./client-data
credaudit passwords ./client-data --min-confidence 80 --show-evidence
```

### `credaudit convert`

Convert streamed NDJSON findings into reports without rescanning.

```sh
credaudit convert --in credaudit_out/findings.ndjson --out credaudit_out/final_report --formats html csv
```

### `credaudit validate`

Load configuration and print active parser settings.

```sh
credaudit validate
```

### `credaudit rules`

Print rule indexes, names, and descriptions.

```sh
credaudit rules
```

Rule names or indexes can be passed to `--only-rules`.

### `credaudit examples`

Print copy-paste commands for the safest common workflows after installation.

```sh
credaudit examples
```

## Practical Recipes

Scan one file:

```sh
credaudit ./secrets.txt
credaudit ./client-credentials.xlsx
```

Scan common plaintext configuration files:

```sh
credaudit ./project --include-ext .txt .json .env .yaml .yml .log .cfg .ini --max-size 10 --formats html csv json
```

Scan Office, PDF, and HAR evidence separately with longer timeouts:

```sh
credaudit ./evidence --include-ext .docx .pdf .xlsx .har --max-size 5 --per-file-timeout 30 --workers 2 --formats html csv json --verbose
```

Run the full configured scan scope:

```sh
credaudit scan ./project --full --safe --formats html csv json
```

Run a quieter, high-confidence scan:

```sh
credaudit ./project --sensitivity 1 --high-confidence
```

Scan only selected rules:

```sh
credaudit ./project --only-rules PasswordValueAssignment CredentialPair
credaudit ./project --only-rules 7 13
```

Scan ZIP, TAR, TGZ, TAR.GZ, or RAR archives:

```sh
credaudit scan ./artifacts --scan-archives --archive-depth 2 --include-ext .zip .tar .tgz .gz .rar --max-size 100 --formats html csv json
```

Scan HAR response bodies only:

```sh
credaudit scan traffic.har --har-include responses --formats html json
```

Fail CI on high or critical findings:

```sh
credaudit scan ./src --full --safe --formats sarif json --fail-on High
```

For very large shares, stream first and convert later:

```sh
credaudit ./large-share --include-ext .txt .json .env .yaml .yml .log .cfg .ini --max-size 10 --sensitivity 1 --threads 32 --workers 8 --per-file-timeout 10 --ndjson-out credaudit_out/large_findings.ndjson --ndjson-truncate --no-banner
credaudit convert --in credaudit_out/large_findings.ndjson --out credaudit_out/large_report --formats html csv
```

## What CredAudit Detects

CredAudit includes built-in rules for:

- Private keys.
- AWS access keys and secret access key assignments.
- GitHub, GitLab, Slack, SendGrid, npm, OpenAI, Telegram, Twilio, Stripe, Google,
  and Azure token formats.
- Password, secret, token, and API key assignments.
- Password-only assignments such as `password: value`, `passwd=value`, and
  `pwd: value`.
- Same-line `username:password` pairs.
- Username-like lines immediately before password-like lines.
- Database connection strings with embedded passwords.
- JWTs with valid token structure.
- High-entropy strings.
- Low-severity indicators such as username assignments or password keywords.

Use `credaudit rules` for the exact rule list in the installed version.

## File Types

The extractor can read:

- Text-like files: `.txt`, `.json`, `.env`, `.log`, `.cfg`, `.ini`, `.yaml`,
  `.yml`, `.py`, `.js`, `.toml`
- Documents: `.docx`, `.pdf`, `.xlsx`
- HTTP archives: `.har`
- Archives when enabled: `.zip`, `.tar`, `.tgz`, `.tar.gz`, `.rar`

Important default: directory scans use the fast safe scope unless you widen it
with `--full`, `--include-ext`, or `--include-glob`.

## Output Files

By default, scans stream redacted NDJSON to:

```text
credaudit_out/findings.ndjson
```

When `--formats` is used, reports are timestamped by default:

```text
credaudit_out/report_YYYYMMDD_HHMMSS.html
credaudit_out/report_YYYYMMDD_HHMMSS.csv
credaudit_out/report_YYYYMMDD_HHMMSS.json
credaudit_out/report_YYYYMMDD_HHMMSS.sarif
credaudit_out/findings_YYYYMMDD_HHMMSS.ndjson
```

Use fixed report names when needed:

```sh
credaudit ./project --formats html csv json --no-timestamp
```

Output format notes:

- HTML is best for human review, filtering, and triage.
- CSV is redacted and useful for spreadsheets.
- JSON is redacted in safe mode and raw in raw mode.
- SARIF is useful for CI and code scanning platforms.
- NDJSON is written as findings are discovered, which is useful for large scans.

See [docs/SCHEMA.md](docs/SCHEMA.md) for output fields.

## Key Options

File selection:

```sh
--include-ext .txt .env .json
--include-glob "**/*.env"
--exclude-glob "**/node_modules/**"
--ignore-file .credauditignore
--max-size 10
--max-size-kb 100
```

Safety and output:

```sh
--safe
--raw
--formats html csv json sarif
--no-ndjson
--ndjson-out credaudit_out/findings.ndjson
--console-limit 100
```

Detection tuning:

```sh
--sensitivity 1
--sensitivity 2
--sensitivity 3
--high-confidence
--min-confidence 80
--show-evidence
--only-rules PasswordValueAssignment CredentialPair
```

Performance:

```sh
--threads 16
--workers 4
--per-file-timeout 10
--no-cache
--verbose
```

CI:

```sh
--fail-on Low
--fail-on Medium
--fail-on High
--fail-on Critical
```

## Sensitivity, Confidence, And Severity

Sensitivity controls which rules run:

- `--sensitivity 1` or `cautious`: high-confidence rules, entropy disabled.
- `--sensitivity 2` or `balanced`: default rule set, entropy enabled.
- `--sensitivity 3` or `aggressive`: currently similar to balanced.

Every finding has a confidence score from `0` to `100`, evidence reasons, a
finding class, and severity. Severity is based on confidence:

- `Critical`: 95+
- `High`: 80-94
- `Medium`: 50-79
- `Low`: below 50

For cleaner reports:

```sh
credaudit ./client-data --min-confidence 80 --formats html csv
```

## Configuration

CredAudit loads `config.yaml` from the current working directory unless
`--config` is provided.

Minimal example:

```yaml
include_ext: [".txt", ".json", ".env", ".docx", ".pdf", ".xlsx", ".har"]
include_glob: []
exclude_glob: ["**/.git/**", "**/__pycache__/**", "**/node_modules/**"]
workers: null
threads: 8
entropy_min_length: 20
entropy_threshold: 4.0
cache_file: ".credaudit_cache.json"
```

CLI flags override configuration for the current run:

```sh
credaudit ./project --config ./client-config.yaml --include-ext .env .json
```

## Security Guidance

- Prefer `credaudit PATH` or `--safe` for client-facing work.
- Keep `--raw` reports private and delete them when they are no longer needed.
- Do not upload raw reports to ticketing systems, chat, or shared drives unless
  your process explicitly allows it.
- Rotate or revoke exposed credentials after discovery.
- Use `--no-cache` when you need a fresh scan or want to avoid cache reuse.
- Safe mode skips raw cache writes.

## Troubleshooting

`credaudit` is not recognized:

```sh
python -m credaudit --version
python -m pip install -e .
```

No findings were reported:

```sh
credaudit ./client-data --list
credaudit ./client-data --include-ext .txt .json .env .yaml .yml --max-size 10
```

A scan is too slow:

```sh
credaudit ./client-data --include-ext .txt .env .json --max-size 10 --per-file-timeout 10 --workers 4
```

A workbook, PDF, or HAR is slow or unreadable:

```sh
credaudit ./specific-file.xlsx --per-file-timeout 30 --verbose --formats html json
```

Need fewer false positives:

```sh
credaudit ./client-data --sensitivity 1 --high-confidence
```

Need more coverage:

```sh
credaudit ./client-data --full --include-ext .txt .json .env .yaml .yml .docx .pdf .xlsx .har --max-size 20
```

## Development

Run the standard-library tests:

```sh
python -m unittest discover -s tests -p "test*.py" -v
python -m unittest discover -s tests/e2e -p "test*.py" -v
```

Run the CLI locally:

```sh
python -m credaudit --version
python -m credaudit ./tests/secrets.txt
```

Package metadata lives in `pyproject.toml`. The current package version is
`0.6.3`.

## License

MIT. See [LICENSE](LICENSE).
