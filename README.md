# CredAudit

CredAudit is a Python command-line tool for finding exposed credentials, API keys, tokens, private keys, and other secrets in files, folders, archives, and HTTP Archive (`.har`) traffic captures.

It is designed for security reviews, client audits, CI checks, and quick evidence gathering. It reads common document and configuration formats, applies built-in detection rules, redacts sensitive values in most reports, and exports findings in formats that are easy to review or integrate with security tooling.

## Main Features

- Scan a single file or a full directory tree.
- Extract text from plaintext files, JSON, `.env`, DOCX, PDF, XLSX, and HAR captures.
- Optionally scan ZIP, TAR, TGZ, TAR.GZ, and RAR archives.
- Detect common credential types such as private keys, AWS keys, GitHub tokens, Slack tokens, Stripe keys, JWTs, database URLs with embedded passwords, provider API keys, password assignments, and high-entropy strings.
- Choose scan sensitivity with cautious, balanced, and aggressive levels.
- Limit scans by extension, include glob, exclude glob, ignore file, and maximum file size.
- Generate JSON, CSV, HTML, and SARIF reports.
- Stream findings to NDJSON during large scans.
- Reuse cached results for unchanged files to speed up repeated scans.
- Fail a CI job when findings meet a selected severity threshold.

## Requirements

- Python 3.10 or later.
- Supported operating systems: Windows, Kali Linux, other Linux distributions, and macOS.
- Package dependencies are installed automatically from `pyproject.toml`.
- RAR archive scanning may require an external `unrar` or `unar` utility depending on the operating system.

## Installation

### Windows

Install Python 3.10 or later from `python.org` or the Microsoft Store. During installation, enable the option to add Python to `PATH`.

PowerShell or Windows Terminal:

```powershell
python --version
python -m pip install --upgrade pip
python -m pip install .
credaudit --version
```

Command Prompt:

```bat
python --version
python -m pip install --upgrade pip
python -m pip install .
credaudit --version
```

If `credaudit` is not recognized after installation, run it through Python:

```bat
python -m credaudit --version
python -m credaudit C:\path\to\client-data
```

### Kali Linux

Install system prerequisites:

```sh
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

Install CredAudit from this repository:

```sh
cd CredAudit
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
credaudit --version
```

Run a safe fast scan:

```sh
credaudit ./tests/secrets.txt
```

Optional archive support:

```sh
sudo apt install -y unar
```

### Linux and macOS

Install from this repository:

```sh
python -m pip install .
```

For development or local testing:

```sh
python -m pip install -e .
```

After installation, use the `credaudit` command. You can also run it as a module:

```sh
python -m credaudit --version
```

On Windows, PowerShell is not required. You can run CredAudit from PowerShell, Command Prompt, Windows Terminal, or Git Bash as long as Python and the `credaudit` command are available on `PATH`.

## Quick Start

Recommended safe scan for a file:

```sh
credaudit ./tests/secrets.txt
```

Recommended safe scan for a folder:

```sh
credaudit ./project
```

The simple `credaudit PATH` command runs a scan in fast safe/redacted mode. The `credaudit scan PATH` form uses the same safe defaults unless you explicitly choose otherwise. By default CredAudit scans `.txt` files only, skips files larger than 10 KB, uses a 2-second per-file timeout, skips common generated folders, prints redacted findings on the screen, and avoids writing raw secrets into report data or cache.

If you want report files, choose one or more formats explicitly:

```sh
credaudit ./project --formats html csv json
```

Reports are written to `./credaudit_out` when `--formats` is used:

- `report_YYYYMMDD_HHMMSS.html` - interactive browser report.
- `report_YYYYMMDD_HHMMSS.json` - finding data. In safe mode, matches and context are redacted.
- `report_YYYYMMDD_HHMMSS.csv` - redacted tabular report.
- `report_YYYYMMDD_HHMMSS.sarif` - SARIF 2.1.0 when requested.

When report files are created, CredAudit prints clickable `file:///...` URLs in the terminal for each generated format.

Timestamped report filenames are the default when `--formats` is used. Add `--no-timestamp` when you intentionally want fixed filenames such as `report.html`.

Advanced users can still run the full configured scan scope:

```sh
credaudit scan -p ./project --full --safe --formats html json csv
```

Use `--raw` only when exact secret values are required for internal remediation evidence:

```sh
credaudit scan -p ./project --full --raw --formats html json csv
```

## Typical Client Workflow

1. Validate the local configuration:

   ```sh
   credaudit validate
   ```

2. Review available detection rules:

   ```sh
   credaudit rules
   ```

3. Run a dry scan to confirm scope:

   ```sh
   credaudit ./client-data --list
   ```

4. Run the audit and review the redacted CLI results:

   ```sh
   credaudit ./client-data
   ```

5. Export an HTML report when needed:

   ```sh
   credaudit ./client-data --formats html csv json
   ```

6. Open the HTML report using the `HTML: file:///...` URL printed under `Report URLs`.

7. Triage high and medium severity findings first, then use the file path and line number in each report row to remediate the source files.

## Commands

### `credaudit PATH`

Runs a fast, safe, redacted scan with minimal command-line input.

```sh
credaudit ./client-data
```

This is the recommended command for normal client use.

Default behavior for this shortcut:

- Scans `.txt` files only.
- Skips files larger than 10 KB.
- Stops scanning any single file after 2 seconds.
- Skips common generated folders such as `.git`, `.venv`, `node_modules`, `build`, `dist`, and `*.egg-info`.
- Prints redacted findings in the CLI.
- Writes report files only when `--formats` is used.
- Does not write the findings cache.

### `credaudit validate`

Checks that configuration can be loaded and prints active parser settings.

```sh
credaudit validate
```

### `credaudit rules`

Lists built-in detection rules with their names and descriptions.

```sh
credaudit rules
```

Rule names can be used with `--only-rules`.

### `credaudit scan`

Runs the scanner against a file or directory with full control over options.

```sh
credaudit scan ./path-to-scan
```

The path can be positional (`credaudit scan ./project`) or passed with `-p` (`credaudit scan -p ./project`). This command is safe and fast by default. Add `--full` to use the full configured file scope, and add `--raw` only when raw findings are intentionally needed.

### `credaudit convert`

Converts streamed NDJSON findings into HTML or CSV reports without rescanning.

```sh
credaudit convert --in credaudit_out/findings.ndjson --out credaudit_out/final_report --formats html csv
```

This creates `final_report.html` and/or `final_report.csv`.

## Common Usage Examples

Scan one text file:

```sh
credaudit ./notes.txt
```

Detect a username/password pair in a text file:

```text
admin
mISX%%13402
```

Run:

```sh
credaudit ./client-credentials.txt
```

Expected CLI finding style:

```text
High  UsernameNearPassword  1  client-credentials.txt  a****n
Low   PasswordCandidate     2  client-credentials.txt  mI****02
```

`UsernameNearPassword` is a contextual rule. It is reported during a normal scan when a username-like line appears immediately before a detected password or password candidate.

Scan only `.txt` files in a folder:

```sh
credaudit ./client-data --include-ext .txt
```

Scan only `.env` and JSON files:

```sh
credaudit ./project --include-ext .env .json
```

Scan larger text files by raising the default 10 KB limit:

```sh
credaudit ./project --max-size-kb 100
```

Exclude dependency and cache folders:

```sh
credaudit ./project --exclude-glob "**/node_modules/**" --exclude-glob "**/__pycache__/**"
```

Use include globs:

```sh
credaudit ./project --include-glob "**/*.env" --include-glob "**/*.yaml"
```

Use an ignore file:

```sh
credaudit ./project --ignore-file .credauditignore
```

Skip large files:

```sh
credaudit ./project --max-size 10
```

Run a clean safe scan without cache:

```sh
credaudit ./project --no-cache
```

Run the full configured scope:

```sh
credaudit scan ./project --full --safe
```

Fail CI if any high severity finding is present:

```sh
credaudit scan ./src --full --safe --formats sarif json --fail-on High
```

Run only selected rules:

```sh
credaudit ./project --only-rules PasswordAssignment GitHubToken
```

You can also use numeric rule indexes from `credaudit rules`:

```sh
credaudit ./project --only-rules 1 3 5
```

## Scan Options

Important scan flags:

- `-p, --path PATH` - file or directory to scan.
- `-o, --output-dir DIR` - output directory. Default: `./credaudit_out`.
- `--formats json csv html sarif` - one or more final report formats.
- If `--formats` is omitted, findings are printed on screen instead of saved as report files.
- `--safe, --redacted-only` - write redacted-only reports and skip raw-secret cache writes. This is the default.
- `--raw` - allow raw matched values in reports and cache. Use only for internal remediation.
- `--console-limit N` - maximum findings to print on screen when `--formats` is omitted. Default: `50`.
- `--fast` - use fast defaults: `.txt` only, 10 KB max files, 2-second per-file timeout, generated-folder skips, and up to 4 workers. This is the default.
- `--full, --standard` - use the full configured file scope instead of fast defaults.
- `--include-ext EXT [...]` - scan only these extensions.
- `--include-glob PATTERN` - include files matching a glob. Can be repeated.
- `--exclude-glob PATTERN` - exclude files matching a glob. Can be repeated.
- `--ignore-file FILE` - load ignore glob patterns from a file.
- `--max-size MB` - skip files larger than this size.
- `--max-size-kb KB` - skip files larger than this size in KB.
- `--threads N` - threads used for file discovery.
- `--workers N` - worker processes used for scanning.
- `--list` - dry run. Print files that would be scanned.
- `--timestamp` - append a timestamp to report filenames. This is the default when `--formats` is used.
- `--no-timestamp` - use fixed report filenames such as `report.html` and `report.json`.
- `--fail-on Low|Medium|High` - exit with code `2` if findings meet or exceed the threshold.
- `--config PATH` - config file path. Default: `config.yaml`.
- `--entropy-min-length INT` - minimum token length for entropy detection.
- `--entropy-threshold FLOAT` - entropy threshold. Default: `4.0`.
- `--cache-file PATH` - cache file path. Default: `.credaudit_cache.json`.
- `--scan-archives` - scan supported archive files.
- `--archive-depth N` - nested archive depth.
- `--no-cache` - ignore cache and force a full rescan.
- `--verbose` - print scan details and skip reasons.
- `--no-banner` - suppress the ASCII banner.
- `--per-file-timeout SEC` - stop scanning a file after this many seconds. Standard default: `120`; fast default: `2`; use `0` to disable.
- `--only-rules R1 R2 ...` - restrict detection to specific rule names or rule indexes.
- `--sensitivity 1|2|3` - select cautious, balanced, or aggressive detection.
- `--har-include both|responses|requests` - choose which HAR bodies to scan.
- `--har-max-body-bytes N` - maximum HAR request or response body size to scan.
- `--ndjson-out PATH` - stream findings to NDJSON while scanning.
- `--ndjson-truncate` - clear the NDJSON file before writing.
- `--ndjson-flush-sec SEC` - time-based NDJSON flush interval.
- `--ndjson-buffer N` - finding-count NDJSON flush threshold.
- `--ndjson-include-raw` - include raw matched values in NDJSON when `--raw` is also used.

## Sensitivity Levels

Use `--sensitivity` to control how broad the rules should be:

- `1`, `L1`, `low`, or `cautious` - high-confidence rules only. Entropy detection is disabled to reduce noise.
- `2`, `L2`, `medium`, or `balanced` - default. Includes password/API-key assignment rules and entropy detection.
- `3`, `L3`, `high`, or `aggressive` - currently similar to balanced, with entropy enabled.

Example:

```sh
credaudit ./project --sensitivity 1
```

## What CredAudit Scans

The default `credaudit PATH` and `credaudit scan PATH` commands scan `.txt` files only and skip files larger than 10 KB.

The scanner can also scan these extensions when you pass `--full` to use the configured scope, or when you pass `--include-ext` / `--include-glob` explicitly:

```text
.txt, .json, .env, .docx, .pdf, .xlsx, .har
```

The extractor can also read these plaintext-style extensions when they are included by CLI flag or config:

```text
.log, .cfg, .ini, .yaml, .yml, .py, .js, .toml
```

Extraction behavior:

- Plaintext files are read with UTF-8, UTF-16, and Latin-1 fallbacks.
- DOCX files are scanned from paragraph text.
- PDF files are scanned through `pdfminer.six` text extraction.
- XLSX files are scanned from cell values, including simple key/value rows such as `password: value`.
- HAR files are scanned from textual request and response bodies.

## Detection Coverage

CredAudit groups its built-in rules into a few practical categories:

- Private keys - detects exposed PEM private key blocks.
- Cloud and provider credentials - detects common keys and tokens for services such as AWS, GitHub, Slack, Google, SendGrid, GitLab, npm, OpenAI, Telegram, Twilio, Stripe, and Azure.
- Password and secret assignments - detects values written near keywords such as `password`, `secret`, `api_key`, and `token`.
- Credential indicators - detects username/login assignments and lines that mention `password` even when no secret value is present.
- Standalone password candidates - detects values such as `myo@193` and `mISX%%13402` when they look like password strings even without a nearby keyword.
- Credential pairs in text files - detects username-like lines immediately before password findings.
- Database credentials - detects connection strings that include usernames and passwords.
- JWTs - detects JSON Web Tokens with valid token structure.
- High-entropy values - detects long random-looking strings that may be secrets.

Use sensitivity level `1` for a quieter, high-confidence scan. Use the default sensitivity level `2` for normal audits.

Username or login assignments are reported as low severity indicators. Lines that mention `password` without a detected value are also reported as low severity indicators. When a real password value is detected on the same line, CredAudit keeps the stronger password finding instead of showing both.

Standalone password candidates are reported as low severity. A candidate must be a compact token, at least 6 characters long, containing letters, at least one digit, and either a symbol or mixed uppercase/lowercase. Email addresses, URLs, package-like names, placeholders, and normal `key=value` assignments are filtered out before this rule is reported.

If a password finding appears on a line and the line immediately before it looks like a username, CredAudit reports that previous line as `UsernameNearPassword` with high severity. This catches common text-file pairs such as:

```text
admin
mISX%%13402
```

When more than one rule matches the same secret value on the same file and line, CredAudit keeps one finding and prefers the strongest or most specific rule. For example, a value that matches both `PasswordAssignment` and `PasswordAssignmentLoose` is shown once. Common syntax characters at the edge of a value, such as a trailing comma or semicolon, are ignored for this comparison.

Run `credaudit rules` when you need the exact technical rule names available in the installed version.

## HAR Scanning

CredAudit can scan `.har` files exported from tools such as browsers, Burp Suite, or OWASP ZAP when request or response bodies are included in the capture.

Scan both requests and responses:

```sh
credaudit scan traffic.har --full --safe
```

Scan only responses:

```sh
credaudit scan traffic.har --full --safe --har-include responses
```

Limit the maximum body size scanned per HAR entry:

```sh
credaudit scan traffic.har --full --safe --har-max-body-bytes 4194304
```

The same limit can be set with the `CREDAUDIT_HAR_MAX_BODY_BYTES` environment variable.

HAR finding paths use virtual IDs such as:

```text
https://example.test/api/login#response
```

## Archive Scanning

Archive scanning is enabled with `--scan-archives`. Because archive extensions are not in the default include list, include them explicitly when scanning archive files or folders that contain archives.

Example:

```sh
credaudit scan ./artifacts --safe --scan-archives --archive-depth 2 --include-ext .zip .tar .tgz .gz .rar --max-size 100
```

For `.tar.gz` specifically, use `--include-ext .gz` or an include glob such as `--include-glob "**/*.tar.gz"`.

Supported archive formats:

- `.zip`
- `.tar`
- `.tgz`
- `.tar.gz`
- `.rar`

Archive extraction is performed in a temporary directory with path traversal protection. Findings from archives are reported with paths like:

```text
archive.zip!inner/folder/file.env
```

## Output Formats

### HTML

The HTML report is an interactive dashboard for review and triage. It includes:

- Severity counts.
- Search and filtering.
- Rule and file type filters.
- Sortable table columns.
- Redacted values by default.
- Optional raw-value reveal in raw mode only.
- Links to JSON and CSV when those formats are generated in the same run.

Recommended command:

```sh
credaudit ./project --formats html csv json
```

The HTML report embeds a limited number of rows for browser performance. The default is `500`. Adjust this with:

```sh
CREDAUDIT_HTML_MAX_ROWS=1000 credaudit ./project --formats html csv json
```

On Windows PowerShell:

```powershell
$env:CREDAUDIT_HTML_MAX_ROWS = "1000"
credaudit . --formats html csv json
```

On Windows Command Prompt:

```bat
set CREDAUDIT_HTML_MAX_ROWS=1000
credaudit . --formats html csv json
```

### JSON

By default, JSON contains redacted finding records. When `--raw` is used, JSON includes the raw `match` value and should be treated as sensitive audit evidence.

Each finding includes:

- `file`
- `rule`
- `match`
- `redacted`
- `context`
- `severity`
- `line`

### CSV

CSV is intended for safer sharing and spreadsheet review. It contains redacted values and redacted context snippets.

Columns:

```text
file, rule, redacted, severity, line, context
```

### SARIF

SARIF 2.1.0 is useful for code scanning platforms and CI integrations.

```sh
credaudit scan ./src --full --safe --formats sarif --fail-on High
```

### NDJSON Streaming

NDJSON is useful for very large scans because findings are written while the scan is still running.

```sh
credaudit ./large-share --ndjson-out credaudit_out/findings.ndjson
```

Use `--ndjson-truncate` to start with a clean file:

```sh
credaudit ./large-share --ndjson-out credaudit_out/findings.ndjson --ndjson-truncate
```

By default, NDJSON contains redacted values and redacted context. Include raw matches only when required in raw mode:

```sh
credaudit scan -p ./project --full --raw --ndjson-out credaudit_out/findings.ndjson --ndjson-include-raw
```

Safe mode ignores `--ndjson-include-raw`.

Convert streamed findings later:

```sh
credaudit convert --in credaudit_out/findings.ndjson --out credaudit_out/full_report --formats html csv
```

Use `--safe` during conversion if the NDJSON file contains raw matches:

```sh
credaudit convert --in credaudit_out/findings.ndjson --out credaudit_out/full_report --formats html csv --safe
```

## Configuration

CredAudit loads `config.yaml` from the working directory by default. CLI flags override config values for the current run.

Note: the default safe command path applies fast defaults over the config file unless you pass explicit options such as `--full`, `--include-ext`, `--include-glob`, `--max-size-kb`, or `--per-file-timeout`.

Example:

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

Use `--config` to load a different file:

```sh
credaudit ./project --config ./client-config.yaml
```

## Caching and Performance

CredAudit avoids writing a findings cache in safe mode so raw matches are not stored locally by accident. When `--raw` is used, CredAudit can store file size, modification time, and findings in `.credaudit_cache.json` to speed up repeated internal scans.

- The default command path uses fast mode: `.txt` only, 10 KB max files, a 2-second per-file timeout, generated-folder skips, and up to 4 workers.
- In raw mode, unchanged files reuse cached findings.
- In raw mode, changed files are scanned again.
- Use `--no-cache` when a clean scan is required.
- Safe mode skips cache reads and writes to avoid storing raw matches locally.
- Use `--workers` to control scanning process count.
- Use `--threads` to control file discovery concurrency.
- Use `--per-file-timeout` to prevent a single slow or corrupt file from stalling a run.
- Use `--max-size-kb` to raise or lower the fast-mode file size limit.

Example for a large share:

```sh
credaudit /mnt/share --include-ext .txt .json .env .yaml --max-size 10 --sensitivity 1 --threads 32 --workers 8 --ndjson-out credaudit_out/findings.ndjson --no-banner
```

## Exit Codes

- `0` - scan completed and the `--fail-on` threshold was not met.
- `2` - one or more findings met or exceeded the `--fail-on` severity threshold.

Example:

```sh
credaudit scan ./src --full --safe --formats sarif json --fail-on Medium
```

## Security Notes

- For client-facing use, prefer the default safe command: `credaudit PATH`.
- Safe mode redacts matches and context snippets in generated reports.
- Values are redacted with a four-star middle mask, such as `se****23`, while keeping enough context for review.
- Safe mode skips cache reads and writes to avoid storing raw matches in `.credaudit_cache.json`.
- Raw mode can write raw matched secrets to JSON and HTML report data.
- CSV contains redacted values and redacted context snippets.
- NDJSON is redacted by default, but `--raw --ndjson-include-raw` writes raw matches.
- Remediate exposed credentials by rotating or revoking them, not only by removing them from files.

## Version

Current package version: `0.5.0`.

Print the installed version:

```sh
credaudit --version
```

## License

MIT. See `LICENSE` for details.
