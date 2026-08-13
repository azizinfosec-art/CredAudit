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
- Supported operating systems: Windows, Linux, and macOS. Kali Linux is supported, but it is not required.
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
python -m credaudit scan -p C:\path\to\client-data --formats html json csv
```

### Linux, Kali Linux, and macOS

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

Scan a file and create the default reports:

```sh
credaudit scan -p ./tests/secrets.txt
```

Scan a folder and create HTML, JSON, and CSV reports:

```sh
credaudit scan -p ./project --formats html json csv
```

Reports are written to `./credaudit_out` by default:

- `report.html` - interactive browser report.
- `report.json` - full finding data, including raw matches.
- `report.csv` - redacted tabular report.
- `report.sarif` - SARIF 2.1.0 when requested.

Use `--timestamp` when you want report files such as `report_YYYYMMDD_HHMMSS.html` instead of overwriting `report.html`.

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
   credaudit scan -p ./client-data --list
   ```

4. Run the audit and export reports:

   ```sh
   credaudit scan -p ./client-data --formats html json csv --timestamp
   ```

5. Open the HTML report:

   Windows PowerShell:

   ```powershell
   start credaudit_out\report.html
   ```

   Windows Command Prompt:

   ```bat
   start credaudit_out\report.html
   ```

   Linux or macOS:

   ```sh
   xdg-open credaudit_out/report.html 2>/dev/null || open credaudit_out/report.html
   ```

6. Triage high and medium severity findings first, then use the file path and line number in each report row to remediate the source files.

## Commands

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

Runs the scanner against a file or directory.

```sh
credaudit scan -p ./path-to-scan --formats html json csv
```

### `credaudit convert`

Converts streamed NDJSON findings into HTML or CSV reports without rescanning.

```sh
credaudit convert --in credaudit_out/findings.ndjson --out credaudit_out/final_report --formats html csv
```

This creates `final_report.html` and/or `final_report.csv`.

## Common Usage Examples

Scan one text file:

```sh
credaudit scan -p ./notes.txt --formats html json csv
```

Scan only `.txt` files in a folder:

```sh
credaudit scan -p ./client-data --include-ext .txt --formats html json csv
```

Scan only `.env` and JSON files:

```sh
credaudit scan -p ./project --include-ext .env .json --formats html csv
```

Exclude dependency and cache folders:

```sh
credaudit scan -p ./project --exclude-glob "**/node_modules/**" --exclude-glob "**/__pycache__/**"
```

Use include globs:

```sh
credaudit scan -p ./project --include-glob "**/*.env" --include-glob "**/*.yaml"
```

Use an ignore file:

```sh
credaudit scan -p ./project --ignore-file .credauditignore
```

Skip large files:

```sh
credaudit scan -p ./project --max-size 10
```

Run a full rescan without cache:

```sh
credaudit scan -p ./project --no-cache
```

Fail CI if any high severity finding is present:

```sh
credaudit scan -p ./src --formats sarif json --fail-on High
```

Run only selected rules:

```sh
credaudit scan -p ./project --only-rules PasswordAssignment GitHubToken
```

You can also use numeric rule indexes from `credaudit rules`:

```sh
credaudit scan -p ./project --only-rules 1 3 5
```

## Scan Options

Important scan flags:

- `-p, --path PATH` - file or directory to scan.
- `-o, --output-dir DIR` - output directory. Default: `./credaudit_out`.
- `--formats json csv html sarif` - one or more final report formats.
- `--include-ext EXT [...]` - scan only these extensions.
- `--include-glob PATTERN` - include files matching a glob. Can be repeated.
- `--exclude-glob PATTERN` - exclude files matching a glob. Can be repeated.
- `--ignore-file FILE` - load ignore glob patterns from a file.
- `--max-size MB` - skip files larger than this size.
- `--threads N` - threads used for file discovery.
- `--workers N` - worker processes used for scanning.
- `--list` - dry run. Print files that would be scanned.
- `--timestamp` - append a timestamp to report filenames.
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
- `--per-file-timeout SEC` - stop scanning a file after this many seconds. Default: `120`; use `0` to disable.
- `--only-rules R1 R2 ...` - restrict detection to specific rule names or rule indexes.
- `--sensitivity 1|2|3` - select cautious, balanced, or aggressive detection.
- `--har-include both|responses|requests` - choose which HAR bodies to scan.
- `--har-max-body-bytes N` - maximum HAR request or response body size to scan.
- `--ndjson-out PATH` - stream findings to NDJSON while scanning.
- `--ndjson-truncate` - clear the NDJSON file before writing.
- `--ndjson-flush-sec SEC` - time-based NDJSON flush interval.
- `--ndjson-buffer N` - finding-count NDJSON flush threshold.
- `--ndjson-include-raw` - include raw matched values in NDJSON.

## Sensitivity Levels

Use `--sensitivity` to control how broad the rules should be:

- `1`, `L1`, `low`, or `cautious` - high-confidence rules only. Entropy detection is disabled to reduce noise.
- `2`, `L2`, `medium`, or `balanced` - default. Includes password/API-key assignment rules and entropy detection.
- `3`, `L3`, `high`, or `aggressive` - currently similar to balanced, with entropy enabled.

Example:

```sh
credaudit scan -p ./project --sensitivity 1 --formats html csv
```

## What CredAudit Scans

Default included extensions from `config.yaml`:

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

Built-in rules include:

- PEM private keys.
- AWS Access Key IDs.
- AWS Secret Access Keys in contextual assignments.
- GitHub tokens.
- JWTs with valid JSON header and payload structure.
- Password, secret, API key, and token assignments.
- Slack webhook URLs and Slack tokens.
- Google API keys.
- SendGrid API keys.
- GitLab personal access tokens.
- npm tokens.
- OpenAI API keys.
- Telegram bot tokens.
- Twilio Account SID and contextual Twilio auth tokens.
- Stripe secret keys.
- Azure Storage SAS URLs with signatures.
- Database connection strings with embedded passwords.
- High-entropy strings.

Run `credaudit rules` for the exact rule names available in the installed version.

## HAR Scanning

CredAudit can scan `.har` files exported from tools such as browsers, Burp Suite, or OWASP ZAP when request or response bodies are included in the capture.

Scan both requests and responses:

```sh
credaudit scan -p traffic.har --formats html json csv
```

Scan only responses:

```sh
credaudit scan -p traffic.har --har-include responses --formats html
```

Limit the maximum body size scanned per HAR entry:

```sh
credaudit scan -p traffic.har --har-max-body-bytes 4194304
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
credaudit scan -p ./artifacts --scan-archives --archive-depth 2 --include-ext .zip .tar .tgz .gz .rar --formats html json
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
- Optional raw-value reveal in the browser.
- Links to JSON and CSV when those formats are generated in the same run.

Recommended command:

```sh
credaudit scan -p ./project --formats html json csv
```

The HTML report embeds a limited number of rows for browser performance. The default is `500`. Adjust this with:

```sh
CREDAUDIT_HTML_MAX_ROWS=1000 credaudit scan -p ./project --formats html json csv
```

On Windows PowerShell:

```powershell
$env:CREDAUDIT_HTML_MAX_ROWS = "1000"
credaudit scan -p . --formats html json csv
```

On Windows Command Prompt:

```bat
set CREDAUDIT_HTML_MAX_ROWS=1000
credaudit scan -p . --formats html json csv
```

### JSON

JSON contains full finding records and includes the raw `match` value. Treat JSON output as sensitive audit evidence.

Each finding includes:

- `file`
- `rule`
- `match`
- `redacted`
- `context`
- `severity`
- `line`

### CSV

CSV is intended for safer sharing and spreadsheet review. It contains redacted values only.

Columns:

```text
file, rule, redacted, severity, line, context
```

### SARIF

SARIF 2.1.0 is useful for code scanning platforms and CI integrations.

```sh
credaudit scan -p ./src --formats sarif --fail-on High
```

### NDJSON Streaming

NDJSON is useful for very large scans because findings are written while the scan is still running.

```sh
credaudit scan -p ./large-share --ndjson-out credaudit_out/findings.ndjson --formats html
```

Use `--ndjson-truncate` to start with a clean file:

```sh
credaudit scan -p ./large-share --ndjson-out credaudit_out/findings.ndjson --ndjson-truncate
```

By default, NDJSON contains redacted values only. Include raw matches only when required:

```sh
credaudit scan -p ./project --ndjson-out credaudit_out/findings.ndjson --ndjson-include-raw
```

Convert streamed findings later:

```sh
credaudit convert --in credaudit_out/findings.ndjson --out credaudit_out/full_report --formats html csv
```

## Configuration

CredAudit loads `config.yaml` from the working directory by default. CLI flags override config values for the current run.

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
credaudit scan -p ./project --config ./client-config.yaml
```

## Caching and Performance

CredAudit stores file size, modification time, and findings in `.credaudit_cache.json` by default.

- Unchanged files reuse cached findings.
- Changed files are scanned again.
- Use `--no-cache` when a clean scan is required.
- Use `--workers` to control scanning process count.
- Use `--threads` to control file discovery concurrency.
- Use `--per-file-timeout` to prevent a single slow or corrupt file from stalling a run.

Example for a large share:

```sh
credaudit scan -p /mnt/share --include-ext .txt .json .env .yaml --max-size 10 --sensitivity 1 --threads 32 --workers 8 --ndjson-out credaudit_out/findings.ndjson --formats html csv --timestamp --no-banner
```

## Exit Codes

- `0` - scan completed and the `--fail-on` threshold was not met.
- `2` - one or more findings met or exceeded the `--fail-on` severity threshold.

Example:

```sh
credaudit scan -p ./src --formats sarif json --fail-on Medium
```

## Security Notes

- Treat all report outputs as sensitive unless reviewed and sanitized.
- JSON includes raw matched secrets.
- HTML can reveal raw values in the browser because the report embeds finding data.
- CSV contains redacted values only.
- NDJSON is redacted by default, but `--ndjson-include-raw` writes raw matches.
- Remediate exposed credentials by rotating or revoking them, not only by removing them from files.

## Version

Current package version: `0.4.0`.

Print the installed version:

```sh
credaudit --version
```

## License

MIT. See `LICENSE` for details.
