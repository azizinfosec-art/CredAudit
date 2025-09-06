# CredAudit

Fast, resilient secret scanner for files, folders, and HTTP traffic captures (HAR). Supports text, DOCX, PDF, XLSX, and HAR with multiple report formats.

## What's New (v0.3.13)

- Provider-specific detections (enabled at Sensitivity L2/L3): Google API key, Slack tokens, SendGrid API key, GitLab PAT, npm token, OpenAI key, Telegram bot token, Twilio Account SID/Auth token. L1 remains cautious.

## What's New (v0.3.12)

- HAR support: scan .har files exported with content (Burp/ZAP/DevTools)
  - Options: --har-include {both,responses,requests}
  - Options: --har-max-body-bytes N (bytes) or env CREDAUDIT_HAR_MAX_BODY_BYTES
- HTML report: server-rendered rows so data shows without JavaScript; env CREDAUDIT_HTML_MAX_ROWS controls embedded rows (default 500)
- CLI help: Environment section includes CREDAUDIT_HTML_MAX_ROWS; Scan help includes HAR options
 - Sensitivity levels: --sensitivity {1,2,3} to choose cautious/balanced/aggressive rule sets
 - CLI UX: interactive spinner progress (TTY) and end-of-run summary with elapsed time

## Installation

- Requirements: Python 3.9+
- Local install (from this repo):
  - `python -m pip install .`
  - or dev mode: `python -m pip install -e .`

This installs the console command `credaudit`. You can also run via `python -m credaudit`.

## Quickstart

Scan a file or directory and produce JSON/CSV/HTML reports:

```sh
credaudit scan -p ./tests/secrets.txt --formats json csv html
# or
python -m credaudit scan -p ./tests/secrets.txt --formats json csv html
```

Outputs are written to `./credaudit_out` by default. The banner shows only on interactive terminals; use `--no-banner` to silence it.

## Linux (Install & Use)

Install (user environment)

```sh
# 1) Ensure Python 3.9+ is available
python3 --version

# 2) Create and activate a virtualenv (recommended)
python3 -m venv .venv
. .venv/bin/activate

# 3) Install CredAudit from this repo
python -m pip install --upgrade pip
python -m pip install -e .

# 4) (Optional) Utilities for archive scanning
# RAR support: install unrar/unar if you plan to use --scan-archives
# Debian/Ubuntu: sudo apt-get install unrar
# macOS (Homebrew): brew install unar
```

Run scans

```sh
# Scan a folder and produce HTML/JSON/CSV
credaudit scan -p . --formats html json csv

# Scan a HAR capture (responses + requests)
credaudit scan -p traffic.har --formats html

# Open the HTML report
xdg-open credaudit_out/report.html 2>/dev/null || true
```

## macOS (Install & Use)

Install (Terminal)

```sh
# 1) Ensure Python 3.9+ is available
python3 --version

# 2) Create and activate a virtualenv (recommended)
python3 -m venv .venv
source .venv/bin/activate

# 3) Install CredAudit from this repo
python -m pip install --upgrade pip
python -m pip install -e .

# 4) (Optional) Utilities for archive scanning
# For RAR support (if using --scan-archives):
brew install unar
```

Run scans

```sh
# Scan a folder and produce HTML/JSON/CSV
credaudit scan -p . --formats html json csv

# Scan a HAR capture (responses + requests)
credaudit scan -p traffic.har --formats html

# Open the HTML report
open credaudit_out/report.html
```

## Windows (Install & Use)

Install (PowerShell)

```powershell
# 1) Ensure Python 3.9+ is installed (Microsoft Store or python.org)
py --version

# 2) Create and activate a virtualenv (recommended)
py -m venv .venv
. .venv\Scripts\Activate.ps1

# 3) Install CredAudit from this repo
py -m pip install --upgrade pip
py -m pip install -e .
```

Run scans

```powershell
# Scan a folder and produce HTML/JSON/CSV
credaudit scan -p . --formats html json csv

# Scan a HAR capture (responses + requests)
credaudit scan -p traffic.har --formats html

# Open the HTML report
start credaudit_out\report.html
```

## Commands

- `credaudit validate` â€” Validate config and show enabled parsers.
- `credaudit rules` â€” List builtâ€‘in detection rules.
- `credaudit scan` â€” Run a scan on files/folders.

## Scan Options

- `-p, --path PATH` â€” File or directory to scan.
- `-o, --output-dir DIR` â€” Output directory (default: `./credaudit_out`).
- `--formats FMT [...]` â€” Any of: `json`, `csv`, `html`, `sarif`.
- `--include-ext EXT [...]` â€” Limit by extensions (e.g. `.env .json`).
- `--include-glob PATTERN [...]` â€” Include files by glob (repeatable).
- `--exclude-glob PATTERN [...]` â€” Exclude files by glob (repeatable).
- `--ignore-file FILE` â€” Glob patterns file (like `.credauditignore`).
- `--max-size MB` â€” Skip files larger than this size.
- `--threads N` â€” Threads for file discovery.
- `--workers N` â€” Processes for scanning.
- `--list` â€” Dry-run: only list files that would be scanned.
- `--timestamp` â€” Append a timestamp to report filenames.
- `--fail-on {Low,Medium,High}` â€” Exit nonâ€‘zero if any finding â‰¥ threshold.
- `--config PATH` â€” Path to `config.yaml` (default: `config.yaml`).
- `--entropy-min-length INT` â€” Min token length for entropy rule (default: 20).
- `--entropy-threshold FLOAT` â€” Entropy threshold (default: 4.0).
- `--cache-file PATH` â€” Cache file (default: `.credaudit_cache.json`).
- `--scan-archives` â€” (Placeholder) Flag for archive scanning.
- `--archive-depth N` â€” Depth for nested archives.
- `--no-cache` â€” Ignore cache; force full rescan.
- `--verbose` â€” Verbose logging.
- `--no-banner` â€” Suppress ASCII banner output.

## Examples

- Dry run to see what would be scanned:
  ```sh
  credaudit scan -p . --list
  ```

- Include only `.env` files while excluding dependencies:
  ```sh
  credaudit scan -p . --include-ext .env --exclude-glob "**/node_modules/**" --exclude-glob "**/__pycache__/**"
  ```

- Use globs instead of extensions:
  ```sh
  credaudit scan -p . --include-glob "**/*.env" --include-glob "**/*.json"
  ```

- Stricter entropy to reduce noise:
  ```sh
  credaudit scan -p . --entropy-min-length 24 --entropy-threshold 4.5
  ```

- Fail CI if High severity found and timestamp reports:
  ```sh
  credaudit scan -p ./src --formats sarif json --fail-on High --timestamp
  ```

### HAR Options

- `--har-include {both,responses,requests}`: what to scan inside .har (default: both)
- `--har-max-body-bytes N`: max size per HAR body in bytes (default 2097152; env CREDAUDIT_HAR_MAX_BODY_BYTES)

### All Scan Flags (complete)

- `-p, --path PATH`: File or directory to scan
- `-o, --output-dir DIR`: Output directory (default: `./credaudit_out`)
- `--formats {json,csv,html,sarif} [...]`: One or more output formats
- `--include-ext EXT [...]`: Only scan these extensions (e.g., `.env .json`)
- `--include-glob PATTERN` (repeatable): Include files matching glob(s)
- `--exclude-glob PATTERN` (repeatable): Exclude files matching glob(s)
- `--ignore-file FILE`: Path to ignore patterns file (like `.credauditignore`)
- `--max-size MB`: Skip files larger than MB
- `--threads N`: Threads for file discovery
- `--workers N`: Processes for scanning
- `--list`: Dry-run â€” only list files to be scanned
- `--timestamp`: Append timestamp to report filenames
- `--fail-on {Low,Medium,High}`: Exit non-zero if any finding â‰¥ threshold
- `--config PATH`: Path to `config.yaml` (default: `config.yaml`)
- `--entropy-min-length INT`: Min token length for entropy rule (default: 20)
- `--entropy-threshold FLOAT`: Entropy threshold (default: 4.0)
- `--cache-file PATH`: Cache file name/path (default: `.credaudit_cache.json`)
- `--scan-archives`: Scan inside ZIP/TAR/RAR archives (optional)
- `--archive-depth N`: How deep to unpack nested archives
- `--no-cache`: Force full rescan (ignore cache)
- `--verbose`: Verbose logging with skip reasons
- `--no-banner`: Suppress ASCII banner output
- `--har-include {both,responses,requests}`: What bodies to scan in `.har`
- `--har-max-body-bytes N`: Max size per HAR body (bytes); env `CREDAUDIT_HAR_MAX_BODY_BYTES`
- `--sensitivity {1,2,3}`: Rule sensitivity (1=cautious, 2=balanced, 3=aggressive)

### Sensitivity

- `--sensitivity {1,2,3}` â€” Rule sensitivity level:
  - `1` (cautious): high-confidence rules only; entropy-based detection disabled
  - `2` (balanced, default): includes password/API key assignment rules + entropy
  - `3` (aggressive): same as 2 (entropy enabled). Future versions may add more generic patterns here.
  - Aliases: `L1/L2/L3`, `low/medium/high`.

### Progress & Summary

- Minimal spinner shows during scanning in interactive terminals (TTY). Suppressed with `--verbose`.
- Verbose mode prints a one-line tip instead of the spinner.
- End-of-run summary includes severity counts and elapsed time, for example:
  `Scanned 124 files | Findings: 38 (H:2 M:11 L:25) | Time: 7.42s | Reports: credaudit_out (formats: html,json,csv)`

## Output Formats

- `json` â€” Full findings (includes raw `match` and `redacted`).
- `csv` â€” Columns: `file, rule, redacted, severity, line, context`.
- `html` â€” Singleâ€‘page, sortable summary with severity coloring.
- `sarif` â€” SARIF 2.1.0 for code scanning integrations.

Notes:
- JSON includes the raw matched value (`match`) for completeness. Handle with care.
- The HTML displays a limited, lightweight view (default max 500 rows) to keep browsers responsive.
- Use the â€œFull CSVâ€ and â€œFull JSONâ€ links in the report for complete data.
- You can adjust the maximum embedded rows via env var: `CREDAUDIT_HTML_MAX_ROWS` (e.g., 1000).

## What Gets Scanned

By default, the following extensions are included:
`.txt, .json, .env, .docx, .pdf, .xlsx, .har`

- Text files are read with encoding fallbacks (`utfâ€‘8`, `utfâ€‘16`, `latinâ€‘1`).
- DOCX: paragraph text extracted.
- PDF: text extracted via `pdfminer.six`.
- XLSX: cell values extracted; simple key/value heuristics for secrets (e.g., `password: value`).

You can override defaults via `--include-ext` or `config.yaml`.

### Archive Scanning

- Enable with `--scan-archives`; control nested depth with `--archive-depth N`.
- Supported formats: `.zip`, `.tar`, `.tgz`, `.tar.gz`, `.rar`.
- Safe extraction to a temporary directory with path traversal protection.
- Only scans extracted files with supported extensions (same list as above).
- Findings from archives show paths like: `archive.zip!inner/folder/file.env`.
- Example:
  ```sh
  credaudit scan -p ./artifacts --scan-archives --archive-depth 2 --formats html json
  ```

### HAR Support

- CredAudit scans .har files (exported with content) and aggregates findings across entries.
- Examples:
  ```sh
  credaudit scan -p traffic.har --formats html json csv
  credaudit scan -p traffic.har --har-include responses --formats html
  credaudit scan -p traffic.har --har-max-body-bytes 4194304
  ```

Built-in detections include:

Builtâ€‘in detections include:
- Private keys (PEM)
- AWS Access Key IDs
- AWS Secret Access Keys (contextual assignments)
- GitHub tokens
- JWTs (validated for structure)
- Password/secret assignments (strict and loose)
- Slack webhook URLs
- High-entropy strings
- Azure Storage SAS URLs (with signatures)
- Stripe secret keys (`sk_live_...`, `sk_test_...`)
- Database connection URIs with embedded password (Postgres/MySQL/Mongo/Redis)
 - Provider-specific tokens (enabled at Sensitivity L2/L3): Google API key (AIza...), Slack tokens (xox..), SendGrid (SG.xxx.yyy), GitLab PAT (glpat-...), npm token (npm_...), OpenAI key (sk-...), Telegram bot token (id:token), Twilio Account SID/Auth token

Run `credaudit rules` to list them.

## Config File (`config.yaml`)

Optional file loaded from the working directory by default.

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

CLI flags override these values for the current run.

## Caching

A lightweight cache (`.credaudit_cache.json`) stores file size/mtime and findings:
- Unchanged files reuse cached findings to speed up repeated scans.
- Use `--no-cache` to force a full rescan.

## Exit Codes

- `0` â€” Success; threshold not exceeded.
- `2` â€” `--fail-on` threshold met or exceeded.

## Versioning

- Print version: `credaudit --version` or `credaudit -V`.
- Banner also shows the current version in interactive output.
- To bump the version in code and packaging metadata:
  ```sh
  python scripts/bump_version.py 0.3.x
  ```
  This updates `credaudit/__init__.py` and `pyproject.toml`.

## License

MIT â€” see `LICENSE` for full text.

## CI and Pre-Commit

- GitHub Actions:
  - A workflow at `.github/workflows/credaudit.yml` runs CredAudit on pushes/PRs.
  - Publishes SARIF to GitHub code scanning and uploads HTML/JSON artifacts.
  - To customize, edit the workflow (e.g., paths, formats, or fail conditions).

- Pre-commit hook:
  - Config at `.pre-commit-config.yaml` runs a fast scan only on staged files.
  - Setup:
    - `pip install -e .` (ensure `credaudit` is importable)
    - `pip install pre-commit`
    - `pre-commit install`
  - Optional: set `CREDAUDIT_FAIL_ON` to `Low`, `Medium`, or `High` (default `High`).
    - Example: `CREDAUDIT_FAIL_ON=Medium pre-commit run --all-files`
