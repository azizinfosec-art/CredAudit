# CredAudit

Fast, resilient secret scanner for files and folders. Supports text, DOCX, PDF, and XLSX content with multiple report formats.

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

## Commands

- `credaudit validate` — Validate config and show enabled parsers.
- `credaudit rules` — List built‑in detection rules.
- `credaudit scan` — Run a scan on files/folders.

## Scan Options

- `-p, --path PATH` — File or directory to scan.
- `-o, --output-dir DIR` — Output directory (default: `./credaudit_out`).
- `--formats FMT [...]` — Any of: `json`, `csv`, `html`, `sarif`.
- `--include-ext EXT [...]` — Limit by extensions (e.g. `.env .json`).
- `--include-glob PATTERN [...]` — Include files by glob (repeatable).
- `--exclude-glob PATTERN [...]` — Exclude files by glob (repeatable).
- `--ignore-file FILE` — Glob patterns file (like `.credauditignore`).
- `--max-size MB` — Skip files larger than this size.
- `--threads N` — Threads for file discovery.
- `--workers N` — Processes for scanning.
- `--list` — Dry-run: only list files that would be scanned.
- `--timestamp` — Append a timestamp to report filenames.
- `--fail-on {Low,Medium,High}` — Exit non‑zero if any finding ≥ threshold.
- `--config PATH` — Path to `config.yaml` (default: `config.yaml`).
- `--entropy-min-length INT` — Min token length for entropy rule (default: 20).
- `--entropy-threshold FLOAT` — Entropy threshold (default: 4.0).
- `--cache-file PATH` — Cache file (default: `.credaudit_cache.json`).
- `--scan-archives` — (Placeholder) Flag for archive scanning.
- `--archive-depth N` — Depth for nested archives.
- `--no-cache` — Ignore cache; force full rescan.
- `--verbose` — Verbose logging.
- `--no-banner` — Suppress ASCII banner output.

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

## Output Formats

- `json` — Full findings (includes raw `match` and `redacted`).
- `csv` — Columns: `file, rule, redacted, severity, line, context`.
- `html` — Single‑page, sortable summary with severity coloring.
- `sarif` — SARIF 2.1.0 for code scanning integrations.

Note: JSON includes the raw matched value (`match`) for completeness. Handle with care.

## What Gets Scanned

By default, the following extensions are included:
`.txt, .json, .env, .docx, .pdf, .xlsx`

- Text files are read with encoding fallbacks (`utf‑8`, `utf‑16`, `latin‑1`).
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

## Rules

Built‑in detections include:
- Private keys (PEM)
- AWS Access Key IDs
- AWS Secret Access Keys (contextual assignments)
- GitHub tokens
- JWTs (validated for structure)
- Password/secret assignments (strict and loose)
- Slack webhook URLs
- High‑entropy strings
- Azure Storage SAS URLs (with signatures)
- Stripe secret keys (`sk_live_...`, `sk_test_...`)
- Database connection URIs with embedded password (Postgres/MySQL/Mongo/Redis)

Run `credaudit rules` to list them.

## Config File (`config.yaml`)

Optional file loaded from the working directory by default.

Example:

```yaml
include_ext: [".txt", ".json", ".env", ".docx", ".pdf", ".xlsx"]
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

- `0` — Success; threshold not exceeded.
- `2` — `--fail-on` threshold met or exceeded.

## Versioning

- Print version: `credaudit --version` or `credaudit -V`.
- Banner also shows the current version in interactive output.
- To bump the version in code and packaging metadata:
  ```sh
  python scripts/bump_version.py 0.3.x
  ```
  This updates `credaudit/__init__.py` and `pyproject.toml`.

## License

MIT — see `LICENSE` for full text.

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
