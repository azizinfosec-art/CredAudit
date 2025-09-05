# CredAudit v0.3.4 (Final) — includes DOCX/XLSX/PDF parsers.

# Usage

CredAudit is a fast, resilient secret scanner for files and folders.

## Basic Scan

Scan a file or directory for secrets:

```sh
python -m credaudit scan -p ./tests/secrets.txt --formats json
```

## Options

- `-p, --path PATH` : Path to file or directory to scan.
- `--formats FORMAT` : Output formats (json, csv, html, sarif).
- `--config CONFIG` : Path to configuration file.
- `--exclude EXCLUDE` : Glob patterns to exclude files/folders.
- `--rules RULES` : Comma-separated list of rule names to enable.
- `--disable-rules RULES` : Comma-separated list of rule names to disable.
- `--entropy-threshold FLOAT` : Set entropy threshold for detection.
- `--redact` : Redact secrets in output.
- `--no-cache` : Disable scan caching.
- `--show-severity` : Show severity in output.
- `--show-context` : Show context around findings.
- `--verbose` : Verbose output.
- `--quiet` : Minimal output.
- `--help` : Show help message.
- `--version` : Show version information.

## Other Commands

- `validate-config` : Validate configuration file.
- `list-rules` : List all detection rules.

## Example

```sh
python -m credaudit scan -p ./my_project --formats html --redact --show-severity
```

This will scan all files in `my_project`, output results in HTML format, redact secrets, and show severity levels.
