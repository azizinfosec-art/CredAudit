# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning (SemVer). During 0.x, breaking changes are noted but use MINOR version bumps unless 1.0 is proposed.

## [0.5.0] - 2026-08-13 (Asia/Riyadh, GMT+3)

### Added
- CLI: simple safe shortcut, `credaudit PATH`, for client-friendly scans.
- CLI: `--safe` / `--redacted-only` mode for redacted reports and no raw-secret cache writes.
- CLI: `--fast` mode defaults for the shortcut: `.txt` only, 10 KB max file size, 2-second per-file timeout, generated-folder skips, and up to 4 workers.
- CLI: `--full` / `--standard` to opt into the full configured file scope.
- CLI: `--raw` to opt into raw findings for internal remediation workflows.
- CLI: console findings table when `--formats` is not provided.
- CLI: `--console-limit` to control how many findings are shown on screen.
- CLI: clickable `file:///...` report URLs when `--formats` creates report files.
- CLI: timestamped report filenames are now the default when `--formats` is used.
- CLI: `--no-timestamp` to write fixed report filenames such as `report.html`.
- CLI: `--max-size-kb` for small-file scan limits.
- CLI: `credaudit scan PATH` now uses the same fast safe defaults as `credaudit PATH`.
- Rules: low-severity `UsernameAssignment`, `PasswordKeyword`, and `PasswordCandidate` indicators.
- Rules: high-severity `UsernameNearPassword` for username-like lines immediately before password findings.
- Tests: coverage for safe shortcut, fast defaults, and console output.

### Changed
- Default client workflow now prints redacted findings to the terminal unless output formats are explicitly selected.
- Safe/redacted and fast mode are now the default scan behavior; full/raw behavior is explicit.
- CSV and NDJSON outputs redact matched secrets in context snippets.
- HTML safe reports hide raw-secret controls.
- Documentation now includes Windows and Kali Linux setup instructions and simpler client usage examples.
- Windows interrupt handling is cleaner when a scan is cancelled with Ctrl+C.

### Fixed
- Duplicate findings from overlapping rules are collapsed by file, line, and secret value while preserving the strongest or most specific rule.
- Duplicate checks now normalize common trailing syntax punctuation such as commas and semicolons.
- Redaction now uses a four-star middle mask instead of fully masking short values.
- Explicit file targets such as `.xlsx` workbooks are scanned directly in default fast mode instead of being silently filtered by directory-scan defaults.
- XLSX extraction now detects password values under mixed table headers such as `system` / `user` / `password`, instead of treating the header row as the secret.
- Noisy `openpyxl` data-validation compatibility warnings are suppressed during XLSX scanning so progress output stays readable.
- Scan progress now refreshes while workers are busy on slow files, so long XLSX/PDF/HAR reads no longer look frozen between completed files.

### Security
- Safe mode skips cache reads and writes to avoid storing raw findings locally.
- Safe/console output redacts secret matches before displaying or exporting client-facing results.

## [0.4.0] - 2025-09-07 (Asia/Kuwait, GMT+3)

### Added
- CLI: `--only-rules` to restrict detection to specific rules. Accepts names or numeric indices (from `credaudit rules`).
- HTML: new cyber‑hacker themed dashboard (dark neon, two‑pane layout, sticky header/footer, keyboard shortcuts). Exporter now prefers external template at `credaudit/html_templates/report.html.j2`.
- Docs: `docs/SCHEMA.md` defining NDJSON/JSON/CSV/SARIF fields.
- Tests: end‑to‑end tests for NDJSON/JSON/HTML/HAR/ZIP.
- Formats: `.toml` added to supported text extensions.

### Changed
- Rules: `PasswordAssignment` now also matches JSON‑quoted style (e.g., `"password":"value"`) with minimal, safe tweak to reduce misses without adding noise.
- Exports: deterministic ordering across JSON/CSV/HTML/SARIF (by file → line → rule).
- SARIF: driver version uses the package `__version__`.

### Fixed
- N/A

### Deprecated
- None

### Removed
- None

### Security
- None

[0.5.0]: https://github.com/azizinfosec-art/CredAudit/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/azizinfosec-art/CredAudit/compare/v0.3.16...v0.4.0
