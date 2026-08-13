# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning (SemVer). During 0.x, breaking changes are noted but use MINOR version bumps unless 1.0 is proposed.

## [0.5.0] - 2026-08-13 (Asia/Riyadh, GMT+3)

### Added
- CLI: simple safe shortcut, `credaudit PATH`, for client-friendly scans.
- CLI: `--safe` / `--redacted-only` mode for redacted reports and no raw-secret cache writes.
- CLI: `--fast` mode defaults for the shortcut: `.txt` only, 10 KB max file size, and 5-second per-file timeout.
- CLI: console findings table when `--formats` is not provided.
- CLI: `--console-limit` to control how many findings are shown on screen.
- CLI: `--max-size-kb` for small-file scan limits.
- Tests: coverage for safe shortcut, fast defaults, and console output.

### Changed
- Default client workflow now prints redacted findings to the terminal unless output formats are explicitly selected.
- CSV and NDJSON outputs redact matched secrets in context snippets.
- HTML safe reports hide raw-secret controls.
- Documentation now includes Windows and Kali Linux setup instructions and simpler client usage examples.

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
