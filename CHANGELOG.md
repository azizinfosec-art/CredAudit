# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning (SemVer). During 0.x, breaking changes are noted but use MINOR version bumps unless 1.0 is proposed.

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

[0.4.0]: https://github.com/azizinfosec-art/CredAudit/compare/v0.3.16...v0.4.0
