# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning (SemVer). During 0.x, breaking changes are noted but use MINOR version bumps unless 1.0 is proposed.

## [0.6.3] - 2026-08-16 (Asia/Riyadh, GMT+3)

### Added
- CLI: `credaudit examples` prints copy-paste commands for common safe scans after installation.

### Fixed
- Pre-commit scans now block `Critical` findings when the fail threshold is `High`.
- Text extraction now detects UTF-16 encoded text instead of silently losing password assignments.
- Archive scanning now applies the configured max-size limit to extracted members.
- ZIP/TAR/RAR archive scans now include extracted `.har` files.
- Directory discovery now prunes excluded folders before walking them, improving large-repo scans.
- Rule toggles from `config.yaml` now apply to scan execution, including entropy detection.
- Cache reuse now respects scanner settings such as selected rules, sensitivity, entropy thresholds, HAR limits, and package version.
- Timestamped report links now select reports using wall-clock time instead of the monotonic performance timer.

### Changed
- File discovery now filters paths through a bounded worker queue instead of materializing every discovered file up front.
- Small text files now avoid the expensive nested timeout subprocess path while heavier parsers and large files keep process isolation.
- Text scanning now resolves match line numbers from precomputed line starts instead of repeatedly recounting newlines.
- UTF-8 text extraction now avoids unnecessary fallback decoding work for ordinary text files.

### Tests
- Added e2e coverage for UTF-16 text files, critical pre-commit blocking, archive HAR members, archive max-size limits, disabled entropy rules, and cache invalidation when selected rules change.

## [0.6.2] - 2026-08-15 (Asia/Riyadh, GMT+3)

### Added
- Packaging metadata now includes author, keywords, project URLs, Python version classifiers, and a `dev` optional dependency group.
- Source distributions now explicitly include the packaged HTML report template.
- Repository line-ending and binary-file handling is documented through `.gitattributes`.

### Changed
- README now focuses on the safest default workflow, practical audit recipes, GitHub/CI usage, and troubleshooting.
- GitHub Actions now runs the standard-library unit and e2e test suites on Python 3.10, 3.11, and 3.12.

### Fixed
- GitHub Actions SARIF upload now uses fixed report filenames with `--no-timestamp`, matching the upload path.
- GitHub Actions self-scan is now provider-focused and excludes known fixtures/rule examples to reduce noisy code-scanning alerts.
- `credaudit validate` now reports configured include extensions and all supported parser extensions more accurately.
- Cleaned fallback HTML pager labels to avoid mojibake when the external template is unavailable.

## [0.6.1] - 2026-08-14 (Asia/Riyadh, GMT+3)

### Changed
- HTML reports now use a cleaner security-console layout with a compact scan context header, ExtraHop/NDR-inspired dark gray panels, cyan active accents, and a gray findings table.
- HTML report styling now avoids the removed top navigation bar so the report opens directly on the scan context and findings summary.

## [0.6.0] - 2026-08-13 (Asia/Riyadh, GMT+3)

### Added
- CLI: `credaudit passwords PATH` intent shortcut for password-focused `.txt` scans up to 5 MB.
- CLI: `--high-confidence`, `--min-confidence`, and `--show-evidence` for confidence-based triage.
- Rules: high-severity `CredentialPair` for compact same-line `username:password` text entries.
- Rules: password-only assignments after `password`, `pass`, `pwd`, `passwd`, `passphrase`, or `passcode` now take higher priority and confidence than generic secret assignments.
- Confidence: header/metadata-style colon pairs such as `Content-Transfer-Encoding: base64` are capped below high-confidence scores.
- Reports: JSON, CSV, NDJSON, SARIF, and HTML now include confidence/evidence metadata for findings.
- Tests: coverage for same-line credential pairs, confidence filtering, and console evidence output.

### Changed
- Scanner findings now include `confidence`, `finding_class`, `validity`, and redaction-safe `evidence` fields.
- Severity is now derived from confidence: `95+` is `Critical`, `80-94` is `High`, `50-79` is `Medium`, and lower scores are `Low`.
- Scan-style commands now stream redacted NDJSON by default to the output directory, with `--no-ndjson` available to disable it.
- `--per-file-timeout` now defaults to `2` seconds for scan-style commands, including `--full` scans.
- HTML reports now use a denser hacker-style triage dashboard with score filtering, responsive layout, evidence details, and filtered CSV export.
- Cached findings without confidence metadata are rescanned when confidence filtering is requested.

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
- HTML: new cyber-hacker themed dashboard (dark neon, two-pane layout, sticky header/footer, keyboard shortcuts). Exporter now prefers external template at `credaudit/html_templates/report.html.j2`.
- Docs: `docs/SCHEMA.md` defining NDJSON/JSON/CSV/SARIF fields.
- Tests: end-to-end tests for NDJSON/JSON/HTML/HAR/ZIP.
- Formats: `.toml` added to supported text extensions.

### Changed
- Rules: `PasswordAssignment` now also matches JSON-quoted style (e.g., `"password":"value"`) with minimal, safe tweak to reduce misses without adding noise.
- Exports: deterministic ordering across JSON/CSV/HTML/SARIF (by file -> line -> rule).
- SARIF: driver version uses the package `__version__`.

### Fixed
- N/A

### Deprecated
- None

### Removed
- None

### Security
- None

[0.6.3]: https://github.com/azizinfosec-art/CredAudit/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/azizinfosec-art/CredAudit/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/azizinfosec-art/CredAudit/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/azizinfosec-art/CredAudit/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/azizinfosec-art/CredAudit/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/azizinfosec-art/CredAudit/compare/v0.3.16...v0.4.0
## 0.7.0

- Added the public Python Engine API via `from credaudit import scan`.
- Added `ScanResult` with findings, severity counts, file totals, and timing.
- Added Engine API tests and usage documentation.
