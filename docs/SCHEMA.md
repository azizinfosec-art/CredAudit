# CredAudit Output Schemas

This document describes the stable fields for CredAudit outputs. Fields are case‑sensitive. New optional fields may be added in minor versions; existing fields will not be renamed.

Contents:
- NDJSON (streamed findings)
- JSON (full report)
- CSV (tabular)
- SARIF 2.1.0

## NDJSON (streamed during scan)

- Format: one JSON object per line. Each line represents a single finding produced during this run. Cached findings are not re‑emitted to NDJSON.
- Fields per line:
  - `ts` (string): ISO8601 UTC timestamp when the record was written.
  - `file` (string): file path or virtual ID (`archive.zip!path/inside` or `URL#response`).
  - `rule` (string): rule name (e.g., `PasswordAssignment`).
  - `severity` (string): one of `Low`, `Medium`, `High`.
  - `redacted` (string): masked representation of the secret.
  - `context` (string): surrounding text snippet (single line, truncated).
  - `line` (number|string): 1‑based line index (string or number). May be empty when unavailable.
  - Optional `match` (string): raw value, present only when `--ndjson-include-raw` is used.

Example line:
```
{"ts":"2025-09-07T07:45:12+00:00","file":"C:/repo/.env","rule":"PasswordAssignment","severity":"Medium","redacted":"pass**********d123","context":"password: Abcd1234","line":3}
```

## JSON (final report)

- Format: an array of finding objects.
- Fields per finding:
  - `file` (string)
  - `rule` (string)
  - `match` (string): raw value (if available)
  - `redacted` (string)
  - `context` (string)
  - `severity` (string): `Low` | `Medium` | `High`
  - `line` (number|string)

Example (trimmed):
```
[
  {
    "file":"C:/repo/.env",
    "rule":"PasswordAssignment",
    "match":"password: Abcd1234",
    "redacted":"pass**********d123",
    "context":"password: Abcd1234",
    "severity":"Medium",
    "line":3
  }
]
```

## CSV (final report)

Columns (in order):
- `file`, `rule`, `redacted`, `severity`, `line`, `context`

Notes:
- CSV contains redacted values only.
- Use NDJSON with `--ndjson-include-raw` if raw values are needed during streaming.

## SARIF 2.1.0

- Schema: SARIF v2.1.0.
- Root shape:
```
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "CredAudit", "version": "<package version>" } },
      "results": [
        {
          "ruleId": "<rule>",
          "level": "error|warning|note",   // High=error, Medium=warning, Low=note
          "message": { "text": "<redacted>" },
          "locations": [ {
            "physicalLocation": {
              "artifactLocation": { "uri": "<abs-path-or-virtual>" },
              "region": { "startLine": <number> }
            }
          } ]
        }
      ]
    }
  ]
}
```

## Compatibility

- Field names above are stable once released. New optional fields may be added; consuming code should ignore unknown fields.
- If you need additional metadata (e.g., sheet/cell for Excel), please open an issue; we will add new fields without breaking existing ones.

