Changelog

## 0.3.13 — 2025-09-06
- Added provider-specific detections gated to Sensitivity L2/L3: Google API key, Slack tokens, SendGrid API key, GitLab PAT, npm token, OpenAI key, Telegram bot token, Twilio Account SID/Auth token

## 0.3.12 — 2025-09-06

Highlights
- HAR support: scan `.har` files exported with content (Burp/ZAP/DevTools)
  - Options: `--har-include {both,responses,requests}`
  - Options: `--har-max-body-bytes N` (bytes) and env `CREDAUDIT_HAR_MAX_BODY_BYTES`
- HTML report UX: server-rendered rows so data shows without JavaScript; env `CREDAUDIT_HTML_MAX_ROWS` controls embedded rows (default 500)
- Sensitivity levels: `--sensitivity {1,2,3}` (L1 cautious, L2 balanced, L3 aggressive)
- CLI UX: interactive spinner (TTY), verbose tip line, end-of-run summary with elapsed time

Other
- README updated to document new options and defaults
- Default include extensions now include `.har`
