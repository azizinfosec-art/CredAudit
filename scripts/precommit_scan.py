#!/usr/bin/env python3
"""
CredAudit pre-commit hook: scans only staged/changed files passed by pre-commit.

Usage (pre-commit passes file paths automatically):
  python scripts/precommit_scan.py [FILES...]

Exit codes:
  0 - OK
  2 - Findings at or above threshold (block commit)

Env vars:
  CREDAUDIT_FAIL_ON: Low|Medium|High (default: High)
"""
from __future__ import annotations
import os
import sys
from typing import List

from credaudit.config import Config
from credaudit.detection.scan import serialize_findings
from credaudit.parsers.extract import extract_text_from_file
from credaudit.detection.scan import scan_text

SEV_ORDER = {"Low": 1, "Medium": 2, "High": 3}


def main(argv: List[str]) -> int:
    files = [p for p in argv if os.path.isfile(p)]
    if not files:
        return 0
    cfg = Config.from_yaml(os.environ.get("CREDAUDIT_CONFIG", "config.yaml"))
    include_exts = set(cfg.include_ext)

    selected: List[str] = []
    for p in files:
        ext = os.path.splitext(p)[1].lower()
        if include_exts and ext not in include_exts:
            continue
        selected.append(p)

    if not selected:
        return 0

    # Scan files directly (no cache, no exporters)
    findings = []
    for p in selected:
        try:
            t = extract_text_from_file(p)
            if not t:
                continue
            f = serialize_findings(
                scan_text(p, t, cfg.entropy_min_length, cfg.entropy_threshold)
            )
            findings.extend(f)
        except Exception:
            # Ignore unreadable/problematic files in pre-commit context
            continue

    if not findings:
        return 0

    # Compute threshold decision
    fail_on = os.environ.get("CREDAUDIT_FAIL_ON", "High")
    thr = SEV_ORDER.get(fail_on, 3)
    worst = max(SEV_ORDER.get(f.get("severity", "Low"), 1) for f in findings)

    # Minimal console summary
    print(f"CredAudit pre-commit: {len(findings)} finding(s) in {len(set(f['file'] for f in findings))} file(s)")
    for f in findings[:50]:  # show up to 50 lines
        print(f" - [{f.get('severity','Low')}] {f.get('rule','?')} @ {f.get('file','?')}:{f.get('line',1)} :: {f.get('redacted','[redacted]')}")
    if len(findings) > 50:
        print(f" ... and {len(findings)-50} more ...")

    return 2 if worst >= thr else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

