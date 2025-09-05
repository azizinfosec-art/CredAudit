#!/usr/bin/env python3
"""
Simple version bump helper.

Usage:
  python scripts/bump_version.py 0.3.5

Updates:
  - credaudit/__init__.py (__version__)
  - pyproject.toml ([project].version)
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def update_init(new_ver: str) -> None:
    p = ROOT / 'credaudit' / '__init__.py'
    s = p.read_text(encoding='utf-8')
    s2 = re.sub(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", f"__version__='{new_ver}'", s)
    p.write_text(s2, encoding='utf-8')

def update_pyproject(new_ver: str) -> None:
    p = ROOT / 'pyproject.toml'
    s = p.read_text(encoding='utf-8')
    s2 = re.sub(r"(^version\s*=\s*['\"])([^'\"]+)(['\"])", rf"\g<1>{new_ver}\3", s, count=1, flags=re.M)
    p.write_text(s2, encoding='utf-8')

def main() -> int:
    if len(sys.argv) != 2:
        print('Usage: python scripts/bump_version.py <new_version>')
        return 2
    new_ver = sys.argv[1].strip()
    if not re.match(r"^\d+\.\d+\.\d+([.-]?\w+)?$", new_ver):
        print('Error: version must look like 1.2.3 or 1.2.3-dev1')
        return 2
    update_init(new_ver)
    update_pyproject(new_ver)
    print(f"Bumped version to {new_ver}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

