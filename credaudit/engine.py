"""Stable programmatic API for using CredAudit as a scanning engine."""

from dataclasses import dataclass
from typing import Any, List, Optional
import os
import time

from . import __version__
from .config import Config
from .orchestrator import collect_files, scan_paths
from .utils.common import redact_finding_records


@dataclass
class ScanResult:
    """Result returned by :func:`scan`."""

    findings: List[dict]
    files_scanned: int
    elapsed_sec: float
    exit_code: int
    version: str = __version__

    @property
    def counts(self) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in self.findings:
            severity = finding.get("severity")
            if severity in counts:
                counts[severity] += 1
        return counts


def scan(
    path: str = ".",
    *,
    mode: str = "fast",
    sensitivity: int = 2,
    min_confidence: Optional[int] = None,
    include_ext: Optional[List[str]] = None,
    output_dir: str = "credaudit_out",
    formats: Optional[List[str]] = None,
    safe: bool = True,
    no_cache: bool = False,
    workers: Optional[int] = None,
) -> ScanResult:
    """Scan a path and return findings for use in another Python project.

    ``mode`` can be ``"fast"`` or ``"full"``. Results are redacted by default.
    """
    if mode not in {"fast", "full"}:
        raise ValueError("mode must be 'fast' or 'full'")
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    cfg = Config()
    target_is_file = os.path.isfile(path)
    extensions = include_ext if include_ext is not None else (
        [] if target_is_file else [".txt"]
    ) if mode == "fast" else cfg.include_ext
    exclude_globs = list(cfg.exclude_glob)
    max_size_bytes = 10 * 1024 if mode == "fast" and not target_is_file else None
    rule_level = max(1, min(3, int(sensitivity)))
    scan_workers = workers if workers is not None else (min(4, os.cpu_count() or 2) if mode == "fast" else cfg.workers)

    files = collect_files(
        path,
        extensions,
        cfg.include_glob,
        exclude_globs,
        threads=cfg.threads,
        max_size_bytes=max_size_bytes,
    )
    started = time.perf_counter()
    findings, exit_code = scan_paths(
        files,
        output_dir,
        formats or [],
        False,
        cfg.cache_file,
        cfg.entropy_min_length,
        cfg.entropy_threshold,
        scan_workers,
        None,
        False,
        0,
        False,
        no_cache=no_cache,
        rule_level=rule_level,
        safe_report=safe,
        min_confidence=min_confidence,
        max_size_bytes=max_size_bytes,
    )
    visible = redact_finding_records(findings) if safe else findings
    return ScanResult(visible, len(files), round(time.perf_counter() - started, 3), exit_code)

