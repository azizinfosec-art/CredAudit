import json
import os
import time
from datetime import datetime, timezone
from typing import Iterable, Dict, Any, Optional


class NDJSONWriter:
    def __init__(
        self,
        path: str,
        truncate: bool = False,
        flush_sec: float = 1.0,
        buffer_size: int = 100,
        include_raw: bool = False,
    ) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        mode = "w" if truncate else "a"
        self._f = open(path, mode, encoding="utf-8", newline="\n")
        self._buf: list[str] = []
        self._last_flush = time.time()
        self._flush_sec = max(0.0, float(flush_sec))
        self._buf_size = max(1, int(buffer_size))
        self._include_raw = bool(include_raw)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def add_findings(self, findings: Iterable[Dict[str, Any]]) -> None:
        ts = self._now()
        for rec in findings:
            out = {
                "ts": ts,
                "file": rec.get("file", ""),
                "rule": rec.get("rule", ""),
                "severity": rec.get("severity", "Low"),
                "redacted": rec.get("redacted", rec.get("value", "")),
                "context": rec.get("context", ""),
                "line": rec.get("line", ""),
            }
            if self._include_raw:
                out["match"] = rec.get("match", rec.get("value", ""))
            self._buf.append(json.dumps(out, ensure_ascii=False))
            if len(self._buf) >= self._buf_size:
                self._flush()
        # time-based flush
        if (time.time() - self._last_flush) >= self._flush_sec:
            self._flush()

    def _flush(self) -> None:
        if not self._buf:
            return
        self._f.write("\n".join(self._buf) + "\n")
        self._f.flush()
        os.fsync(self._f.fileno()) if hasattr(os, "fsync") else None
        self._buf.clear()
        self._last_flush = time.time()

    def close(self) -> None:
        try:
            self._flush()
        finally:
            try:
                self._f.close()
            except Exception:
                pass

