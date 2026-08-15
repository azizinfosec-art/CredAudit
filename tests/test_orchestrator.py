import unittest
import tempfile
from multiprocessing import Queue
from pathlib import Path

from credaudit import orchestrator


class TestOrchestratorWorkers(unittest.TestCase):
    def test_scan_file_runner_reports_keyboard_interrupt(self):
        original = orchestrator._scan_file_inner

        def raise_keyboard_interrupt(*_args, **_kwargs):
            raise KeyboardInterrupt()

        try:
            orchestrator._scan_file_inner = raise_keyboard_interrupt
            q = Queue(maxsize=1)
            orchestrator._scan_file_runner(q, "locked.xlsx", 20, 4.0, "both", None, None, None)
            self.assertEqual(q.get(timeout=1), ("locked.xlsx", [], "interrupted"))
        finally:
            orchestrator._scan_file_inner = original

    def test_collect_files_prunes_root_excluded_directories(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keep = root / "keep"
            skip = root / ".git"
            keep.mkdir()
            skip.mkdir()
            (keep / "secret.txt").write_text("password: Keep123!\n", encoding="utf-8")
            (skip / "ignored.txt").write_text("password: Skip123!\n", encoding="utf-8")

            files = orchestrator.collect_files(
                str(root),
                [".txt"],
                [],
                ["**/.git/**"],
                threads=0,
            )

            self.assertEqual([Path(p).name for p in files], ["secret.txt"])


if __name__ == "__main__":
    unittest.main()
