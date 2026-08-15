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

    def test_small_text_timeout_scans_inline_without_child_process(self):
        original = orchestrator._scan_file_inner
        calls = []

        def fake_scan_file_inner(*args, **kwargs):
            calls.append(args)
            return args[0], [{"rule": "PasswordValueAssignment"}], "ok"

        try:
            orchestrator._scan_file_inner = fake_scan_file_inner
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "secret.txt"
                path.write_text("password: Inline123!\n", encoding="utf-8")

                result = orchestrator._scan_file(
                    str(path),
                    20,
                    4.0,
                    per_file_timeout=2.0,
                )

            self.assertTrue(calls)
            self.assertEqual(result[2], "ok")
        finally:
            orchestrator._scan_file_inner = original


if __name__ == "__main__":
    unittest.main()
