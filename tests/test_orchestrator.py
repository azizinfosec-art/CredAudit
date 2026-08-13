import unittest
from multiprocessing import Queue

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


if __name__ == "__main__":
    unittest.main()
