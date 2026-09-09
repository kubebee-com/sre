#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("unified_kind", ROOT / "scripts/ci/unified-kind.py")
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RUNNER)


class CleanupResourcesTest(unittest.TestCase):
    def test_cleanup_reports_failure_and_continues(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            if args[:3] == ["kind", "delete", "cluster"] and args[-1] == "cluster-b":
                return 1
            return 0

        original_run = RUNNER.run
        RUNNER.run = fake_run
        try:
            cleaned = RUNNER.cleanup_resources(
                [("cluster-a", Path("a")), ("cluster-b", Path("b"))],
                ["image-a", "image-b"],
            )
        finally:
            RUNNER.run = original_run

        self.assertFalse(cleaned)
        self.assertEqual(
            [call[0] for call in calls],
            [
                ["kind", "delete", "cluster", "--name", "cluster-b"],
                ["kind", "delete", "cluster", "--name", "cluster-a"],
                ["docker", "image", "rm", "image-a"],
                ["docker", "image", "rm", "image-b"],
            ],
        )


if __name__ == "__main__":
    unittest.main()
