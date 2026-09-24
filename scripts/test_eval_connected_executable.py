"""Check that the repair benchmark grades executed behavior, not patch shape."""

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("eval-connected-executable.py")
SPEC = importlib.util.spec_from_file_location("eval_connected_executable", SCRIPT)
EVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVAL)


class RepairFixtureTests(unittest.TestCase):
    def test_each_fault_fails_before_edit_and_passes_only_after_its_edit(self):
        fixes = {
            "db-pool-zero": "pool_size=8\n",
            "migration-drift": "apply_migration=43\n",
            "upstream-timeout": "upstream_timeout_ms=500\n",
        }
        for scenario, replacement in fixes.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as scratch:
                workspace = Path(scratch)
                shutil.copytree(EVAL.REPAIR_FIXTURE, workspace, dirs_exist_ok=True)
                self.assertFalse(EVAL.service_test(workspace, scenario))
                (workspace / EVAL.WORKSPACE_FILES[scenario][0]).write_text(replacement)
                self.assertTrue(EVAL.service_test(workspace, scenario))


if __name__ == "__main__":
    unittest.main()
