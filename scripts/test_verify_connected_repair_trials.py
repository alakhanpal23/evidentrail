import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "verify_connected_repair_trials",
    Path(__file__).with_name("verify-connected-repair-trials.py"),
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VerifiedTrialTests(unittest.TestCase):
    def fixture(self, root):
        buggy = root / "buggy"
        buggy.mkdir()
        (buggy / "app.py").write_text("VALUE = 0\n")
        (buggy / "test_app.py").write_text(
            "import unittest\nfrom app import VALUE\n"
            "class Check(unittest.TestCase):\n"
            "    def test_value(self): self.assertEqual(VALUE, 1)\n"
        )
        fixed = root / "fixed"
        shutil.copytree(buggy, fixed)
        (fixed / "app.py").write_text("VALUE = 1\n")
        source = root / "source.jsonl"
        record = {"source_id": "a" * 64, "native_id": "event-1", "raw": "error value 0"}
        source.write_text(json.dumps(record) + "\n")
        pack = root / "pack.jsonl"
        pack.write_text(json.dumps(record) + "\n")
        arms = {}
        for arm in MODULE.ARMS:
            path = root / arm
            shutil.copytree(buggy, path)
            if arm == "challenger":
                (path / "app.py").write_text("VALUE = 1\n")
            arms[arm] = {
                "edited_tree": arm, "elapsed_ms": 100, "model_calls": 1,
                "log_pack": None if arm == "no_logs" else "pack.jsonl",
                "log_pack_sha256": None if arm == "no_logs" else MODULE.file_hash(pack).hex(),
            }
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({
            "schema_version": 1,
            "repair_agent_model": "repair-model-v1",
            "current_route": "current-selector-v1",
            "challenger_route": "challenger-selector-v2",
            "cases": [{
                "id": "synthetic-1", "project": "synthetic", "fault_family": "config",
                "split": "development", "raw_budget": 4096,
                "buggy_tree": "buggy", "fixed_tree": "fixed",
                "source_records": "source.jsonl", "editable_paths": ["app.py"],
                "buggy_tree_sha256": MODULE.tree_digest(buggy),
                "fixed_tree_sha256": MODULE.tree_digest(fixed),
                "source_records_sha256": MODULE.file_hash(source).hex(),
                "test_argv": [sys.executable, "-m", "unittest", "test_app.Check.test_value"],
                "arms": arms,
            }],
        }))
        return manifest, pack

    def test_real_test_execution_and_source_fidelity(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest, pack = self.fixture(Path(temp))
            rows = MODULE.verify(manifest)
            self.assertEqual(len(rows), 5)
            self.assertEqual([row["repair_test_passes"] for row in rows],
                             [False, False, False, False, True])
            pack.write_text(json.dumps({"source_id": "a" * 64, "native_id": "event-1",
                                        "raw": "changed log"}) + "\n")
            with self.assertRaises(ValueError):
                MODULE.verify(manifest)

    def test_rejects_trial_that_alters_the_verifier(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest, _ = self.fixture(Path(temp))
            (Path(temp) / "challenger" / "test_app.py").write_text("# bypassed\n")
            with self.assertRaises(ValueError):
                MODULE.verify(manifest)


if __name__ == "__main__":
    unittest.main()
