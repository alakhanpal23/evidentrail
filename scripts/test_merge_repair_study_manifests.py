"""Protect the held-out set from a development pilot and case drift."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "merge_repair_study_manifests",
    Path(__file__).with_name("merge-repair-study-manifests.py"),
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MergeTests(unittest.TestCase):
    def test_pilot_excluded_and_lock_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def pair(name):
                frozen = {
                    "id": name, "project": name.split("-")[0],
                    "fault_family": "output_representation" if name == "PySnooper-2" else "formatter_comments",
                    "raw_budget": 1024,
                    "buggy_tree_sha256": "b", "fixed_tree_sha256": "f",
                    "hidden_test_tree_sha256": "h", "source_records_sha256": "s",
                    "editable_paths": ["source.py"], "test_argv_suffix": ["-m", "unittest", "hidden"],
                }
                trial = {key: frozen[key] for key in MODULE.CASE_FIELDS}
                trial.update({"split": "held_out", "test_argv": ["python", *frozen["test_argv_suffix"]],
                              "arms": {arm: {"model_calls": 2} for arm in
                                       ("no_logs", "first_id", "severity", "current", "challenger")}})
                identity = {key: key for key in MODULE.IDENTITY_FIELDS}
                manifest = {"schema_version": 1, **identity, "cases": [trial]}
                lock = {**identity, "cases": [frozen]}
                manifest_path = root / f"{name}-manifest.json"
                lock_path = root / f"{name}-lock.json"
                manifest_path.write_text(json.dumps(manifest))
                lock_path.write_text(json.dumps(lock))
                return manifest_path, lock_path

            primary, primary_lock = pair("PySnooper-2")
            supplemental, supplemental_lock = pair("black-8")
            result = MODULE.merge(primary, primary_lock, supplemental, supplemental_lock)
            self.assertEqual([case["split"] for case in result["cases"]],
                             ["development", "held_out"])
            self.assertEqual(result["cases"][1]["arms"]["first_id"]["model_calls"], 1)
            data = json.loads(supplemental.read_text())
            data["cases"][0]["raw_budget"] = 2048
            supplemental.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "frozen inputs"):
                MODULE.merge(primary, primary_lock, supplemental, supplemental_lock)


if __name__ == "__main__":
    unittest.main()
