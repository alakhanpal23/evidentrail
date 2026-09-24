import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "finalize", Path(__file__).with_name("finalize-learning-repair-manifest.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FinalizeTests(unittest.TestCase):
    def test_deterministic_arms_count_only_repair_cli_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            packs = {arm: {"selection": {"selected_calls": 2}}
                     for arm in MODULE.ARMS if arm != "no_logs"}
            lock = {"case_lock_sha256": "a", "history_lock_sha256": "b",
                    "labels_sha256": "c", "cases": [{"id": "case", "packs": packs}]}
            trial = {"case_lock_sha256": "a", "history_lock_sha256": "b",
                     "labels_sha256": "c", "cases": [{"id": "case", "arms": {
                         arm: {"model_calls": 3 if arm != "no_logs" else 1}
                         for arm in MODULE.ARMS}}]}
            lock_path, raw_path, output = (root / name for name in
                                           ("lock.json", "raw.json", "final.json"))
            lock_path.write_text(json.dumps(lock))
            raw_path.write_text(json.dumps(trial))
            MODULE.finalize(raw_path, lock_path, output)
            final = json.loads(output.read_text())
            self.assertEqual(final["cases"][0]["arms"]["severity"]["model_calls"], 1)
            self.assertEqual(final["cases"][0]["arms"]["challenger"]["model_calls"], 3)


if __name__ == "__main__":
    unittest.main()
