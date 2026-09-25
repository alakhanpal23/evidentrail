"""Check source-local histories exclude other held-out streams and source drift."""

import base64
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "build_learning_source_histories",
    Path(__file__).with_name("build-learning-source-histories.py"),
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class HistoryTests(unittest.TestCase):
    def test_development_history_is_shared_but_heldout_streams_are_isolated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifacts = root / "cases"
            artifacts.mkdir()
            development, heldout = [], []
            for case_id, split in (("project-1", "development"),
                                   ("project-2", "development"),
                                   ("project-3", "held_out"),
                                   ("project-4", "held_out")):
                source = artifacts / case_id / "source-records.jsonl"
                source.parent.mkdir()
                source.write_text(json.dumps({
                    "source_id": "a" * 64, "native_id": "line-0",
                    "raw_base64": base64.urlsafe_b64encode(case_id.encode()).decode().rstrip("="),
                }) + "\n")
                row = {"id": case_id, "project": "project", "split": split,
                       "buggy_commit": case_id,
                       "source_records_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
                (development if split == "development" else heldout).append(row)
            cohort = root / "cohort.json"
            labels = root / "development.json"
            cohort.write_text(json.dumps({"cases": heldout}))
            labels.write_text(json.dumps({"cases": development}))
            frozen = MODULE.build(cohort, labels, artifacts, root / "histories", root / "lock.json")
            self.assertEqual(frozen["cases"][0]["source_id"], frozen["cases"][1]["source_id"])
            for current, other in (("project-3", "project-4"), ("project-4", "project-3")):
                rows = [json.loads(line) for line in
                        (root / "histories" / current / "source-records.jsonl").read_text().splitlines()]
                ids = {row["native_id"] for row in rows}
                self.assertIn(current + "/line-0", ids)
                self.assertNotIn(other + "/line-0", ids)
                self.assertEqual(len(ids), 3)
            with self.assertRaisesRegex(ValueError, "source inventory changed"):
                (artifacts / "project-1" / "source-records.jsonl").write_text("tampered\n")
                MODULE.build(cohort, labels, artifacts, root / "different", root / "different.json")


if __name__ == "__main__":
    unittest.main()
