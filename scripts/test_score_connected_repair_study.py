import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "score_connected_repair_study",
    Path(__file__).with_name("score-connected-repair-study.py"),
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RepairStudyScoreTests(unittest.TestCase):
    def fixture(self, count=10):
        cases = [
            {
                "id": f"case-{index}",
                "project": f"project-{index % 3}",
                "fault_family": f"family-{index % 3}",
                "split": "held_out",
                "raw_budget": 4096,
            }
            for index in range(count)
        ]
        rows = []
        for case in cases:
            for arm in MODULE.ARMS:
                rows.append({
                    "case_id": case["id"], "arm": arm, "raw_budget": 4096,
                    "selected_raw_bytes": 0 if arm == "no_logs" else 1024,
                    "source_exact": True, "buggy_test_fails": True,
                    "fixed_test_passes": True,
                    "repair_test_passes": arm == "challenger",
                    "elapsed_ms": 100, "model_calls": 1,
                })
        return {
            "schema_version": 1, "repair_agent_model": "repair-model-v1",
            "current_route": "current-selector-v1", "challenger_route": "challenger-selector-v2",
            "cases": cases,
        }, rows

    def load(self, manifest, rows):
        with tempfile.TemporaryDirectory() as temp:
            manifest_path = Path(temp) / "manifest.json"
            results_path = Path(temp) / "results.jsonl"
            manifest_path.write_text(json.dumps(manifest))
            results_path.write_text("\n".join(json.dumps(row) for row in rows))
            return MODULE.read_study(manifest_path, results_path)

    def test_held_out_paired_verified_improvement_can_pass_review_gate(self):
        cases, rows = self.load(*self.fixture())
        result = MODULE.score(cases, rows)
        self.assertTrue(result["challenger_eligible_for_human_review"])
        self.assertEqual(result["verified_repair_successes"]["challenger"], 10)

    def test_development_case_budget_mismatch_and_regression_fail_closed(self):
        manifest, rows = self.fixture(1)
        cases, loaded = self.load(manifest, rows)
        self.assertEqual(MODULE.score(cases, loaded)["reason"], "insufficient_independent_cases")
        manifest, rows = self.fixture()
        rows[0]["raw_budget"] = 2048
        with self.assertRaises(ValueError):
            self.load(manifest, rows)
        manifest, rows = self.fixture()
        rows[3]["repair_test_passes"] = True
        rows[4]["repair_test_passes"] = False
        cases, loaded = self.load(manifest, rows)
        self.assertFalse(MODULE.score(cases, loaded)["challenger_eligible_for_human_review"])
        manifest, rows = self.fixture()
        manifest["cases"].append({
            "id": "development", "project": "project-0", "fault_family": "new",
            "split": "development", "raw_budget": 4096,
        })
        rows.extend({**row, "case_id": "development"} for row in rows[:5])
        with self.assertRaises(ValueError):
            self.load(manifest, rows)

    def test_challenger_must_beat_no_logs(self):
        manifest, rows = self.fixture()
        for row in rows:
            if row["arm"] == "no_logs":
                row["repair_test_passes"] = True
        cases, loaded = self.load(manifest, rows)
        result = MODULE.score(cases, loaded)
        self.assertFalse(result["challenger_eligible_for_human_review"])
        self.assertEqual(result["paired_comparisons"]["no_logs"]["one_sided_exact_p"], 1.0)

    def test_current_route_is_scored_against_every_baseline(self):
        manifest, rows = self.fixture()
        for row in rows:
            row["repair_test_passes"] = row["arm"] == "current"
        cases, loaded = self.load(manifest, rows)
        result = MODULE.score(cases, loaded)
        self.assertTrue(result["current_eligible_for_human_review"])
        self.assertEqual(result["current_vs_baselines"]["no_logs"]["target_only"], 10)

    def test_missing_or_identical_route_identity_is_rejected(self):
        manifest, rows = self.fixture()
        manifest.pop("repair_agent_model")
        with self.assertRaises(ValueError):
            self.load(manifest, rows)
        manifest, rows = self.fixture()
        manifest["challenger_route"] = manifest["current_route"]
        with self.assertRaises(ValueError):
            self.load(manifest, rows)


if __name__ == "__main__":
    unittest.main()
