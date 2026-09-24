import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

route = load("route_score", ROOT / "score-learning-route.py")
base = load("repair_score", ROOT / "score-connected-repair-study.py")
verifier = load("repair_verify", ROOT / "verify-connected-repair-trials.py")
fixture_module = load("repair_fixture", ROOT / "test_verify_connected_repair_trials.py")

class MemoryAblationTests(unittest.TestCase):
    def test_six_arm_verifier_and_scorer_accept_frozen_development_fixture(self):
        old_arms = fixture_module.MODULE.ARMS
        fixture_module.MODULE.ARMS = route.ARMS
        old_score_arms = base.ARMS
        base.ARMS = route.ARMS
        try:
            with tempfile.TemporaryDirectory() as directory:
                manifest, _ = fixture_module.VerifiedTrialTests().fixture(Path(directory))
                frozen = json.loads(manifest.read_text())
                frozen["challenger_no_memory_route"] = "challenger-memory-disabled-v2"
                manifest.write_text(json.dumps(frozen))
                verifier.ARMS = route.ARMS
                rows = verifier.verify(manifest)
                self.assertEqual(len(rows), 6)
                results = Path(directory) / "results.jsonl"
                results.write_text("".join(json.dumps(row) + "\n" for row in rows))
                cases, parsed = base.read_study(manifest, results)
                self.assertEqual(len(parsed), 6)
                self.assertFalse(route.score_ablation(cases, parsed, base)["qualified"])
        finally:
            fixture_module.MODULE.ARMS = old_arms
            base.ARMS = old_score_arms
    def test_ten_independent_memory_only_repairs_qualify(self):
        cases = {str(i): {"split": "held_out"} for i in range(10)}
        rows = {(case, arm): {"repair_test_passes": arm == "challenger"}
                for case in cases for arm in ("challenger", "challenger_no_memory")}
        result = route.score_ablation(cases, rows, base)
        self.assertTrue(result["qualified"])
        self.assertLessEqual(result["one_sided_exact_p"], 0.01)
        rows[("0", "challenger_no_memory")]["repair_test_passes"] = True
        rows[("0", "challenger")]["repair_test_passes"] = False
        self.assertFalse(route.score_ablation(cases, rows, base)["qualified"])

    def test_no_downstream_gain_cannot_qualify(self):
        cases = {"only": {"split": "held_out"}}
        rows = {("only", arm): {"repair_test_passes": True}
                for arm in ("challenger", "challenger_no_memory")}
        self.assertFalse(route.score_ablation(cases, rows, base)["qualified"])

if __name__ == "__main__":
    unittest.main()
