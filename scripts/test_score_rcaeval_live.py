"""Regression checks for the paired live-run denominator and score."""

import json
import runpy
import tempfile
import unittest
from pathlib import Path


SCORE = runpy.run_path(str(Path(__file__).with_name("score-rcaeval-live.py")))["score"]


def fixture():
    header = {
        "dataset": "phamquiluan/RCAEval",
        "revision": "afeacb11bcc94dadfd1c8f483ee4377b2b8b614e",
        "live_model": True,
        "metrics_only": True,
        "generic_question": True,
        "case_count": 2,
    }
    rows = []
    for fault, naive, model in (("cpu", True, False), ("mem", False, True)):
        rows.append({
            "case": f"re2ss_catalogue_{fault}_1",
            "status": "partial",
            "naive_joint_hit": naive,
            "top1_joint_hit": model,
            "top3_joint_hit": model,
            "top1_root_service_hit": True,
            "top1_fault_hit": model,
            "top1_fault_type": "mem" if model else "unknown",
            "model_needs_more_evidence": not model,
            "citation_count": 1,
            "hypothesis_count": 1,
            "top1_support_scope": "direct" if model else "dependent_only",
            "direct_hypothesis_count": int(model),
            "dependent_only_hypothesis_count": int(not model),
            "model_latency_seconds": 1.5,
        })
    return header, rows


def score_rows(header, rows):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "run.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in [header, *rows]), encoding="utf-8")
        return SCORE(path)


class LiveScoreTests(unittest.TestCase):
    def test_counts_paired_wins_and_losses(self):
        header, rows = fixture()
        report = score_rows(header, rows)
        self.assertEqual(report["case_count"], 2)
        self.assertEqual(report["naive_top1_joint_hits"], 1)
        self.assertEqual(report["model_top1_joint_hits"], 1)
        self.assertEqual(report["model_only_joint_hits"], 1)
        self.assertEqual(report["naive_only_joint_hits"], 1)
        self.assertEqual(report["direct_hypotheses"], 1)
        self.assertEqual(report["dependent_only_hypotheses"], 1)
        self.assertEqual(report["top1_unknown_fault_types"], 1)
        self.assertEqual(report["top1_specific_fault_types"], 1)
        self.assertEqual(report["needs_more_evidence"], 1)

    def test_rejects_incomplete_duplicate_and_failed_runs(self):
        header, rows = fixture()
        for modified_header, modified_rows in (
            ({**header, "case_count": 3}, rows),
            (header, [rows[0], {**rows[1], "case": rows[0]["case"]}]),
            (header, [rows[0], {**rows[1], "status": "product_error"}]),
        ):
            with self.subTest(modified_rows=modified_rows), self.assertRaises(ValueError):
                score_rows(modified_header, modified_rows)

    def test_rejects_inconsistent_unknown_and_abstention_scores(self):
        header, rows = fixture()
        for changed in (
            {**rows[0], "top1_fault_hit": True},
            {**rows[0], "model_needs_more_evidence": "yes"},
            {**rows[0], "hypothesis_count": 0, "top1_fault_type": None},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                score_rows(header, [changed, rows[1]])


if __name__ == "__main__":
    unittest.main()
