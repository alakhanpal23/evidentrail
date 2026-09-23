"""Checks the precedent scorer's split and complete-denominator gate."""

import json
import runpy
import tempfile
import unittest
from pathlib import Path


SCORE = runpy.run_path(str(Path(__file__).with_name("score-rcaeval-precedents.py")))["score"]
SERVICES = ("carts", "catalogue", "orders", "payment", "user")
FAULTS = ("cpu", "mem", "disk", "delay", "loss", "socket")


def fixture():
    header = {
        "dataset": "phamquiluan/RCAEval",
        "revision": "afeacb11bcc94dadfd1c8f483ee4377b2b8b614e",
        "case_count": 90,
        "metrics_only": True,
        "generic_question": True,
        "live_model": False,
    }
    rows = []
    for service in SERVICES:
        for fault in FAULTS:
            for replicate in (1, 2, 3):
                rows.append({
                    "case": f"re2ss_{service}_{fault}_{replicate}",
                    "status": "partial",
                    "root_service": service,
                    "naive_top_service": service,
                    "naive_joint_hit": True,
                    "service_fault_family_shifts": {service: {fault: 10.0}},
                })
    return header, rows


def score_rows(header, rows):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "probe.jsonl"
        path.write_text("".join(json.dumps(item) + "\n" for item in [header, *rows]), encoding="utf-8")
        return SCORE(path)


class PrecedentScoreTests(unittest.TestCase):
    def test_replica_one_is_training_only(self):
        header, rows = fixture()
        result = score_rows(header, rows)
        self.assertEqual(result["benchmark"], "RE2-SS")
        self.assertEqual(result["cases"], 60)
        self.assertEqual(result["precedent_joint_hits"], 60)
        self.assertEqual(result["naive_joint_hits"], 60)

    def test_accepts_online_boutique_case_names(self):
        header, rows = fixture()
        renamed = [{**row, "case": row["case"].replace("re2ss_", "re2ob_", 1)} for row in rows]
        self.assertEqual(score_rows(header, renamed)["benchmark"], "RE2-OB")
        renamed = [{**row, "case": row["case"].replace("re2ss_", "re2tt_", 1)} for row in rows]
        self.assertEqual(score_rows(header, renamed)["benchmark"], "RE2-TT")

    def test_missing_or_duplicate_case_is_unscorable(self):
        header, rows = fixture()
        for changed in (rows[:-1], [*rows[:-1], rows[0]]):
            with self.subTest(length=len(changed)), self.assertRaises(ValueError):
                score_rows(header, changed)


if __name__ == "__main__":
    unittest.main()
