#!/usr/bin/env python3
"""Score contentless output from the seven-case connected RCAEval line probe."""

import argparse
import json
from pathlib import Path


EXPECTED_CASES = {
    "re3ss_carts_f1_1",
    "re3ss_carts_f1_2",
    "re3ss_carts_f3_1",
    "re3ss_carts_f3_2",
    "re3ss_front-end_f1_1",
    "re3ss_front-end_f1_2",
    "re3ss_front-end_f2_1",
}
PREFIX = "RCAEVAL_CONNECTED_EVAL "


def score(lines):
    rows = {}
    for line in lines:
        if not line.startswith(PREFIX):
            continue
        row = json.loads(line[len(PREFIX):])
        key = (row["method"], row["case"])
        if key in rows or row["case"] not in EXPECTED_CASES:
            raise ValueError("duplicate or unexpected RCAEval case")
        if row["labeled_source_lines"] != 1 or row["raw_log_budget"] != 32768:
            raise ValueError("invalid labeled-line or matched-budget contract")
        if not (0 <= row["selected_labeled_lines"] <= row["selected_template_lines"] <= row["selected_lines"]):
            raise ValueError("invalid selected-line counts")
        rows[key] = row
    methods = {method for method, _ in rows}
    if not {"first_id", "severity"}.issubset(methods):
        raise ValueError("missing deterministic comparison arm")
    if any({case for arm, case in rows if arm == method} != EXPECTED_CASES for method in methods):
        raise ValueError("incomplete method/case matrix")
    return {
        method: {
            "cases": 7,
            "exact_line_hit_cases": sum(rows[method, case]["selected_labeled_lines"] > 0 for case in EXPECTED_CASES),
            "template_hit_cases": sum(rows[method, case]["selected_template_lines"] > 0 for case in EXPECTED_CASES),
            "root_service_hit_cases": sum(rows[method, case]["selected_root_lines"] > 0 for case in EXPECTED_CASES),
            "selected_lines": sum(rows[method, case]["selected_lines"] for case in EXPECTED_CASES),
            "truncated_cases": sum(rows[method, case]["candidate_pool_truncated"] or rows[method, case]["service_directory_truncated"] for case in EXPECTED_CASES),
            "total_selector_calls": sum(rows[method, case]["selection_calls"] for case in EXPECTED_CASES),
        }
        for method in sorted(methods)
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_output", type=Path)
    args = parser.parse_args()
    print(json.dumps(score(args.run_output.read_text().splitlines()), sort_keys=True))


if __name__ == "__main__":
    main()
