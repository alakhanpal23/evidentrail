#!/usr/bin/env python3
"""Score a frozen, paired connected-log repair study without promoting a route.

Input is contentless JSON: no source code, log text, credentials, or patches.
The runner that creates each row must independently run the buggy, fixed, and
agent-edited repository tests and record the result. This scorer rejects
incomplete or development-only studies instead of treating them as wins.
"""

import argparse
import json
import math
from pathlib import Path


ARMS = ("no_logs", "first_id", "severity", "current", "challenger")
REQUIRED_CASE_FIELDS = {"id", "project", "fault_family", "split", "raw_budget"}
REQUIRED_ROW_FIELDS = {
    "case_id", "arm", "raw_budget", "selected_raw_bytes", "source_exact",
    "buggy_test_fails", "fixed_test_passes", "repair_test_passes",
    "elapsed_ms", "model_calls",
}


def read_study(manifest_path: Path, results_path: Path):
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("cases"), list):
        raise ValueError("invalid study manifest")
    if (not all(isinstance(manifest.get(field), str) and manifest[field].strip()
                for field in ("repair_agent_model", "current_route", "challenger_route"))
            or manifest["current_route"] == manifest["challenger_route"]):
        raise ValueError("model and route identities must be frozen")
    cases = {}
    for case in manifest["cases"]:
        if not isinstance(case, dict) or not REQUIRED_CASE_FIELDS <= case.keys():
            raise ValueError("incomplete case")
        if (not all(isinstance(case[key], str) and case[key] for key in
                    ("id", "project", "fault_family"))
                or case["split"] not in ("development", "held_out")
                or type(case["raw_budget"]) is not int
                or not 1024 <= case["raw_budget"] <= 1024 * 1024
                or case["id"] in cases):
            raise ValueError("invalid or duplicate case")
        cases[case["id"]] = case
    rows = {}
    for line in results_path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict) or not REQUIRED_ROW_FIELDS <= row.keys():
            raise ValueError("incomplete result row")
        key = (row["case_id"], row["arm"])
        if row["case_id"] not in cases or row["arm"] not in ARMS or key in rows:
            raise ValueError("unknown or duplicate case/arm")
        budget = cases[row["case_id"]]["raw_budget"]
        if (type(row["raw_budget"]) is not int or row["raw_budget"] != budget
                or type(row["selected_raw_bytes"]) is not int
                or not 0 <= row["selected_raw_bytes"] <= budget
                or (row["arm"] == "no_logs" and row["selected_raw_bytes"] != 0)
                or any(type(row[field]) is not bool for field in
                       ("source_exact", "buggy_test_fails", "fixed_test_passes", "repair_test_passes"))
                or not row["source_exact"] or not row["buggy_test_fails"]
                or not row["fixed_test_passes"]
                or type(row["elapsed_ms"]) is not int or row["elapsed_ms"] < 0
                or type(row["model_calls"]) is not int or row["model_calls"] < 0):
            raise ValueError("invalid budget, provenance, or verifier receipt")
        rows[key] = row
    for case_id in cases:
        if any((case_id, arm) not in rows for arm in ARMS):
            raise ValueError(f"incomplete paired arms for {case_id}")
    for field in ("project", "fault_family"):
        held = {case[field] for case in cases.values() if case["split"] == "held_out"}
        development = {case[field] for case in cases.values() if case["split"] == "development"}
        if held & development:
            raise ValueError(f"development and held-out {field} overlap")
    return cases, rows


def one_sided_exact_p(challenger_only, baseline_only):
    discordant = challenger_only + baseline_only
    if discordant == 0:
        return 1.0
    return sum(math.comb(discordant, k) for k in range(challenger_only, discordant + 1)) / 2 ** discordant


def percentile_95(values):
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def score(cases, rows):
    held = [case_id for case_id, case in cases.items() if case["split"] == "held_out"]
    projects = {cases[case_id]["project"] for case_id in held}
    families = {cases[case_id]["fault_family"] for case_id in held}
    sufficiently_independent = len(held) >= 10 and len(projects) >= 3 and len(families) >= 3
    counts = {arm: sum(rows[(case_id, arm)]["repair_test_passes"] for case_id in held)
              for arm in ARMS}
    comparisons = {}
    for arm in ("no_logs", "first_id", "severity", "current"):
        challenger_only = sum(rows[(case_id, "challenger")]["repair_test_passes"]
                              and not rows[(case_id, arm)]["repair_test_passes"] for case_id in held)
        baseline_only = sum(rows[(case_id, arm)]["repair_test_passes"]
                            and not rows[(case_id, "challenger")]["repair_test_passes"] for case_id in held)
        comparisons[arm] = {
            "challenger_only": challenger_only,
            "baseline_only": baseline_only,
            "one_sided_exact_p": one_sided_exact_p(challenger_only, baseline_only),
        }
    p95 = {arm: percentile_95([rows[(case_id, arm)]["elapsed_ms"] for case_id in held])
           for arm in ARMS} if held else {}
    calls = {arm: sum(rows[(case_id, arm)]["model_calls"] for case_id in held)
             for arm in ARMS}
    eligible = (sufficiently_independent
                and counts["challenger"] > counts["current"]
                and all(result["baseline_only"] == 0
                        and result["one_sided_exact_p"] <= 0.01
                        for result in comparisons.values())
                and p95["challenger"] <= 1.25 * max(1, p95["current"])
                and calls["challenger"] <= 1.25 * max(1, calls["current"]))
    return {
        "schema_version": 1,
        "held_out_cases": len(held),
        "held_out_projects": len(projects),
        "held_out_fault_families": len(families),
        "verified_repair_successes": counts,
        "paired_comparisons": comparisons,
        "p95_elapsed_ms": p95,
        "model_calls": calls,
        "challenger_eligible_for_human_review": eligible,
        "reason": "held_out_gate_passed" if eligible else (
            "insufficient_independent_cases" if not sufficiently_independent
            else "no_qualified_downstream_advantage"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    cases, rows = read_study(args.manifest, args.results)
    report = score(cases, rows)
    frozen = json.loads(args.manifest.read_text())
    report.update({field: frozen[field] for field in
                   ("repair_agent_model", "current_route", "challenger_route")})
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
