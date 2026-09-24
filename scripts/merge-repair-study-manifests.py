#!/usr/bin/env python3
"""Merge prelocked primary and supplemental trials, excluding the pilot case."""

import argparse
import json
from pathlib import Path


PILOT_CASE = "PySnooper-2"
IDENTITY_FIELDS = ("repair_agent_model", "current_route", "challenger_route")
CASE_FIELDS = (
    "id", "project", "fault_family", "raw_budget", "buggy_tree_sha256",
    "fixed_tree_sha256", "hidden_test_tree_sha256", "source_records_sha256",
    "editable_paths",
)


def checked_cases(manifest_path, lock_path):
    manifest = json.loads(manifest_path.read_text())
    lock = json.loads(lock_path.read_text())
    actual = {case["id"]: case for case in manifest["cases"]}
    expected = {case["id"]: case for case in lock["cases"]}
    if len(actual) != len(manifest["cases"]) or set(actual) != set(expected):
        raise ValueError(f"trial cases differ from frozen lock: {manifest_path}")
    for case_id, frozen in expected.items():
        trial = actual[case_id]
        if any(trial[field] != frozen[field] for field in CASE_FIELDS):
            raise ValueError(f"trial differs from frozen inputs: {case_id}")
        if trial["test_argv"][1:] != frozen["test_argv_suffix"]:
            raise ValueError(f"trial changed the test command: {case_id}")
    if any(manifest[field] != lock[field] for field in IDENTITY_FIELDS):
        raise ValueError("trial changed frozen model or route identity")
    return manifest


def merge(primary_manifest, primary_lock, supplement_manifest, supplement_lock):
    primary = checked_cases(primary_manifest, primary_lock)
    supplement = checked_cases(supplement_manifest, supplement_lock)
    if any(primary[field] != supplement[field] for field in IDENTITY_FIELDS):
        raise ValueError("paired studies used different models or routes")
    cases = primary["cases"] + supplement["cases"]
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("duplicate case across studies")
    if sum(case["id"] == PILOT_CASE for case in cases) != 1:
        raise ValueError("missing or duplicated development pilot")
    for case in cases:
        if case["id"] == PILOT_CASE:
            case["split"] = "development"
        # The deterministic selectors make no model call. The legacy runner
        # process began before this metric clarification was applied.
        for arm in ("no_logs", "first_id", "severity"):
            case["arms"][arm]["model_calls"] = 1
    primary["cases"] = cases
    primary["pilot_exclusion"] = (
        "PySnooper-2 was used for an agent-runner pilot before the held-out "
        "lock. Its paired trials are reported as development data only."
    )
    return primary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("primary-manifest", "primary-lock", "supplement-manifest",
                 "supplement-lock", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite merged trial manifest")
    result = merge(args.primary_manifest, args.primary_lock,
                   args.supplement_manifest, args.supplement_lock)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"held_out": sum(case["split"] == "held_out"
                                       for case in result["cases"]),
                      "development": sum(case["split"] == "development"
                                         for case in result["cases"])}, sort_keys=True))


if __name__ == "__main__":
    main()
