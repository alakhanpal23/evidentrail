#!/usr/bin/env python3
"""Write the contentless, pre-trial lock for screened BugsInPy repair cases."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


CASES = (
    ("black", 4, "formatter_lexing"),
    ("black", 5, "formatter_lexing"),
    ("black", 7, "formatter_grammar"),
    ("black", 11, "formatter_comments"),
    ("thefuck", 1, "command_rule"),
    ("thefuck", 25, "command_rule"),
    ("thefuck", 26, "command_rule"),
    ("fastapi", 1, "api_serialization"),
    ("fastapi", 2, "api_dependency"),
    ("PySnooper", 2, "output_representation"),
)

VERIFY_SPEC = importlib.util.spec_from_file_location(
    "verify_connected_repair_trials",
    Path(__file__).with_name("verify-connected-repair-trials.py"),
)
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)


def editable_paths(patch):
    paths = []
    for line in patch.read_text().splitlines():
        if line.startswith("diff --git a/"):
            path = line.split(" b/", 1)[1]
            if not path.startswith(("tests/", "test/")):
                paths.append(path)
    if not paths:
        raise ValueError(f"no editable source paths in {patch}")
    return sorted(set(paths))


def freeze(artifacts, benchmark, selected_cases=CASES):
    cases = []
    for project, bug_id, family in selected_cases:
        name = f"{project}-{bug_id}"
        root = artifacts / name
        control = json.loads((root / "control.json").read_text())
        meta = benchmark / project / "bugs" / str(bug_id)
        test_argv = control["test_argv"]
        if len(test_argv) < 4:
            raise ValueError("incomplete regression command")
        task = f"Fix the reported failure in {test_argv[-1].split('::')[-1]} in {project}."
        source_hash = hashlib.sha256((root / "source-records.jsonl").read_bytes()).hexdigest()
        cases.append({
            "id": name, "project": project, "bug_id": bug_id,
            "fault_family": family, "split": "held_out", "raw_budget": 1024,
            "task": task, "buggy_commit": control["buggy_commit"],
            "fixed_commit": control["fixed_commit"],
            "test_argv_suffix": test_argv[1:],
            "editable_paths": editable_paths(meta / "bug_patch.txt"),
            "buggy_tree_sha256": VERIFY.tree_digest(root / "buggy"),
            "fixed_tree_sha256": VERIFY.tree_digest(root / "fixed"),
            "hidden_test_tree_sha256": VERIFY.tree_digest(root / "hidden-tests"),
            "source_records_sha256": source_hash,
            "failing_log_sha256": control["log_sha256"],
            "failing_log_bytes": control["log_bytes"],
        })
    return {
        "schema_version": 1,
        "case_source": "BugsInPy pinned buggy/fixed revisions; fixed tests hidden",
        "development_exclusion": "tqdm bug 1 was used in prior development probes",
        "repair_agent_model": "codex-cli-0.156.1/gpt-6-sol/low",
        "current_route": "connected_compaction/codex-cli-0.156.1/gpt-6-sol/low/study-bridge-v1",
        "challenger_route": "connected_compaction/codex-cli-0.156.1/gpt-6-luna/low/study-bridge-v1",
        "selection_prompt_version": "codex-group-rank-v1",
        "repair_prompt_version": "source-only-repair-v1",
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-root", required=True, type=Path)
    parser.add_argument("--benchmark-projects", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case", action="append", metavar="PROJECT:ID:FAMILY",
                        help="Freeze only these screened cases, in the supplied order")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite frozen study lock")
    selected = CASES
    if args.case:
        try:
            selected = tuple((project, int(bug_id), family)
                             for project, bug_id, family in
                             (value.split(":", 2) for value in args.case))
        except (ValueError, TypeError) as error:
            parser.error(f"invalid --case: {error}")
    locked = freeze(args.artifacts_root, args.benchmark_projects, selected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(locked, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"locked_cases": len(locked["cases"]),
                      "projects": sorted({row["project"] for row in locked["cases"]}),
                      "fault_families": len({row["fault_family"] for row in locked["cases"]})},
                     sort_keys=True))


if __name__ == "__main__":
    main()
