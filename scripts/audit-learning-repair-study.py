#!/usr/bin/env python3
"""Audit a six-arm trial manifest against pretrial locks and exact source packs."""

import argparse
import importlib.util
import json
from pathlib import Path


def load(path):
    spec = importlib.util.spec_from_file_location("learning_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load(Path(__file__).with_name("run-learning-repair-study.py"))


def audit(args):
    held, histories, _ = RUNNER.inputs(
        args.case_lock, args.development_lock, args.history_lock, args.labels,
        args.artifacts_root, args.histories)
    frozen = json.loads(args.pack_lock.read_text())
    manifest = json.loads(args.manifest.read_text())
    if any(frozen[field] != RUNNER.digest(path) or manifest[field] != RUNNER.digest(path)
           for field, path in (
               ("case_lock_sha256", args.case_lock),
               ("history_lock_sha256", args.history_lock),
               ("labels_sha256", args.labels))):
        raise ValueError("study manifest differs from frozen inputs")
    if (manifest["repair_agent_model"] != "gpt-6-sol"
            or manifest["current_route"] != "codex-gpt-6-sol-no-memory"
            or manifest["challenger_route"] != "codex-gpt-6-luna-shadow-memory-on"
            or manifest["challenger_no_memory_route"]
            != "codex-gpt-6-luna-shadow-memory-off"):
        raise ValueError("frozen route or repair-agent identity changed")
    locked = {row["id"]: row for row in held["cases"]}
    history = {row["id"]: row for row in histories["cases"]}
    packs = {row["id"]: row["packs"] for row in frozen["cases"]}
    cases = {row["id"]: row for row in manifest["cases"]}
    if (len(cases) != len(manifest["cases"])
            or len(packs) != len(frozen["cases"])
            or set(cases) != set(locked) or set(packs) != set(locked)):
        raise ValueError("missing or duplicate held-out cases")
    different = 0
    for case_id, case in cases.items():
        original = locked[case_id]
        h = history[case_id]
        if (case["split"] != "held_out"
                or any(case[field] != original[field] for field in
                       ("project", "fault_family", "raw_budget", "editable_paths",
                        "buggy_tree_sha256", "fixed_tree_sha256",
                        "hidden_test_tree_sha256"))
                or case["source_records_sha256"] != h["source_records_sha256"]
                or Path(case["source_records"]).resolve()
                != (args.histories / case_id / "source-records.jsonl").resolve()
                or set(case["arms"]) != set(RUNNER.ARMS)):
            raise ValueError(f"frozen case protocol changed: {case_id}")
        source = RUNNER.VERIFY.source_records(Path(case["source_records"]))
        for arm in RUNNER.ARMS:
            trial = case["arms"][arm]
            if arm == "no_logs":
                if trial["log_pack"] is not None:
                    raise ValueError("no-logs arm received a pack")
                continue
            selected = packs[case_id][arm]
            method = selected["selection"]["selector"]
            expected_method = {"first_id": "first_id", "severity": "severity",
                               "current": "codex", "challenger": "codex_memory_on",
                               "challenger_no_memory": "codex_memory_off"}[arm]
            expected_model = ("gpt-6-sol" if arm == "current" else "gpt-6-luna"
                              if arm in ("challenger", "challenger_no_memory") else None)
            if (method != expected_method or selected["selector_model"] != expected_model
                    or trial["log_pack_sha256"] != selected["sha256"]
                    or Path(trial["log_pack"]).resolve()
                    != (args.packs / case_id / f"{arm}.jsonl").resolve()
                    or RUNNER.digest(Path(trial["log_pack"])) != selected["sha256"]
                    or RUNNER.VERIFY.verify_pack(Path(trial["log_pack"]), source,
                                                 case["raw_budget"])
                    != selected["selected_raw_bytes"]):
                raise ValueError(f"frozen selection changed: {case_id}/{arm}")
        if packs[case_id]["challenger"]["sha256"] != packs[case_id]["challenger_no_memory"]["sha256"]:
            different += 1
    return {"schema_version": 1, "held_out_cases": len(cases),
            "development_cases": len(json.loads(args.development_lock.read_text())["cases"]),
            "memory_pack_differences": different,
            "case_lock_sha256": RUNNER.digest(args.case_lock),
            "history_lock_sha256": RUNNER.digest(args.history_lock),
            "labels_sha256": RUNNER.digest(args.labels),
            "pack_lock_sha256": RUNNER.digest(args.pack_lock),
            "manifest_sha256": RUNNER.digest(args.manifest)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("case-lock", "development-lock", "history-lock", "labels",
                 "artifacts-root", "histories", "packs", "pack-lock", "manifest"):
        parser.add_argument("--" + name, required=True, type=Path)
    print(json.dumps(audit(parser.parse_args()), sort_keys=True))


if __name__ == "__main__":
    main()
