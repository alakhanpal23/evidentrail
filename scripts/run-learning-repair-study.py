#!/usr/bin/env python3
"""Prepare and run frozen six-arm, source-local shadow-learning repair trials."""

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import time
from pathlib import Path


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


ROOT = Path(__file__).resolve().parent
BASE = module("connected_runner", ROOT / "run-connected-repair-study.py")
VERIFY = BASE.VERIFY
ARMS = ("no_logs", "first_id", "severity", "current", "challenger",
        "challenger_no_memory")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs(case_lock, development_lock, history_lock, labels_path, artifacts, histories):
    held = json.loads(case_lock.read_text())
    dev = json.loads(development_lock.read_text())
    history = json.loads(history_lock.read_text())
    if (history["cohort_lock_sha256"] != digest(case_lock)
            or history["development_lock_sha256"] != digest(development_lock)):
        raise ValueError("source history lock does not match frozen cohorts")
    held_ids = {case["id"] for case in held["cases"]}
    dev_by_id = {case["id"]: case for case in dev["cases"]}
    if (len(held_ids) != len(held["cases"])
            or len(dev_by_id) != len(dev["cases"]) or held_ids & set(dev_by_id)):
        raise ValueError("overlapping or duplicate development and held-out cases")
    by_history = {case["id"]: case for case in history["cases"]}
    if held_ids != set(by_history):
        raise ValueError("incomplete source history lock")
    labels = [json.loads(line) for line in labels_path.read_text().splitlines()]
    if not labels:
        raise ValueError("empty development labels")
    labels_by_project = {}
    for row in labels:
        dev_case = dev_by_id.get(row["case_id"])
        if (dev_case is None or row["label"] not in ("relevant", "irrelevant")
                or row["task"] != dev_case["task"]
                or not row["native_id"].startswith(row["case_id"] + "/")
                or row.get("reviewer") != "blind_model"
                or len(row.get("provenance_sha256", "")) != 64):
            raise ValueError("invalid or non-development label")
        native = row["native_id"].split("/", 1)[1]
        original_path = artifacts / row["case_id"] / "source-records.jsonl"
        if digest(original_path) != dev_case["source_records_sha256"]:
            raise ValueError("development source inventory changed")
        original = VERIFY.source_records(original_path)
        if not any(key[1] == native for key in original):
            raise ValueError("label refers to a record absent from development source")
        labels_by_project.setdefault(dev_case["project"], []).append(row)
    for case in held["cases"]:
        root = artifacts / case["id"]
        if digest(root / "source-records.jsonl") != case["source_records_sha256"]:
            raise ValueError("held-out source inventory changed")
        for field, folder in (("buggy_tree_sha256", "buggy"),
                              ("fixed_tree_sha256", "fixed"),
                              ("hidden_test_tree_sha256", "hidden-tests")):
            if VERIFY.tree_digest(root / folder) != case[field]:
                raise ValueError(f"frozen {case['id']} {folder} changed")
        source = histories / case["id"] / "source-records.jsonl"
        h = by_history[case["id"]]
        if digest(source) != h["source_records_sha256"]:
            raise ValueError(f"source history changed: {case['id']}")
        records = VERIFY.source_records(source)
        project_dev = h["development_case_ids"]
        if (len(project_dev) < 2 or any(dev_by_id[id_]["project"] != case["project"]
                                        for id_ in project_dev)
                or {row["case_id"] for row in labels_by_project.get(case["project"], [])}
                != set(project_dev)):
            raise ValueError("source-local labels must cover the two frozen development cases")
        contributors = [*(dev_by_id[id_] for id_ in project_dev), case]
        expected = {}
        for contributor in contributors:
            for (_, native), raw in VERIFY.source_records(
                    artifacts / contributor["id"] / "source-records.jsonl").items():
                expected[(h["source_id"], contributor["id"] + "/" + native)] = raw
        if (len(records) != h["record_count"]
                or records != expected):
            raise ValueError("history differs from the exact frozen source records")
    return held, history, labels_by_project


def select(selector, source, output, task, budget, method, model=None,
           labels=None, case_id=None):
    command = [str(selector), str(source), str(output), task, str(budget), method]
    if model:
        command.append(model)
    if labels:
        command.extend((str(labels), case_id))
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, timeout=600, check=False)
    if result.returncode:
        raise RuntimeError(f"selection failed for {case_id}/{method}: "
                           + result.stderr.decode(errors="replace")[-1000:])
    metadata = json.loads(result.stderr.decode().splitlines()[-1])
    metadata["end_to_end_elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return metadata


def prepare(args):
    if args.pack_lock.exists() or args.packs.exists():
        raise ValueError("refusing to overwrite frozen packs")
    held, history, labels = inputs(args.case_lock, args.development_lock,
                                    args.history_lock, args.labels, args.artifacts_root,
                                    args.histories)
    args.packs.mkdir(parents=True)
    frozen = {"schema_version": 1,
              "case_lock_sha256": digest(args.case_lock),
              "history_lock_sha256": digest(args.history_lock),
              "labels_sha256": digest(args.labels), "cases": []}
    for case in held["cases"]:
        case_dir = args.packs / case["id"]
        case_dir.mkdir()
        source_path = args.histories / case["id"] / "source-records.jsonl"
        records = VERIFY.source_records(source_path)
        project_label_path = case_dir / "development-labels.jsonl"
        project_label_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n"
                                             for row in labels[case["project"]]))
        selections = {}
        for arm, method, model in (
            ("first_id", "first_id", None),
            ("severity", "severity", None),
            ("current", "codex", "gpt-6-sol"),
            ("challenger", "codex_memory_on", "gpt-6-luna"),
            ("challenger_no_memory", "codex_memory_off", "gpt-6-luna"),
        ):
            output = case_dir / f"{arm}.jsonl"
            learning = method.startswith("codex_memory")
            metadata = select(args.selector_bin.resolve(), source_path, output,
                              case["task"], case["raw_budget"], method, model,
                              project_label_path if learning else None,
                              case["id"] if learning else None)
            used = VERIFY.verify_pack(output, records, case["raw_budget"])
            selections[arm] = {"sha256": digest(output), "selected_raw_bytes": used,
                               "selector_model": model, "selection": metadata}
        frozen["cases"].append({"id": case["id"], "packs": selections})
        print(json.dumps({"case_id": case["id"],
                          "selected_raw_bytes": {k: v["selected_raw_bytes"]
                                                 for k, v in selections.items()}},
                         sort_keys=True), flush=True)
    args.pack_lock.parent.mkdir(parents=True, exist_ok=True)
    args.pack_lock.write_text(json.dumps(frozen, indent=2, sort_keys=True) + "\n")


def run(args):
    held, history, _ = inputs(args.case_lock, args.development_lock,
                              args.history_lock, args.labels, args.artifacts_root,
                              args.histories)
    pack_lock = json.loads(args.pack_lock.read_text())
    if (pack_lock["case_lock_sha256"] != digest(args.case_lock)
            or pack_lock["history_lock_sha256"] != digest(args.history_lock)
            or pack_lock["labels_sha256"] != digest(args.labels)):
        raise ValueError("frozen pack inputs changed")
    by_case = {row["id"]: row["packs"] for row in pack_lock["cases"]}
    if set(by_case) != {case["id"] for case in held["cases"]}:
        raise ValueError("incomplete pack lock")
    by_history = {row["id"]: row for row in history["cases"]}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 1, "repair_agent_model": "gpt-6-sol",
                "current_route": "codex-gpt-6-sol-no-memory",
                "challenger_route": "codex-gpt-6-luna-shadow-memory-on",
                "challenger_no_memory_route": "codex-gpt-6-luna-shadow-memory-off",
                "case_lock_sha256": digest(args.case_lock),
                "history_lock_sha256": digest(args.history_lock),
                "labels_sha256": digest(args.labels), "cases": []}
    python = shutil.which(args.python)
    if python is None:
        raise ValueError("--python must resolve to an executable")
    for case in held["cases"]:
        root = args.artifacts_root / case["id"]
        source_path = args.histories / case["id"] / "source-records.jsonl"
        source = VERIFY.source_records(source_path)
        case_out = args.output_dir / case["id"]
        case_out.mkdir(exist_ok=True)
        arms = {}
        # Rotate trial order by frozen case ID so time drift is shared across arms.
        offset = hashlib.sha256(case["id"].encode()).digest()[0] % len(ARMS)
        ordered_arms = ARMS[offset:] + ARMS[:offset]
        for arm in ordered_arms:
            info = by_case[case["id"]].get(arm)
            pack = None if arm == "no_logs" else args.packs / case["id"] / f"{arm}.jsonl"
            if arm != "no_logs":
                if info is None or digest(pack) != info["sha256"]:
                    raise ValueError(f"frozen pack changed: {case['id']}/{arm}")
                VERIFY.verify_pack(pack, source, case["raw_budget"])
            workspace = case_out / arm
            events = case_out / f"{arm}-events.jsonl"
            metrics = case_out / f"{arm}-metrics.json"
            if metrics.exists() and workspace.is_dir() and events.is_file():
                trial = json.loads(metrics.read_text())
            else:
                if workspace.exists() or metrics.exists() or events.exists():
                    raise ValueError(f"incomplete trial: {case['id']}/{arm}")
                shutil.copytree(root / "buggy", workspace)
                trial = BASE.run_agent(workspace, BASE.load_prompt(case, arm, pack),
                                       manifest["repair_agent_model"], events,
                                       args.timeout_seconds)
                metrics.write_text(json.dumps(trial, indent=2, sort_keys=True) + "\n")
            if not trial["protocol_valid"]:
                raise ValueError(f"invalid agent protocol: {case['id']}/{arm}")
            selection = info["selection"] if info else {}
            arms[arm] = {"edited_tree": str(workspace),
                         "log_pack": str(pack) if pack else None,
                         "log_pack_sha256": info["sha256"] if info else None,
                         "elapsed_ms": trial["elapsed_ms"] + selection.get("end_to_end_elapsed_ms", 0),
                         "model_calls": 1 + selection.get("selected_calls", 0)}
            print(json.dumps({"case_id": case["id"], "arm": arm,
                              "agent_elapsed_ms": trial["elapsed_ms"],
                              "protocol_valid": trial["protocol_valid"]},
                             sort_keys=True), flush=True)
        h = by_history[case["id"]]
        manifest["cases"].append({
            "id": case["id"], "project": case["project"],
            "fault_family": case["fault_family"], "split": "held_out",
            "raw_budget": case["raw_budget"],
            "buggy_tree": str(root / "buggy"), "fixed_tree": str(root / "fixed"),
            "hidden_test_tree": str(root / "hidden-tests"),
            "source_records": str(source_path),
            "buggy_tree_sha256": case["buggy_tree_sha256"],
            "fixed_tree_sha256": case["fixed_tree_sha256"],
            "hidden_test_tree_sha256": case["hidden_test_tree_sha256"],
            "source_records_sha256": h["source_records_sha256"],
            "editable_paths": case["editable_paths"],
            "test_argv": [python, *case["test_argv_suffix"]], "arms": arms})
        (args.output_dir / "study.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "run"):
        p = sub.add_parser(name)
        p.add_argument("--case-lock", required=True, type=Path)
        p.add_argument("--development-lock", required=True, type=Path)
        p.add_argument("--history-lock", required=True, type=Path)
        p.add_argument("--labels", required=True, type=Path)
        p.add_argument("--artifacts-root", required=True, type=Path)
        p.add_argument("--histories", required=True, type=Path)
        p.add_argument("--packs", required=True, type=Path)
        p.add_argument("--pack-lock", required=True, type=Path)
        if name == "prepare":
            p.add_argument("--selector-bin", required=True, type=Path)
        else:
            p.add_argument("--output-dir", required=True, type=Path)
            p.add_argument("--python", required=True)
            p.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    (prepare if args.action == "prepare" else run)(args)


if __name__ == "__main__":
    main()
