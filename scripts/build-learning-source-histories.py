#!/usr/bin/env python3
"""Freeze per-project development history plus one current held-out log stream."""

import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(path, expected_digest):
    if digest(path) != expected_digest:
        raise ValueError(f"source inventory changed: {path}")
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if not rows or len({(row["source_id"], row["native_id"]) for row in rows}) != len(rows):
        raise ValueError(f"empty or duplicate source inventory: {path}")
    if any(("raw_base64" in row) == ("raw" in row) for row in rows):
        raise ValueError(f"record has invalid raw encoding: {path}")
    return rows


def build(cohort_path, development_path, artifacts, output_root, output_lock):
    if output_root.exists() or output_lock.exists():
        raise ValueError("refusing to overwrite frozen study histories")
    cohort = json.loads(cohort_path.read_text())
    development = json.loads(development_path.read_text())
    held = cohort["cases"]
    dev = development["cases"]
    held_ids = {case["id"] for case in held}
    dev_ids = {case["id"] for case in dev}
    if (len(held_ids) != len(held) or len(dev_ids) != len(dev)
            or held_ids & dev_ids or not all(case["split"] == "held_out" for case in held)
            or not all(case["split"] == "development" for case in dev)):
        raise ValueError("invalid or overlapping cohort splits")
    for case in held:
        project_dev = [row for row in dev if row["project"] == case["project"]]
        if len(project_dev) < 2:
            raise ValueError(f"source-local study needs two development cases: {case['project']}")
        if case["buggy_commit"] in {row["buggy_commit"] for row in project_dev}:
            raise ValueError("held-out and development bug revisions overlap")
    output_root.mkdir(parents=True)
    frozen = {
        "schema_version": 1,
        "cohort_lock_sha256": digest(cohort_path),
        "development_lock_sha256": digest(development_path),
        "history_policy": "same-project development logs then one held-out log; no other held-out logs",
        "cases": [],
    }
    for case in held:
        project_dev = [row for row in dev if row["project"] == case["project"]]
        contributing = [*project_dev, case]
        source_id = hashlib.sha256(
            f"bugsinpy:learning-history:v1:{case['project']}".encode()
        ).hexdigest()
        records = []
        for contributor in contributing:
            path = artifacts / contributor["id"] / "source-records.jsonl"
            for row in inventory(path, contributor["source_records_sha256"]):
                records.append({
                    "source_id": source_id,
                    "native_id": f"{contributor['id']}/{row['native_id']}",
                    "raw_base64": row["raw_base64"],
                })
        native_ids = [row["native_id"] for row in records]
        if len(native_ids) != len(set(native_ids)):
            raise ValueError("combined history contains duplicate native IDs")
        directory = output_root / case["id"]
        directory.mkdir()
        output = directory / "source-records.jsonl"
        output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in records))
        frozen["cases"].append({
            "id": case["id"], "project": case["project"],
            "source_id": source_id, "source_records_sha256": digest(output),
            "development_case_ids": [row["id"] for row in project_dev],
            "record_count": len(records),
        })
    output_lock.parent.mkdir(parents=True, exist_ok=True)
    output_lock.write_text(json.dumps(frozen, indent=2, sort_keys=True) + "\n")
    return frozen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-lock", required=True, type=Path)
    parser.add_argument("--development-lock", required=True, type=Path)
    parser.add_argument("--artifacts-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--output-lock", required=True, type=Path)
    args = parser.parse_args()
    frozen = build(args.cohort_lock, args.development_lock, args.artifacts_root,
                   args.output_root, args.output_lock)
    print(json.dumps({"cases": len(frozen["cases"]),
                      "projects": len({case["project"] for case in frozen["cases"]})},
                     sort_keys=True))


if __name__ == "__main__":
    main()
