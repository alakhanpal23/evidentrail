#!/usr/bin/env python3
"""Normalize counted CLI runs in a completed six-arm study without changing trials."""

import argparse
import json
from pathlib import Path


MODEL_SELECTORS = {"current", "challenger", "challenger_no_memory"}
ARMS = {"no_logs", "first_id", "severity", *MODEL_SELECTORS}


def finalize(raw_path, pack_lock_path, output):
    if output.exists():
        raise ValueError("refusing to overwrite finalized manifest")
    manifest = json.loads(raw_path.read_text())
    pack_lock = json.loads(pack_lock_path.read_text())
    if (manifest["case_lock_sha256"] != pack_lock["case_lock_sha256"]
            or manifest["history_lock_sha256"] != pack_lock["history_lock_sha256"]
            or manifest["labels_sha256"] != pack_lock["labels_sha256"]):
        raise ValueError("manifest differs from frozen selection inputs")
    packs = {row["id"]: row["packs"] for row in pack_lock["cases"]}
    if (len(packs) != len(pack_lock["cases"])
            or {row["id"] for row in manifest["cases"]} != set(packs)
            or len(manifest["cases"]) != len(packs)):
        raise ValueError("incomplete or duplicate cases")
    for case in manifest["cases"]:
        if set(case["arms"]) != ARMS:
            raise ValueError("incomplete six-arm case")
        for arm in ARMS:
            expected = 1 + (packs[case["id"]][arm]["selection"]["selected_calls"]
                            if arm in MODEL_SELECTORS else 0)
            old = case["arms"][arm]["model_calls"]
            if (type(old) is not int or old < expected
                    or (arm in MODEL_SELECTORS and old != expected)):
                raise ValueError("invalid counted CLI runs")
            case["arms"][arm]["model_calls"] = expected
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--pack-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    finalize(args.raw, args.pack_lock, args.output)


if __name__ == "__main__":
    main()
