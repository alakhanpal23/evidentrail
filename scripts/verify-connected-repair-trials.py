#!/usr/bin/env python3
"""Verify paired coding-agent repair trials against immutable case controls.

The manifest names pre-created, isolated workspaces. Agents may edit only the
case's allowed source files; the runner verifies all other files and executes
the same regression test in buggy, fixed, and edited workspaces. Selected-log
packs are checked against original source-record IDs and bytes.
"""

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ARMS = ("no_logs", "first_id", "severity", "current", "challenger")


def resolved(base, value):
    path = Path(value)
    return path if path.is_absolute() else base / path


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).digest()


def tree_files(root):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("workspace is not a real directory")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise ValueError("workspace contains a symlink")
    return {
        str(path.relative_to(root)): file_hash(path)
        for path in root.rglob("*")
        if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }


def tree_digest(root):
    digest = hashlib.sha256()
    for name, content_hash in sorted(tree_files(root).items()):
        digest.update(len(name.encode()).to_bytes(4, "big"))
        digest.update(name.encode())
        digest.update(content_hash)
    return digest.hexdigest()


def allowed_edit_only(buggy, trial, editable_paths):
    before = tree_files(buggy)
    after = tree_files(trial)
    for path in before.keys() | after.keys():
        if path not in editable_paths and before.get(path) != after.get(path):
            return False
    return True


def record_bytes(row):
    if "raw" in row and "raw_base64" not in row and isinstance(row["raw"], str):
        return row["raw"].encode()
    if "raw_base64" in row and "raw" not in row and isinstance(row["raw_base64"], str):
        return base64.urlsafe_b64decode(row["raw_base64"] + "===")
    raise ValueError("record must have exactly one raw encoding")


def source_records(path):
    records = {}
    for line in path.read_text().splitlines():
        row = json.loads(line)
        key = (row["source_id"], row["native_id"])
        if key in records:
            raise ValueError("duplicate source/native record")
        records[key] = record_bytes(row)
    if not records:
        raise ValueError("empty source-record inventory")
    return records


def verify_pack(path, records, budget):
    if path is None:
        return 0
    used = 0
    seen = set()
    for line in path.read_text().splitlines():
        row = json.loads(line)
        key = (row["source_id"], row["native_id"])
        if key in seen or key not in records or record_bytes(row) != records[key]:
            raise ValueError("selected log is not an exact source record")
        seen.add(key)
        used += len(records[key])
    if used > budget:
        raise ValueError("selected logs exceed matched raw-byte budget")
    return used


def test_passes(root, hidden_tests, argv, timeout):
    # The agent never receives the regression suite. Only the verifier mounts
    # it into a disposable copy, and generated test files cannot contaminate
    # the frozen source trees or later paired arms.
    with tempfile.TemporaryDirectory(prefix="evidentrail-repair-verify-") as temp:
        execution = Path(temp) / "workspace"
        shutil.copytree(root, execution)
        shutil.copytree(hidden_tests, execution, dirs_exist_ok=True)
        try:
            result = subprocess.run(argv, cwd=execution, capture_output=True,
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise ValueError("verification test timed out") from error
        return result.returncode == 0


def verify(manifest_path):
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("cases"), list):
        raise ValueError("invalid manifest")
    if (not all(isinstance(manifest.get(field), str) and manifest[field].strip()
                for field in ("repair_agent_model", "current_route", "challenger_route"))
            or manifest["current_route"] == manifest["challenger_route"]):
        raise ValueError("model and route identities must be frozen")
    base = manifest_path.parent
    results = []
    for case in manifest["cases"]:
        buggy = resolved(base, case["buggy_tree"])
        fixed = resolved(base, case["fixed_tree"])
        hidden = resolved(base, case["hidden_test_tree"])
        source_path = resolved(base, case["source_records"])
        if (tree_digest(buggy) != case["buggy_tree_sha256"]
                or tree_digest(fixed) != case["fixed_tree_sha256"]
                or tree_digest(hidden) != case["hidden_test_tree_sha256"]
                or file_hash(source_path).hex() != case["source_records_sha256"]):
            raise ValueError("frozen case inputs changed")
        if tree_files(hidden).keys() & (tree_files(buggy).keys() | tree_files(fixed).keys()):
            raise ValueError("hidden test files appear in an agent-visible tree")
        source = source_records(source_path)
        command = case["test_argv"]
        editable = set(case["editable_paths"])
        budget = case["raw_budget"]
        timeout = case.get("test_timeout_seconds", 60)
        if (not isinstance(command, list) or not command
                or not all(isinstance(arg, str) and arg for arg in command)
                or not editable or any(Path(path).is_absolute() or ".." in Path(path).parts
                                    for path in editable)
                or type(budget) is not int or not 1024 <= budget <= 1024 * 1024
                or type(timeout) is not int or not 1 <= timeout <= 300):
            raise ValueError("invalid case test or budget configuration")
        if any(path not in tree_files(buggy) for path in editable):
            raise ValueError("editable file missing from buggy tree")
        buggy_fails = not test_passes(buggy, hidden, command, timeout)
        fixed_passes = test_passes(fixed, hidden, command, timeout)
        if not buggy_fails or not fixed_passes:
            raise ValueError("buggy/fixed test control failed")
        if set(case["arms"]) != set(ARMS):
            raise ValueError("incomplete paired arms")
        for arm in ARMS:
            trial = case["arms"][arm]
            edited = resolved(base, trial["edited_tree"])
            if not allowed_edit_only(buggy, edited, editable):
                raise ValueError("trial changed an unapproved file")
            pack = trial.get("log_pack")
            if arm == "no_logs" and pack is not None:
                raise ValueError("no-logs arm received a log pack")
            if arm != "no_logs" and pack is None:
                raise ValueError("log arm is missing a pack")
            pack_path = resolved(base, pack) if pack else None
            if pack_path is not None and file_hash(pack_path).hex() != trial["log_pack_sha256"]:
                raise ValueError("frozen selected log pack changed")
            used = verify_pack(pack_path, source, budget)
            repaired = test_passes(edited, hidden, command, timeout)
            results.append({
                "case_id": case["id"], "arm": arm, "raw_budget": budget,
                "selected_raw_bytes": used, "source_exact": True,
                "buggy_test_fails": buggy_fails, "fixed_test_passes": fixed_passes,
                "repair_test_passes": repaired,
                "elapsed_ms": trial["elapsed_ms"], "model_calls": trial["model_calls"],
            })
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--manifest", type=Path)
    action.add_argument("--fingerprint-tree", type=Path)
    action.add_argument("--fingerprint-file", type=Path)
    args = parser.parse_args()
    if args.fingerprint_tree:
        print(tree_digest(args.fingerprint_tree))
        return
    if args.fingerprint_file:
        print(file_hash(args.fingerprint_file).hex())
        return
    for row in verify(args.manifest):
        print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()
