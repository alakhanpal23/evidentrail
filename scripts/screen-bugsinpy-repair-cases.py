#!/usr/bin/env python3
"""Screen pinned BugsInPy cases and freeze only reproducing repair fixtures.

The benchmark's own buggy/fixed labels are insufficient: this script runs the
same fixed-revision regression suite over both source revisions in this host's
Python environment. Output fixtures contain agent-visible source trees,
separate hidden tests, and exact failing-test bytes as source records.
"""

import argparse
import base64
import hashlib
import io
import json
import shlex
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


def parse_info(path):
    fields = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value.strip().strip('"')
    return fields


def archive_revision(repo, revision, destination):
    raw = subprocess.check_output(["git", "archive", revision], cwd=repo)
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        safe_members = []
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise ValueError("unsafe archive member")
            # Several benchmark repos link docs/fixtures. The evaluated source
            # tree contains only regular files; controls must still reproduce.
            if not member.issym() and not member.islnk():
                safe_members.append(member)
        archive.extractall(destination, members=safe_members)


def parse_test_command(path, python):
    lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError("test script must contain one pytest command")
    argv = shlex.split(lines[0])
    if argv[:1] == ["pytest"]:
        return [python, "-m", "pytest", *argv[1:]]
    if argv[:3] == ["python3", "-m", "pytest"]:
        return [python, *argv[1:]]
    if argv[:3] == ["python", "-m", "unittest"]:
        return [python, *argv[1:]]
    raise ValueError("unsupported test command")


def execute_case(source, hidden, command, timeout):
    with tempfile.TemporaryDirectory(prefix="evidentrail-case-control-") as temp:
        workspace = Path(temp) / "workspace"
        shutil.copytree(source, workspace)
        shutil.copytree(hidden, workspace, dirs_exist_ok=True)
        try:
            result = subprocess.run(command, cwd=workspace, capture_output=True,
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return None, b""
        return result.returncode, result.stdout + result.stderr


def split_exact_lines(raw):
    return raw.splitlines(keepends=True)


def write_records(path, project, bug_id, raw):
    source_id = hashlib.sha256(f"bugsinpy:{project}:{bug_id}".encode()).hexdigest()
    with path.open("w") as output:
        for index, line in enumerate(split_exact_lines(raw)):
            output.write(json.dumps({
                "source_id": source_id,
                "native_id": f"line-{index:06d}",
                "raw_base64": base64.urlsafe_b64encode(line).decode().rstrip("="),
            }, sort_keys=True) + "\n")


def screen_case(project, bug_dir, repo, output_dir, python, timeout):
    info = parse_info(bug_dir / "bug.info")
    command = parse_test_command(bug_dir / "run_test.sh", python)
    test_root = Path(info["test_file"]).parts[0]
    with tempfile.TemporaryDirectory(prefix="evidentrail-case-screen-") as temp:
        root = Path(temp)
        buggy, fixed, hidden = (root / name for name in ("buggy", "fixed", "hidden"))
        archive_revision(repo, info["buggy_commit_id"], buggy)
        archive_revision(repo, info["fixed_commit_id"], fixed)
        if project == "black":
            # The benchmark setup ordinarily generates this from setuptools_scm.
            # Freeze the same non-solution build artifact in both revisions.
            for source in (buggy, fixed):
                version_file = source / "_black_version.py"
                if not version_file.exists():
                    version_file.write_text('version = "benchmark-build"\n')
        tests = fixed / test_root
        if not tests.is_dir():
            raise ValueError("fixed revision lacks test directory")
        hidden.mkdir()
        shutil.copytree(tests, hidden / test_root)
        shutil.rmtree(buggy / test_root, ignore_errors=True)
        shutil.rmtree(fixed / test_root)
        buggy_code, raw_log = execute_case(buggy, hidden, command, timeout)
        fixed_code, _ = execute_case(fixed, hidden, command, timeout)
        if buggy_code is None or fixed_code is None:
            return {"project": project, "bug_id": bug_dir.name, "status": "timeout"}
        if buggy_code == 0 or fixed_code != 0:
            return {
                "project": project, "bug_id": bug_dir.name, "status": "invalid_controls",
                "buggy_exit": buggy_code, "fixed_exit": fixed_code,
            }
        if not raw_log or len(raw_log) > 1024 * 1024:
            return {"project": project, "bug_id": bug_dir.name, "status": "invalid_log_size"}
        case = output_dir / f"{project}-{bug_dir.name}"
        if case.exists():
            raise ValueError(f"refusing to overwrite frozen case {case}")
        case.mkdir(parents=True)
        for name, source in (("buggy", buggy), ("fixed", fixed), ("hidden-tests", hidden)):
            shutil.copytree(source, case / name)
        write_records(case / "source-records.jsonl", project, bug_dir.name, raw_log)
        (case / "control.json").write_text(json.dumps({
            "project": project, "bug_id": bug_dir.name,
            "buggy_commit": info["buggy_commit_id"],
            "fixed_commit": info["fixed_commit_id"],
            "test_argv": command,
            "test_root": test_root,
            "log_sha256": hashlib.sha256(raw_log).hexdigest(),
            "log_bytes": len(raw_log),
        }, indent=2, sort_keys=True) + "\n")
        return {
            "project": project, "bug_id": bug_dir.name, "status": "reproduced",
            "log_bytes": len(raw_log), "log_lines": len(split_exact_lines(raw_log)),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-projects", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path,
                        help="Directory containing Git clones named evidentrail-repair-PROJECT")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()
    python = shutil.which(args.python)
    if python is None:
        parser.error("--python must resolve to an executable")
    project = args.project
    repo = args.repo_root / f"evidentrail-repair-{project}"
    bugs = args.benchmark_projects / project / "bugs"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for bug in sorted(bugs.iterdir(), key=lambda path: int(path.name)):
        try:
            result = screen_case(project, bug, repo, args.output_dir,
                                 python, args.timeout)
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            result = {"project": project, "bug_id": bug.name,
                      "status": "screen_error", "error_type": type(error).__name__}
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
