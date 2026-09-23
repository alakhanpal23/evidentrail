#!/usr/bin/env python3
"""Score an explicit, labeled incident manifest with a local model only.

The manifest and telemetry stay on this machine. JSONL output contains only
hashed case IDs and aggregate scores, never source lines or explanations.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


FAULTS = {"cpu", "mem", "disk", "delay", "loss", "socket", "other", "unknown"}
PATH_LIMITS = {"logs": 16 * 1024 * 1024, "metrics": 16 * 1024 * 1024,
               "traces": 64 * 1024 * 1024, "topology": 64 * 1024}


def explicit_file(root, name, limit):
    path = Path(name)
    if not path.is_absolute():
        path = root / path
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f"missing, non-file, or oversized {path.name}")
    return path


def validate_manifest(path):
    raw = path.read_bytes()
    data = json.loads(raw)
    if (not isinstance(data, dict) or data.get("schema_version") != 1
            or not isinstance(data.get("cases"), list)):
        raise ValueError("expected schema_version 1 and cases array")
    if not 1 <= len(data["cases"]) <= 256:
        raise ValueError("expected 1 to 256 cases")
    seen = set()
    cases = []
    for case in data["cases"]:
        if not isinstance(case, dict) or set(case) - {
            "id", "question", "expected_status", "expected_service", "expected_fault_type",
            "logs", "metrics", "incident_time", "traces", "topology",
        }:
            raise ValueError("unexpected case field")
        name, question = case.get("id"), case.get("question")
        if (not isinstance(name, str) or not 1 <= len(name) <= 128 or name in seen
                or not isinstance(question, str) or not 1 <= len(question) <= 4096):
            raise ValueError("case IDs must be unique and questions nonempty")
        seen.add(name)
        status = case.get("expected_status")
        if not isinstance(status, str) or status not in {"incident", "unknown", "healthy"}:
            raise ValueError("expected_status must be incident, unknown, or healthy")
        service, fault = case.get("expected_service"), case.get("expected_fault_type")
        if status == "incident":
            if (not isinstance(service, str) or not service
                    or (fault is not None and (not isinstance(fault, str) or fault not in FAULTS))):
                raise ValueError("incident requires a confirmed service and optional fault")
        elif service is not None or fault is not None:
            raise ValueError("unknown and healthy cases cannot name a confirmed cause")
        if (case.get("metrics") is None) != (case.get("incident_time") is None):
            raise ValueError("metrics and incident_time must be paired")
        if case.get("incident_time") is not None and type(case["incident_time"]) is not int:
            raise ValueError("incident_time must be a Unix integer")
        paths = {}
        for field, limit in PATH_LIMITS.items():
            value = case.get(field)
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise ValueError(f"invalid {field} path")
                paths[field] = explicit_file(path.parent, value, limit)
        if "logs" not in paths and "metrics" not in paths:
            raise ValueError("every case needs explicit logs or metrics")
        cases.append((case, paths))
    return hashlib.sha256(raw).hexdigest(), cases


def analyze(case, paths, binary, timeout):
    with tempfile.TemporaryDirectory(prefix="evidentrail-local-eval-") as scratch:
        question_file = Path(scratch) / "question.txt"
        question_file.write_text(case["question"], encoding="utf-8")
        command = [str(binary), "analyze", "--question-file", str(question_file)]
        for field in ("metrics", "traces", "topology"):
            if field in paths:
                command.extend(["--" + field, str(paths[field])])
        if "metrics" in paths:
            command.extend(["--incident-time", str(case["incident_time"])])
        logs = paths["logs"].read_bytes() if "logs" in paths else b""
        env = os.environ.copy()
        env.pop("OPENAI_API_KEY", None)
        started = time.perf_counter()
        try:
            run = subprocess.run(command, input=logs, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"status": "product_error", "error_kind": "timeout"}
        elapsed = round(time.perf_counter() - started, 3)
        if run.returncode:
            return {"status": "product_error", "error_kind": "nonzero_exit",
                    "elapsed_seconds": elapsed}
    try:
        report = json.loads(run.stdout)
        if not isinstance(report, dict) or not isinstance(report.get("hypotheses"), list):
            raise ValueError("unexpected report shape")
        hypotheses = report["hypotheses"]
        top = hypotheses[0] if hypotheses else None
        service = case.get("expected_service")
        fault = case.get("expected_fault_type")
        incident = case["expected_status"] == "incident"
        return {
            "status": "completed", "report_status": report["status"],
            "elapsed_seconds": elapsed,
            "source_lines": report["source_line_count"],
            "alert_groups": report["alert_group_count"],
            "verified_highlights": len(report["model_highlights"]),
            "rejected_highlights": report["rejected_highlight_count"],
            "hypothesis_count": len(hypotheses), "abstained": not hypotheses,
            "needs_more_evidence": report["needs_more_evidence"],
            "citation_count": sum(len(item["evidence"]) for item in hypotheses),
            "rejected_hypotheses": report["rejected_hypothesis_count"],
            "service_hit": bool(top and top["service"] == service) if incident else None,
            "fault_hit": bool(top and top["fault_type"] == fault) if fault else None,
            "joint_hit": bool(top and top["service"] == service and
                              top["fault_type"] == fault) if fault else None,
        }
    except (KeyError, ValueError, TypeError, UnicodeDecodeError):
        return {"status": "product_error", "error_kind": "invalid_report",
                "elapsed_seconds": elapsed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/evidentrail"))
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    model = os.environ.get("EVIDENTRAIL_ANALYZE_LOCAL_MODEL")
    if not model:
        parser.error("set EVIDENTRAIL_ANALYZE_LOCAL_MODEL; hosted inference is disabled")
    if not 1 <= args.timeout_seconds <= 600:
        parser.error("timeout must be 1 to 600 seconds")
    digest, cases = validate_manifest(args.manifest)
    binary = args.binary.resolve(strict=True)
    header = {"schema_version": 1, "manifest_sha256": digest,
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "model": model, "case_count": len(cases), "backend": "ollama_local"}
    print(json.dumps(header, sort_keys=True), flush=True)
    rows = []
    for case, paths in cases:
        row = analyze(case, paths, binary, args.timeout_seconds)
        row["case_digest"] = hashlib.sha256((digest + ":" + case["id"]).encode()).hexdigest()[:16]
        row["expected_status"] = case["expected_status"]
        rows.append(row)
        print(json.dumps(row, sort_keys=True), flush=True)
    summary = {"summary": True, "cases": len(rows),
               "product_errors": sum(row["status"] == "product_error" for row in rows),
               "confirmed_incidents": sum(row["expected_status"] == "incident" for row in rows),
               "confirmed_service_hits": sum(row.get("service_hit") is True for row in rows),
               "confirmed_incident_abstentions": sum(row["expected_status"] == "incident"
                                                     and row.get("abstained") is True for row in rows),
               "fault_labeled_incidents": sum(case.get("expected_fault_type") is not None
                                              for case, _ in cases),
               "confirmed_joint_hits": sum(row.get("joint_hit") is True for row in rows),
               "unknown_or_healthy_cases": sum(row["expected_status"] != "incident" for row in rows),
               "unknown_or_healthy_abstentions": sum(row["expected_status"] != "incident"
                                                      and row.get("abstained") is True for row in rows),
               "unknown_or_healthy_false_attributions": sum(
                   row["expected_status"] != "incident" and row.get("abstained") is False
                   for row in rows)}
    print(json.dumps(summary, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"evaluation preflight failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
