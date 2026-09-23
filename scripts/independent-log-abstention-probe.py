#!/usr/bin/env python3
"""Evaluate exact log lines from a pinned independent 18-case incident set.

This is a log-only test. The source's metrics and traces are already summarized,
so they are deliberately excluded rather than presented as raw product inputs.
Only aggregate counts and case IDs are written; raw logs stay in memory.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request


REVISION = "89db617170f3b2fe560d31f3790cf2678d5d82be"
URL = f"https://raw.githubusercontent.com/PhyByte/LLM-SRE-Bench/{REVISION}/datasets/data/multimodal_rca.json"
SHA256 = "0b5aaffb403bc2723e281093f2883185293be2eefe62ab82a521cf59f017795f"
QUESTION = "Which service, if any, caused the incident? Give only hypotheses supported by these logs; abstain if the logs do not identify a cause or show no incident."


def load_cases(path):
    data = open(path, "rb").read() if path else urllib.request.urlopen(URL, timeout=60).read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise ValueError(f"dataset SHA-256 mismatch: {digest}")
    cases = json.loads(data)
    if len(cases) != 18 or len({case["id"] for case in cases}) != 18:
        raise ValueError("expected 18 unique cases")
    return cases


def probe(case, binary, live):
    logs = case["modalities"]["logs"]
    if len(logs) != 30 or any(not isinstance(line, str) or "\n" in line for line in logs):
        raise ValueError(f"unexpected log shape for {case['id']}")
    command = [binary, "analyze", "--question", QUESTION]
    if not live:
        command.append("--selection-only")
    run = subprocess.run(command, input=("\n".join(logs) + "\n").encode(),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    if run.returncode:
        return {"case": case["id"], "status": "product_error",
                "error_code": run.stderr.decode("utf-8", "replace").strip()[:300]}
    report = json.loads(run.stdout)
    truth = case["ground_truth"]["culprit_service"]
    positive = truth not in ("unknown", "none")
    service_signals = {signal["service"]: signal for signal in report["service_signals"]}
    root = service_signals.get(truth)
    row = {"case": case["id"], "status": report["status"], "positive": positive,
           "log_informative": "logs" in case["ground_truth"]["informative_modalities"],
           "ground_truth_status": "incident" if positive else truth,
           "source_lines": report["source_line_count"],
           "parsed_services": len(service_signals) - ("unknown" in service_signals),
           "root_service_parsed": bool(root) if positive else None,
           "root_alert_events": sum(root[f"{role}_count"] for role in
                                    ("critical", "error", "warning", "change")) if root else None,
           "alert_groups": report["alert_group_count"],
           "visible_groups": report["model_visible_group_count"],
           "rejected_hypotheses": report["rejected_hypothesis_count"]}
    if live:
        hypotheses = report["hypotheses"]
        row.update({"hypothesis_count": len(hypotheses),
                    "abstained": not hypotheses,
                    "top1_service_hit": bool(hypotheses and hypotheses[0]["service"] == truth) if positive else None,
                    "top1_support_scope": report["hypothesis_support"][0]["scope"] if hypotheses else None,
                    "needs_more_evidence": report["needs_more_evidence"],
                    "citation_count": sum(len(h["evidence"]) for h in hypotheses)})
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", help="local copy of pinned public JSON")
    parser.add_argument("--binary", default="target/debug/evidentrail")
    parser.add_argument("--live-model", action="store_true", help="use a local Ollama model")
    args = parser.parse_args()
    if args.live_model and not os.environ.get("EVIDENTRAIL_ANALYZE_LOCAL_MODEL"):
        parser.error("live evaluation requires EVIDENTRAIL_ANALYZE_LOCAL_MODEL")
    cases = load_cases(args.dataset)
    header = {"dataset": "PhyByte/LLM-SRE-Bench", "revision": REVISION,
              "dataset_sha256": SHA256, "case_count": len(cases),
              "mode": "log_only_live" if args.live_model else "log_only_selection",
              "model": os.environ.get("EVIDENTRAIL_ANALYZE_LOCAL_MODEL") if args.live_model else None,
              "evidentrail_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "binary_sha256": hashlib.sha256(open(args.binary, "rb").read()).hexdigest(),
              "worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], text=True).strip())}
    print(json.dumps(header, sort_keys=True), flush=True)
    for case in cases:
        print(json.dumps(probe(case, args.binary, args.live_model), sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"probe failed: {error}", file=sys.stderr)
        sys.exit(1)
