#!/usr/bin/env python3
"""Score a complete live RCAEval JSONL run against the paired naive baseline.

Input is the aggregate output of rcaeval-log-probe.py. No raw telemetry or
model explanations are read or printed. Invalid, duplicate, or failed cases
make the run unscorable rather than silently shrinking its denominator.
"""

import argparse
import json
import math
import sys
from collections import Counter


REVISION = "afeacb11bcc94dadfd1c8f483ee4377b2b8b614e"


def score(path):
    with open(path, encoding="utf-8") as source:
        lines = [json.loads(line) for line in source if line.strip()]
    if len(lines) < 2:
        raise ValueError("expected a probe header and at least one case")
    header, *rows = lines
    if (
        header.get("revision") != REVISION
        or header.get("dataset") != "phamquiluan/RCAEval"
        or header.get("live_model") is not True
        or type(header.get("metrics_only")) is not bool
        or header.get("generic_question") is not True
        or header.get("model_backend") not in {"ollama_local", "openai_hosted"}
        or not isinstance(header.get("model_name"), str)
        or not header["model_name"]
    ):
        raise ValueError("not a pinned live, generic-question RCAEval run")
    if not header["metrics_only"] and header["model_backend"] != "ollama_local":
        raise ValueError("live public-log runs must use a local model")
    for digest_field, expected_length in (("evidentrail_revision", 40), ("binary_sha256", 64)):
        digest = header.get(digest_field)
        if digest is not None and (not isinstance(digest, str) or len(digest) != expected_length or any(ch not in "0123456789abcdef" for ch in digest)):
            raise ValueError(f"invalid {digest_field} in probe header")
    if "worktree_dirty" in header and type(header["worktree_dirty"]) is not bool:
        raise ValueError("invalid worktree_dirty in probe header")
    if header.get("case_count") != len(rows):
        raise ValueError("case count does not match the probe header")
    case_names = [row.get("case") for row in rows]
    if any(not isinstance(name, str) for name in case_names) or len(set(case_names)) != len(rows):
        raise ValueError("case names are missing or duplicated")
    if any(
        len(name.rsplit("_", 2)) != 3
        or name.rsplit("_", 2)[1] not in {"cpu", "mem", "disk", "delay", "loss", "socket"}
        for name in case_names
    ):
        raise ValueError("case names do not encode a supported fault")
    failures = [row["case"] for row in rows if row.get("status") == "product_error"]
    if failures:
        raise ValueError(f"{len(failures)} product errors; score the complete run after resolving them")
    fields = (
        "naive_joint_hit", "top1_joint_hit", "top3_joint_hit",
        "top1_root_service_hit", "top1_fault_hit", "citation_count",
        "model_latency_seconds", "hypothesis_count", "top1_support_scope",
        "direct_hypothesis_count", "dependent_only_hypothesis_count",
        "top1_fault_type", "model_needs_more_evidence",
    )
    for row in rows:
        if row.get("status") not in {"partial", "source_linked_hypotheses"}:
            raise ValueError(f"case {row['case']} has no successful analysis status")
        if any(field not in row for field in fields):
            raise ValueError(f"case {row['case']} lacks live score fields")
        if any(type(row[field]) is not bool for field in fields[:5]):
            raise ValueError(f"case {row['case']} has invalid hit fields")
        if (
            any(type(row[field]) is not int or row[field] < 0 for field in (
                "citation_count", "hypothesis_count", "direct_hypothesis_count",
                "dependent_only_hypothesis_count",
            ))
            or type(row["model_latency_seconds"]) not in (int, float)
            or not math.isfinite(row["model_latency_seconds"])
            or row["model_latency_seconds"] < 0
            or row["citation_count"] < row["hypothesis_count"]
            or row["direct_hypothesis_count"] + row["dependent_only_hypothesis_count"] != row["hypothesis_count"]
            or row["top1_support_scope"] not in ({"direct", "dependent_only"} if row["hypothesis_count"] else {None})
            or row["top1_fault_type"] not in ({"cpu", "mem", "disk", "delay", "loss", "socket", "other", "unknown"} if row["hypothesis_count"] else {None})
            or type(row["model_needs_more_evidence"]) is not bool
            or (row["hypothesis_count"] == 0 and not row["model_needs_more_evidence"])
            or (row["top1_fault_type"] == "unknown" and (row["top1_fault_hit"] or row["top1_joint_hit"]))
        ):
            raise ValueError(f"case {row['case']} has invalid count or latency")
        if not header["metrics_only"]:
            challenge_fields = (
                "metric_challenger_attempted", "metric_challenger_failed",
                "metric_disagreement", "top1_origin", "redacted_log_events",
                "rejected_hypothesis_count",
            )
            if any(field not in row for field in challenge_fields):
                raise ValueError(f"case {row['case']} lacks combined-run fields")
            if (
                any(type(row[field]) is not bool for field in challenge_fields[:3])
                or row["top1_origin"] not in ("combined", "metric_challenger", None)
                or type(row["redacted_log_events"]) is not int
                or row["redacted_log_events"] < 0
                or type(row["rejected_hypothesis_count"]) is not int
                or row["rejected_hypothesis_count"] < 0
                or type(row.get("rejected_group_requests", 0)) is not int
                or row.get("rejected_group_requests", 0) < 0
                or (row["metric_challenger_failed"] and not row["metric_challenger_attempted"])
                or (row["metric_disagreement"] and not row["metric_challenger_attempted"])
                or (row["top1_origin"] == "metric_challenger" and not row["metric_disagreement"])
            ):
                raise ValueError(f"case {row['case']} has invalid combined-run fields")
    counts = Counter()
    by_fault = {}
    for row in rows:
        fault = row["case"].rsplit("_", 2)[1]
        bucket = by_fault.setdefault(fault, Counter())
        for target in (counts, bucket):
            target["cases"] += 1
            for field in fields[:5]:
                target[field] += row[field]
        if row["top1_joint_hit"] and not row["naive_joint_hit"]:
            counts["model_only_joint_hits"] += 1
        if row["naive_joint_hit"] and not row["top1_joint_hit"]:
            counts["naive_only_joint_hits"] += 1
        if row["hypothesis_count"] == 0:
            counts["abstentions"] += 1
        elif row["top1_fault_type"] == "unknown":
            counts["top1_unknown_fault_types"] += 1
        if row["model_needs_more_evidence"]:
            counts["needs_more_evidence"] += 1
        counts["citations"] += row["citation_count"]
        counts["direct_hypotheses"] += row["direct_hypothesis_count"]
        counts["dependent_only_hypotheses"] += row["dependent_only_hypothesis_count"]
        counts["top1_direct_support"] += row["top1_support_scope"] == "direct"
        counts["latency_seconds"] += row["model_latency_seconds"]
        if not header["metrics_only"]:
            counts["metric_challenger_attempts"] += row["metric_challenger_attempted"]
            counts["metric_challenger_failures"] += row["metric_challenger_failed"]
            counts["metric_disagreements"] += row["metric_disagreement"]
            counts["metric_challenger_top1"] += row["top1_origin"] == "metric_challenger"
            counts["redacted_log_events"] += row["redacted_log_events"]
            counts["rejected_hypotheses"] += row["rejected_hypothesis_count"]
            counts["rejected_group_requests"] += row.get("rejected_group_requests", 0)
    return {
        "dataset": header["dataset"],
        "revision": header["revision"],
        "evidentrail_revision": header.get("evidentrail_revision"),
        "binary_sha256": header.get("binary_sha256"),
        "worktree_dirty": header.get("worktree_dirty"),
        "model_backend": header["model_backend"],
        "model_name": header["model_name"],
        "metrics_only": header["metrics_only"],
        "case_count": counts["cases"],
        "naive_top1_joint_hits": counts["naive_joint_hit"],
        "model_top1_joint_hits": counts["top1_joint_hit"],
        "model_top3_joint_hits": counts["top3_joint_hit"],
        "model_top1_service_hits": counts["top1_root_service_hit"],
        "model_top1_fault_hits": counts["top1_fault_hit"],
        "model_only_joint_hits": counts["model_only_joint_hits"],
        "naive_only_joint_hits": counts["naive_only_joint_hits"],
        "abstentions": counts["abstentions"],
        "top1_unknown_fault_types": counts["top1_unknown_fault_types"],
        "top1_specific_fault_types": counts["cases"] - counts["abstentions"] - counts["top1_unknown_fault_types"],
        "needs_more_evidence": counts["needs_more_evidence"],
        "citation_count": counts["citations"],
        "direct_hypotheses": counts["direct_hypotheses"],
        "dependent_only_hypotheses": counts["dependent_only_hypotheses"],
        "top1_direct_support": counts["top1_direct_support"],
        "mean_model_latency_seconds": round(counts["latency_seconds"] / counts["cases"], 3),
        "metric_challenger_attempts": counts["metric_challenger_attempts"] if not header["metrics_only"] else None,
        "metric_challenger_failures": counts["metric_challenger_failures"] if not header["metrics_only"] else None,
        "metric_disagreements": counts["metric_disagreements"] if not header["metrics_only"] else None,
        "metric_challenger_top1": counts["metric_challenger_top1"] if not header["metrics_only"] else None,
        "redacted_log_events": counts["redacted_log_events"] if not header["metrics_only"] else None,
        "rejected_hypotheses": counts["rejected_hypotheses"] if not header["metrics_only"] else None,
        "rejected_group_requests": counts["rejected_group_requests"] if not header["metrics_only"] else None,
        "by_fault": {fault: dict(values) for fault, values in sorted(by_fault.items())},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="JSONL output from a complete --live-model probe")
    args = parser.parse_args()
    try:
        result = score(args.run)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"unscorable run: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
