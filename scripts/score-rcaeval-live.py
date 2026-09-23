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
        or header.get("metrics_only") is not True
        or header.get("generic_question") is not True
    ):
        raise ValueError("not a pinned live, generic-question, metric-only RCAEval run")
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
        "model_latency_seconds", "hypothesis_count",
    )
    for row in rows:
        if row.get("status") not in {"partial", "source_linked_hypotheses"}:
            raise ValueError(f"case {row['case']} has no successful analysis status")
        if any(field not in row for field in fields):
            raise ValueError(f"case {row['case']} lacks live score fields")
        if any(type(row[field]) is not bool for field in fields[:5]):
            raise ValueError(f"case {row['case']} has invalid hit fields")
        if (
            any(type(row[field]) is not int or row[field] < 0 for field in ("citation_count", "hypothesis_count"))
            or type(row["model_latency_seconds"]) not in (int, float)
            or not math.isfinite(row["model_latency_seconds"])
            or row["model_latency_seconds"] < 0
            or row["citation_count"] < row["hypothesis_count"]
        ):
            raise ValueError(f"case {row['case']} has invalid count or latency")
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
        counts["citations"] += row["citation_count"]
        counts["latency_seconds"] += row["model_latency_seconds"]
    return {
        "dataset": header["dataset"],
        "revision": header["revision"],
        "case_count": counts["cases"],
        "naive_top1_joint_hits": counts["naive_joint_hit"],
        "model_top1_joint_hits": counts["top1_joint_hit"],
        "model_top3_joint_hits": counts["top3_joint_hit"],
        "model_top1_service_hits": counts["top1_root_service_hit"],
        "model_top1_fault_hits": counts["top1_fault_hit"],
        "model_only_joint_hits": counts["model_only_joint_hits"],
        "naive_only_joint_hits": counts["naive_only_joint_hits"],
        "abstentions": counts["abstentions"],
        "citation_count": counts["citations"],
        "mean_model_latency_seconds": round(counts["latency_seconds"] / counts["cases"], 3),
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
