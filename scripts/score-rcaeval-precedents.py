#!/usr/bin/env python3
"""Exploratory RCAEval incident-precedent baseline, using numeric aggregates only.

Train on replicate 1 of each RE2 service/fault pair, then score
replicates 2 and 3. The query service is the paired largest-metric-shift
baseline. Equal-weight log1p metric-family shifts are compared by squared
Euclidean distance. This evaluates whether labeled prior incidents are worth
investigating; it is not an Evidentrail model or a held-out product score.
"""

import argparse
import json
import math
import sys
from collections import Counter


REVISION = "afeacb11bcc94dadfd1c8f483ee4377b2b8b614e"
FAULTS = ("cpu", "mem", "disk", "delay", "loss", "socket")


def features(row, service):
    by_service = row["service_fault_family_shifts"].get(service, {})
    return tuple(math.log1p(by_service.get(fault, 0.0)) for fault in FAULTS)


def score(path, exclude_same_service=False):
    with open(path, encoding="utf-8") as source:
        header, *rows = [json.loads(line) for line in source if line.strip()]
    if (
        header.get("dataset") != "phamquiluan/RCAEval"
        or header.get("revision") != REVISION
        or header.get("case_count") != 90
        or header.get("metrics_only") is not True
        or header.get("generic_question") is not True
        or header.get("live_model") is not False
        or len(rows) != 90
    ):
        raise ValueError("expected a complete pinned RE2 metric-only probe")
    case_names = [row.get("case") for row in rows]
    if any(not isinstance(name, str) for name in case_names):
        raise ValueError("case names are missing")
    prefixes = {name.split("_", 1)[0] for name in case_names}
    if prefixes not in ({"re2ss"}, {"re2ob"}, {"re2tt"}):
        raise ValueError("expected one RE2 dataset")
    prefix = next(iter(prefixes))
    services = {name.split("_", 1)[1].rsplit("_", 2)[0] for name in case_names}
    if len(services) != 5:
        raise ValueError("expected five labeled root services")
    expected = {f"{prefix}_{service}_{fault}_{replicate}" for service in services for fault in FAULTS for replicate in (1, 2, 3)}
    if set(case_names) != expected or len(set(case_names)) != 90:
        raise ValueError("case names are incomplete or duplicated")
    for row in rows:
        service = row["case"].split("_", 1)[1].rsplit("_", 2)[0]
        if (
            row.get("status") not in ("partial", "source_linked_hypotheses")
            or row.get("root_service") != service
            or not isinstance(row.get("naive_top_service"), str)
            or not row["naive_top_service"]
            or type(row.get("naive_joint_hit")) is not bool
            or not isinstance(row.get("service_fault_family_shifts"), dict)
        ):
            raise ValueError(f"invalid aggregate for {row['case']}")
        for shifts in row["service_fault_family_shifts"].values():
            if not isinstance(shifts, dict) or any(
                fault not in FAULTS or type(value) not in (int, float)
                or not math.isfinite(value) or value < 0
                for fault, value in shifts.items()
            ):
                raise ValueError(f"invalid metric-family shifts for {row['case']}")
    training = sorted((row for row in rows if row["case"].endswith("_1")), key=lambda row: row["case"])
    held_out = sorted((row for row in rows if not row["case"].endswith("_1")), key=lambda row: row["case"])
    counts = Counter()
    by_fault = {}
    for row in held_out:
        service = row["naive_top_service"]
        query = features(row, service)
        candidates = [
            prior for prior in training
            if (prior["root_service"] != service if exclude_same_service else prior["root_service"] == service)
        ]
        if not candidates:
            candidates = training
        prior = min(candidates, key=lambda prior: sum(
            (left - right) ** 2 for left, right in zip(query, features(prior, prior["root_service"]))
        ))
        predicted_fault = prior["case"].rsplit("_", 2)[1]
        true_fault = row["case"].rsplit("_", 2)[1]
        joint = service == row["root_service"] and predicted_fault == true_fault
        bucket = by_fault.setdefault(true_fault, Counter())
        for target in (counts, bucket):
            target["cases"] += 1
            target["service_hits"] += service == row["root_service"]
            target["joint_hits"] += joint
            target["naive_joint_hits"] += row["naive_joint_hit"]
        counts["precedent_only_joint_hits"] += joint and not row["naive_joint_hit"]
        counts["naive_only_joint_hits"] += row["naive_joint_hit"] and not joint
    return {
        "dataset": header["dataset"],
        "benchmark": {"re2ss": "RE2-SS", "re2ob": "RE2-OB", "re2tt": "RE2-TT"}[prefix],
        "revision": header["revision"],
        "training_replicate": 1,
        "test_replicates": [2, 3],
        "exclude_same_service": exclude_same_service,
        "feature": "equal_weight_log1p_max_relative_shift_by_metric_family",
        "cases": counts["cases"],
        "service_hits": counts["service_hits"],
        "precedent_joint_hits": counts["joint_hits"],
        "naive_joint_hits": counts["naive_joint_hits"],
        "precedent_only_joint_hits": counts["precedent_only_joint_hits"],
        "naive_only_joint_hits": counts["naive_only_joint_hits"],
        "by_fault": {fault: dict(by_fault[fault]) for fault in FAULTS},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="complete selection-only RE2 Sock Shop JSONL")
    parser.add_argument("--exclude-same-service", action="store_true")
    args = parser.parse_args()
    try:
        result = score(args.run, args.exclude_same_service)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"unscorable precedent run: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
