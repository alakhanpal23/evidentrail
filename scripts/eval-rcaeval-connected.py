#!/usr/bin/env python3
"""Run opt-in connected log-only probes on pinned RCAEval cases.

Requires pyarrow. Raw telemetry stays in a temporary directory and is never
printed or committed. The Rust test consumes deterministic NDJSON rows derived
from the original Parquet columns, without an incident time window. The
--labeled arm checks seven Sock Shop cases with a unique published root-cause
message in their logs; one eighth published label is absent from its case's
logs and is excluded.
"""

import hashlib
import io
import json
import os
import argparse
import csv
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import pyarrow.parquet as parquet


REVISION = "afeacb11bcc94dadfd1c8f483ee4377b2b8b614e"
OB_CASES = {
    "re3ob_cartservice_f1_1": "daba5217f71f5a595e28cf9d5a3bda414d6e0cfaf19aa754a24aad9c14677a63",
    "re3ob_emailservice_f1_1": "463675c417315ef5538c4b728698e6964bf0fe618daa94f06693f4f54989d511",
    "re3ob_adservice_f3_1": "d8fb490a359db7cda3ce618ce51251ceec89b90026839f90a891391e3d51b197",
}
LABELED_SS_CASES = {
    "re3ss_carts_f1_1": ("eea9d351ff71dbd1eb2bf77a39db60dc8dc1cead962d8672ffb41627dae9bfbb", "915d20898a9754a00cf72a613065c3c01c04e5389766c88c260ba2fe845f3e4a"),
    "re3ss_carts_f1_2": ("16d8033bc7d9e101daf1ce83e7e75843fa9bded56ce73a90bb273e888a76c0c2", "30316bb9d8ae5468fce02d76cd563416c48391f9c4ce60204471bc4f083c3c58"),
    "re3ss_carts_f3_1": ("c72c766c9c8e31bb86b31335f9ead45b8cbd02d8a740533acd6aaddfa637ac64", "4c3137730b0d7cdc429930e06b39e99b1484fdf99fc327648df02ff12d9a4d29"),
    "re3ss_carts_f3_2": ("0d7036d08718795a12e80aa03c7c3b40edd1fadff50a955641e671d8606e8893", "ee7fae08f73b54c14e894faf04744c96df72d12f5260e8eb1389cac760c5050a"),
    "re3ss_front-end_f1_1": ("6ed259a535292904a22ff8b3a3d73cd81a8aadc83b795d2f26349e7909620e2c", "692cbf1c099c9a2f4ebbf7cfe19f52957181bce9420a10addbbb35dd719915a3"),
    "re3ss_front-end_f1_2": ("dbe7d0a36a955faeebd4e29ddd05c67b2d18d855fed7170bcfb06bde3ce046f8", "c8d3e029b25c4eee5bb5c5111f2b7d53524db0c621619f70a67ffbb28ae4614e"),
    "re3ss_front-end_f2_1": ("2172b7ebc80200690a053649d5143a1dea5d8ff53d2df010c774b9d2e893cd9f", "566020879db4c3b8a1bc3ee3302c9e032ff6960acad85927e86f0afa965a7845"),
}
INDEX_SHA256 = "c49a288920dbba2e8e724679a14636d5c7eb2b45426bba14007ef79a6c0ab1bb"


def load_labels(cases, labeled):
    url = f"https://huggingface.co/datasets/phamquiluan/RCAEval/resolve/{REVISION}/cases.parquet"
    with urllib.request.urlopen(url, timeout=60) as response:
        source = response.read()
    if hashlib.sha256(source).hexdigest() != INDEX_SHA256:
        raise ValueError("pinned RCAEval case index changed")
    index = parquet.read_table(
        io.BytesIO(source),
        columns=["case", "root_cause_service", "inject_time", "n_logs", "has_root_cause_file"],
    )
    labels = {row["case"]: row for row in index.to_pylist() if row["case"] in cases}
    if len(labels) != len(cases) or any(
        not isinstance(row["root_cause_service"], str)
        or not isinstance(row["inject_time"], int)
        or row["has_root_cause_file"] is not labeled
        for row in labels.values()
    ):
        raise ValueError("RCAEval case labels do not match the pinned probe")
    return labels


def prepare(directory, labeled=False, case_filter=None):
    cases = LABELED_SS_CASES if labeled else OB_CASES
    if case_filter is not None:
        if case_filter not in cases:
            raise ValueError(f"case not in selected probe: {case_filter}")
        cases = {case_filter: cases[case_filter]}
    labels = load_labels(cases, labeled)
    for case, expected in cases.items():
        expected_sha256 = expected[0] if labeled else expected
        if labeled:
            root_url = f"https://huggingface.co/datasets/phamquiluan/RCAEval/resolve/{REVISION}/{case}/root_cause.txt"
            with urllib.request.urlopen(root_url, timeout=60) as response:
                root_source = response.read()
            if hashlib.sha256(root_source).hexdigest() != expected[1]:
                raise ValueError(f"pinned RCAEval root line changed: {case}")
            root_fields = next(csv.reader(io.StringIO(root_source.decode("utf-8"))))
            if len(root_fields) != 6 or root_fields[2] != labels[case]["root_cause_service"]:
                raise ValueError(f"invalid RCAEval root line: {case}")
            labels[case]["root_message"] = root_fields[3]
        url = f"https://huggingface.co/datasets/phamquiluan/RCAEval/resolve/{REVISION}/{case}/logs.parquet"
        with urllib.request.urlopen(url, timeout=60) as response:
            source = response.read()
        if hashlib.sha256(source).hexdigest() != expected_sha256:
            raise ValueError(f"pinned RCAEval content changed: {case}")
        table = parquet.read_table(
            io.BytesIO(source), columns=["timestamp", "container_name", "message"]
        )
        if table.num_rows != labels[case]["n_logs"]:
            raise ValueError(f"RCAEval index log count mismatch: {case}")
        root_matches = 0
        with (directory / f"{case}.jsonl").open("wb") as output:
            for row in table.to_pylist():
                if not isinstance(row["timestamp"], int) or not isinstance(row["container_name"], str) or (row["message"] is not None and not isinstance(row["message"], str)):
                    raise ValueError(f"invalid RCAEval log row: {case}")
                if labeled and row["container_name"] == labels[case]["root_cause_service"] and row["message"] == labels[case]["root_message"]:
                    root_matches += 1
                output.write(
                    (
                        json.dumps(
                            {
                                "timestamp": row["timestamp"],
                                "service": row["container_name"],
                                "message": row["message"],
                            },
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("utf-8")
                )
        if labeled and root_matches != 1:
            raise ValueError(f"expected one root line in RCAEval logs, got {root_matches}: {case}")
        print(f"prepared {case}: {table.num_rows} log records", flush=True)
    (directory / "labels.json").write_text(json.dumps(labels, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", action="store_true", help="also run the actual local or hosted log selector")
    parser.add_argument("--labeled", action="store_true", help="use seven Sock Shop cases with an exact root-cause log-line label")
    parser.add_argument("--case", help="run one pinned case for a focused local probe")
    args = parser.parse_args()
    if args.model and not (os.environ.get("EVIDENTRAIL_COMPACT_LOCAL_MODEL") or os.environ.get("OPENAI_API_KEY")):
        parser.error("--model requires EVIDENTRAIL_COMPACT_LOCAL_MODEL or OPENAI_API_KEY")
    with tempfile.TemporaryDirectory(prefix="evidentrail-rcaeval-connected-") as scratch:
        directory = Path(scratch)
        prepare(directory, labeled=args.labeled, case_filter=args.case)
        environment = os.environ.copy()
        environment["EVIDENTRAIL_RCAEVAL_CONNECTED_DIR"] = str(directory)
        if args.model:
            environment["EVIDENTRAIL_RUN_RCAEVAL_MODEL_EVAL"] = "1"
        subprocess.run(
            [
                "cargo",
                "test",
                "-p",
                "evidentrail-cli",
                "--lib",
                "rcaeval_connected_log_only_probe",
                "--",
                "--ignored",
                "--nocapture",
            ],
            check=True,
            env=environment,
        )


if __name__ == "__main__":
    main()
