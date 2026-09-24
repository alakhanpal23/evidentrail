#!/usr/bin/env python3
"""Run the opt-in connected log-only probe on three pinned RCAEval cases.

Requires pyarrow. Raw telemetry stays in a temporary directory and is never
printed or committed. The Rust test consumes deterministic NDJSON rows derived
from the original Parquet columns, without an incident time window.
"""

import hashlib
import io
import json
import os
import argparse
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import pyarrow.parquet as parquet


REVISION = "afeacb11bcc94dadfd1c8f483ee4377b2b8b614e"
CASES = {
    "re3ob_cartservice_f1_1": "daba5217f71f5a595e28cf9d5a3bda414d6e0cfaf19aa754a24aad9c14677a63",
    "re3ob_emailservice_f1_1": "463675c417315ef5538c4b728698e6964bf0fe618daa94f06693f4f54989d511",
    "re3ob_adservice_f3_1": "d8fb490a359db7cda3ce618ce51251ceec89b90026839f90a891391e3d51b197",
}


def prepare(directory):
    for case, expected_sha256 in CASES.items():
        url = f"https://huggingface.co/datasets/phamquiluan/RCAEval/resolve/{REVISION}/{case}/logs.parquet"
        with urllib.request.urlopen(url, timeout=60) as response:
            source = response.read()
        if hashlib.sha256(source).hexdigest() != expected_sha256:
            raise ValueError(f"pinned RCAEval content changed: {case}")
        table = parquet.read_table(
            io.BytesIO(source), columns=["timestamp", "container_name", "message"]
        )
        with (directory / f"{case}.jsonl").open("wb") as output:
            for row in table.to_pylist():
                if not isinstance(row["timestamp"], int) or not isinstance(row["container_name"], str) or not isinstance(row["message"], str):
                    raise ValueError(f"invalid RCAEval log row: {case}")
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
        print(f"prepared {case}: {table.num_rows} log records", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", action="store_true", help="also run the actual local or hosted log selector")
    args = parser.parse_args()
    if args.model and not (os.environ.get("EVIDENTRAIL_COMPACT_LOCAL_MODEL") or os.environ.get("OPENAI_API_KEY")):
        parser.error("--model requires EVIDENTRAIL_COMPACT_LOCAL_MODEL or OPENAI_API_KEY")
    with tempfile.TemporaryDirectory(prefix="evidentrail-rcaeval-connected-") as scratch:
        directory = Path(scratch)
        prepare(directory)
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
