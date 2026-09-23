#!/usr/bin/env python3
"""Probe log-only evidence availability on pinned RCAEval cases.

Requires pyarrow. Downloads public Parquet into memory, sends a bounded NDJSON
window to `evidentrail analyze --selection-only`, and emits aggregate counts.
This is not a root-cause diagnosis benchmark: some injected faults have no
diagnostic log signature and require metrics or traces.
"""

import argparse
import io
import json
import subprocess
import urllib.request

import pyarrow.parquet as parquet


REVISION = "afeacb11bcc94dadfd1c8f483ee4377b2b8b614e"
BASE = f"https://huggingface.co/datasets/phamquiluan/RCAEval/resolve/{REVISION}"
DEFAULT_CASES = [f"re2ss_catalogue_{fault}_1" for fault in ("cpu", "mem", "disk", "delay", "loss", "socket")]


def fetch(case, name):
    with urllib.request.urlopen(f"{BASE}/{case}/{name}", timeout=30) as response:
        return response.read()


def probe(case, binary, window):
    root_service = case.removeprefix("re2ss_").rsplit("_", 2)[0]
    injection = int(fetch(case, "inject_time.txt"))
    table = parquet.read_table(io.BytesIO(fetch(case, "logs.parquet")), columns=["timestamp", "container_name", "message"])
    rows = (
        row for row in table.to_pylist()
        if abs(row["timestamp"] - injection) <= window
    )
    source = b"".join(
        (json.dumps({"timestamp": row["timestamp"], "service": row["container_name"], "message": row["message"]}, ensure_ascii=False) + "\n").encode("utf-8")
        for row in rows
    )
    if not source or len(source) > 16 * 1024 * 1024:
        return {"case": case, "status": "window_exceeds_product_limit", "source_bytes": len(source)}
    run = subprocess.run(
        [binary, "analyze", "--question", f"What caused {root_service} service degradation?", "--selection-only"],
        input=source,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if run.returncode:
        return {"case": case, "status": "product_error", "error_code": run.stderr.decode("utf-8", "replace").strip()}
    report = json.loads(run.stdout)
    root_signal = next(signal for signal in report["service_signals"] if signal["service"] == root_service)
    return {
        "case": case,
        "status": report["status"],
        "source_lines": report["source_line_count"],
        "source_bytes": len(source),
        "alert_groups": report["alert_group_count"],
        "model_visible_groups": report["model_visible_group_count"],
        "omitted_groups": report["omitted_group_count"],
        "root_service": root_service,
        "root_service_alert_events": sum(root_signal[f"{role}_count"] for role in ("critical", "error", "warning", "change")),
        "root_service_alert_evidence": sum(event["service"] == root_service and event["role"] != "context" for event in report["evidence"]),
        "focus_log_signal_absent": report["focus_log_signal_absent"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/evidentrail")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("cases", nargs="*", default=DEFAULT_CASES)
    args = parser.parse_args()
    if args.window_seconds <= 0 or args.window_seconds > 600:
        parser.error("window must be between 1 and 600 seconds")
    print(json.dumps({"dataset": "phamquiluan/RCAEval", "revision": REVISION, "window_seconds": args.window_seconds}))
    for case in args.cases:
        print(json.dumps(probe(case, args.binary, args.window_seconds), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
