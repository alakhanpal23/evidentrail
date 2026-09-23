#!/usr/bin/env python3
"""Probe log and optional metric evidence on pinned RCAEval cases.

Requires pyarrow. Downloads public Parquet into memory, sends a bounded NDJSON
window to `evidentrail analyze --selection-only`, and emits aggregate counts.
This is not a root-cause diagnosis benchmark: some injected faults have no
diagnostic log signature and require metrics or traces.
"""

import argparse
import io
import json
import math
import os
import subprocess
import tempfile
import time
import urllib.request

import pyarrow.parquet as parquet


REVISION = "afeacb11bcc94dadfd1c8f483ee4377b2b8b614e"
BASE = f"https://huggingface.co/datasets/phamquiluan/RCAEval/resolve/{REVISION}"
DEFAULT_CASES = [f"re2ss_catalogue_{fault}_1" for fault in ("cpu", "mem", "disk", "delay", "loss", "socket")]


def fetch(case, name):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(f"{BASE}/{case}/{name}", timeout=60) as response:
                return response.read()
        except (TimeoutError, ConnectionError):
            if attempt == 2:
                raise


def all_re2_ss_cases():
    with urllib.request.urlopen(f"{BASE}/cases.parquet", timeout=60) as response:
        index = parquet.read_table(io.BytesIO(response.read()), columns=["case", "dataset"])
    return sorted(row["case"] for row in index.to_pylist() if row["dataset"] == "RE2-SS")


def metric_fault_type(metric):
    if metric.startswith("latency-"):
        return "delay"
    return {"diskio": "disk", "error": "loss"}.get(metric, metric if metric in {"cpu", "mem", "socket"} else "unknown")


def metric_ndjson(case, injection, window):
    table = parquet.read_table(io.BytesIO(fetch(case, "metrics.parquet")))
    output = io.StringIO()
    for row in table.to_pylist():
        timestamp = row["time"]
        if abs(timestamp - injection) > window:
            continue
        for column, value in row.items():
            if column == "time" or value is None or not math.isfinite(value):
                continue
            service, metric = column.rsplit("_", 1)
            output.write(json.dumps({"timestamp": timestamp, "service": service, "metric": metric, "value": value}) + "\n")
    return output.getvalue().encode("utf-8")


def probe(case, binary, window, with_metrics, generic_question, metrics_only, live_model):
    root_service = case.split("_", 1)[1].rsplit("_", 2)[0]
    true_fault = case.rsplit("_", 2)[1]
    injection = int(fetch(case, "inject_time.txt"))
    if metrics_only:
        source = b""
    else:
        table = parquet.read_table(io.BytesIO(fetch(case, "logs.parquet")), columns=["timestamp", "container_name", "message"])
        rows = (
            row for row in table.to_pylist()
            if abs(row["timestamp"] - injection) <= window
        )
        source = b"".join(
            (json.dumps({"timestamp": row["timestamp"], "service": row["container_name"], "message": row["message"]}, ensure_ascii=False) + "\n").encode("utf-8")
            for row in rows
        )
    if (not source and not metrics_only) or len(source) > 16 * 1024 * 1024:
        return {"case": case, "status": "window_exceeds_product_limit", "source_bytes": len(source)}
    question = "Which service and failure mode caused this incident?" if generic_question else f"What caused {root_service} service degradation?"
    command = [binary, "analyze", "--question", question]
    if not live_model:
        command.append("--selection-only")
    with tempfile.TemporaryDirectory(prefix="evidentrail-rcaeval-") as scratch:
        if with_metrics:
            metrics = metric_ndjson(case, injection, window)
            if len(metrics) > 16 * 1024 * 1024:
                return {"case": case, "status": "metric_window_exceeds_product_limit", "metric_bytes": len(metrics)}
            metric_path = scratch + "/metrics.ndjson"
            with open(metric_path, "wb") as output:
                output.write(metrics)
            command.extend(["--metrics", metric_path, "--incident-time", str(injection)])
        start = time.perf_counter()
        run = subprocess.run(
            command,
            input=source,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        elapsed = time.perf_counter() - start
    if run.returncode:
        return {"case": case, "status": "product_error", "error_code": run.stderr.decode("utf-8", "replace").strip()}
    report = json.loads(run.stdout)
    root_signal = next(signal for signal in report["service_signals"] if signal["service"] == root_service)
    result = {
        "case": case,
        "status": report["status"],
        "source_lines": report["source_line_count"],
        "source_bytes": len(source),
        "alert_groups": report["alert_group_count"],
        "model_visible_groups": report["model_visible_group_count"],
        "omitted_groups": report["omitted_group_count"],
        "model_inventory_groups": report["model_inventory_group_count"],
        "omitted_inventory_groups": report["omitted_inventory_group_count"],
        "model_requested_groups": report["model_requested_group_count"],
        "expanded_groups": report["expanded_group_count"],
        "root_service": root_service,
        "root_service_alert_events": sum(root_signal[f"{role}_count"] for role in ("critical", "error", "warning", "change")),
        "root_service_alert_evidence": sum(event["service"] == root_service and event["role"] in ("critical", "error", "warning", "change") for event in report["evidence"]),
        "focus_log_signal_absent": report["focus_log_signal_absent"],
    }
    if with_metrics:
        root_metrics = [signal for signal in report["metric_signals"] if signal["service"] == root_service]
        strongest = max(root_metrics, key=lambda signal: signal["relative_shift"], default=None)
        naive = max(report["metric_signals"], key=lambda signal: signal["relative_shift"], default=None)
        result.update({
            "metric_source_lines": report["metric_source_line_count"],
            "metric_signals": report["metric_signal_count"],
            "visible_metric_signals": report["model_visible_metric_signal_count"],
            "root_metric_evidence": sum(event["service"] == root_service and event["role"] == "metric" for event in report["evidence"]),
            "root_largest_shift_metric": strongest["metric"] if strongest else None,
            "root_largest_relative_shift": round(strongest["relative_shift"], 3) if strongest else None,
            "root_largest_shift_visible": bool(strongest and {strongest["baseline_event_id"], strongest["incident_event_id"]} <= {event["id"] for event in report["evidence"]}),
            "naive_top_service": naive["service"] if naive else None,
            "naive_root_service_hit": bool(naive and naive["service"] == root_service),
            "naive_top_fault_type": metric_fault_type(naive["metric"]) if naive else None,
            "naive_fault_hit": bool(naive and metric_fault_type(naive["metric"]) == true_fault),
            "naive_joint_hit": bool(naive and naive["service"] == root_service and metric_fault_type(naive["metric"]) == true_fault),
        })
    if live_model:
        hypotheses = report["hypotheses"]
        result.update({
            "model_latency_seconds": round(elapsed, 3),
            "top1_service": hypotheses[0]["service"] if hypotheses else None,
            "top1_root_service_hit": bool(hypotheses and hypotheses[0]["service"] == root_service),
            "top1_fault_type": hypotheses[0]["fault_type"] if hypotheses else None,
            "top1_fault_hit": bool(hypotheses and hypotheses[0]["fault_type"] == true_fault),
            "top1_joint_hit": bool(hypotheses and hypotheses[0]["service"] == root_service and hypotheses[0]["fault_type"] == true_fault),
            "top3_root_service_hit": any(hypothesis["service"] == root_service for hypothesis in hypotheses),
            "top3_joint_hit": any(hypothesis["service"] == root_service and hypothesis["fault_type"] == true_fault for hypothesis in hypotheses),
            "hypothesis_count": len(hypotheses),
            "citation_count": sum(len(hypothesis["evidence"]) for hypothesis in hypotheses),
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/evidentrail")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--with-metrics", action="store_true")
    parser.add_argument("--metrics-only", action="store_true")
    parser.add_argument("--generic-question", action="store_true")
    parser.add_argument("--live-model", action="store_true")
    parser.add_argument("--all-re2-ss", action="store_true")
    parser.add_argument("cases", nargs="*")
    args = parser.parse_args()
    if args.window_seconds <= 0 or args.window_seconds > 600:
        parser.error("window must be between 1 and 600 seconds")
    if args.metrics_only and not args.with_metrics:
        parser.error("--metrics-only requires --with-metrics")
    if args.live_model and not (args.metrics_only and args.with_metrics and args.generic_question):
        parser.error("--live-model requires --metrics-only --with-metrics --generic-question")
    if args.live_model and not os.environ.get("OPENAI_API_KEY"):
        parser.error("--live-model requires OPENAI_API_KEY in the environment")
    if args.all_re2_ss and args.cases:
        parser.error("--all-re2-ss cannot be combined with explicit cases")
    if args.all_re2_ss and args.live_model:
        parser.error("--live-model requires an explicit case list")
    cases = all_re2_ss_cases() if args.all_re2_ss else (args.cases or DEFAULT_CASES)
    print(json.dumps({"dataset": "phamquiluan/RCAEval", "revision": REVISION, "window_seconds": args.window_seconds, "generic_question": args.generic_question, "metrics_only": args.metrics_only, "live_model": args.live_model, "case_count": len(cases)}))
    for case in cases:
        print(json.dumps(probe(case, args.binary, args.window_seconds, args.with_metrics, args.generic_question, args.metrics_only, args.live_model), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
