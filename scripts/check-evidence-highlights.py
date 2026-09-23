#!/usr/bin/env python3
"""Run a local-model, source-exact evidence-brief smoke test."""

import argparse
import hashlib
import json
import os
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/evidentrail")
    args = parser.parse_args()
    if not os.environ.get("EVIDENTRAIL_ANALYZE_LOCAL_MODEL"):
        parser.error("set EVIDENTRAIL_ANALYZE_LOCAL_MODEL to an installed local model")

    lines = [
        f"[ads] WARN: retry scheduled for low-priority refresh trace_id={index:06x}".encode()
        for index in range(500)
    ]
    lines.extend([
        b"[frontend] ERROR: checkoutservice timed out",
        b"[checkoutservice] ERROR: database connection refused",
        b"[database] ERROR: disk full on orders volume",
    ])
    run = subprocess.run(
        [args.binary, "analyze", "--question", "What evidence matters for checkout failures?"],
        input=b"\n".join(lines) + b"\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=True,
    )
    report = json.loads(run.stdout)
    assert report["source_line_count"] == 503
    assert report["alert_group_count"] == 4
    ads = [group for group in report["alert_groups"] if group["service"] == "ads"]
    assert len(ads) == 1 and ads[0]["count"] == 500
    seen_groups = set()
    for highlight in report["model_highlights"]:
        event = highlight["event"]
        index = int(event["id"][1:]) - 1
        assert 0 <= index < len(lines)
        assert event["source_sha256"] == hashlib.sha256(lines[index]).hexdigest()
        assert lines[index].decode().startswith(event["sample"])
        group_id = highlight["group_id"]
        assert group_id and group_id not in seen_groups
        seen_groups.add(group_id)
        assert highlight["repeated_event_count"] == next(
            group["count"] for group in report["alert_groups"] if group["id"] == group_id
        )
    print(json.dumps({
        "source_lines": report["source_line_count"],
        "alert_groups": report["alert_group_count"],
        "repeated_warning_events": ads[0]["count"],
        "verified_highlights": len(report["model_highlights"]),
        "rejected_highlights": report["rejected_highlight_count"],
        "hypothesis_count": len(report["hypotheses"]),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
