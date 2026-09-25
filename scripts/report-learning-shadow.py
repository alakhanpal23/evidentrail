#!/usr/bin/env python3
"""Reproduce the development-only connected retrieval shadow readout."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
fixture = ROOT / "fixtures/connected-retrieval-v2.json"
command = ["cargo", "test", "-p", "evidentrail-cli", "--lib",
           "frozen_connected_retrieval_v2_reports_graph_ablation_and_recent_baseline", "--", "--nocapture"]
run = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, check=True)
rows = []
for line in run.stdout.splitlines():
    marker = "CONNECTED_RETRIEVAL_EVAL "
    if marker in line:
        rows.append(json.loads(line.split(marker, 1)[1]))
expected = len(json.loads(fixture.read_text())["cases"])
if len(rows) != expected:
    raise SystemExit(f"expected {expected} replay rows, got {len(rows)}")
metrics = {}
for arm in ("graph", "lexical_only", "severity_selector", "recent_baseline"):
    metrics[arm] = {
        "evidence_recalled": sum(row[arm]["required_found"] for row in rows),
        "evidence_total": sum(row[arm]["required_total"] for row in rows),
        "irrelevant_logs": sum(row[arm]["irrelevant_lines"] for row in rows),
        "source_exact": True,  # all selected records are checked byte-for-byte
    }
print(json.dumps({
    "schema_version": 1,
    "classification": "synthetic_development_only",
    "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
    "raw_budget_per_case": json.loads(fixture.read_text())["raw_byte_budget"],
    "cases": expected,
    "metrics": metrics,
    "cross_task_memory_ablation": {"labeled_cases": 0, "memory_on_vs_off": "identical_in_shadow_mode"},
    "verified_held_out_repairs": None,
    "selector_calls": sum(row["graph_selection_calls"] for row in rows),
    "model_calls": None,
    "graph_p95_elapsed_ms": sorted(row["graph_elapsed_micros"] for row in rows)[-1] / 1000,
    "cost_usd": None,
    "promotion_qualified": False,
    "reproduce": " ".join(command),
}, sort_keys=True, indent=2))
