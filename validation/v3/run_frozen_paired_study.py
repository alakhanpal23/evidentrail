#!/usr/bin/env python3
"""Screen-first native V3 paired performance protocol.

The expensive 5/30 study is run only when every frozen point-estimate gate
passes. Expansion uses the probe's frozen 10 warmups and 200 observations.
Results are non-certifying unless the caller separately records an approved
signed executable, Keychain authority, and governed host provenance.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "target/release/examples/v3_resource_probe"
SCALES = (10_000, 100_000, 1_000_000)
BOOTSTRAPS = 20_000
SEED = 0xC0DA6303
RECORDED_BASELINE_P95_NANOS = {100_000: 38_696_791, 1_000_000: 29_687_250}


def run_probe(mode: str, records: int) -> dict:
    with tempfile.NamedTemporaryFile() as timing:
        command = [str(PROBE), mode, str(records)]
        if Path("/usr/bin/time").exists():
            command = ["/usr/bin/time", "-l", "-o", timing.name, *command]
        completed = subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True)
        report = json.loads(completed.stdout)
        timing.seek(0)
        text = timing.read().decode("utf-8", "replace")
        rss = 0
        for line in text.splitlines():
            if "maximum resident set size" in line:
                rss = int(line.strip().split()[0])
                break
        report["peak_rss_bytes"] = rss
        product = report["product_performance"]
        product_subtotal = sum(
            product[name]
            for name in (
                "atomic_framing_nanos",
                "global_analysis_nanos",
                "projection_nanos",
                "v1_compilation_nanos",
                "seal_and_publication_nanos",
            )
        )
        if product_subtotal != product["total_elapsed_nanos"]:
            raise RuntimeError("product performance receipt does not reconcile")
        store = report.get("store_performance")
        if mode == "durable" and not store:
            raise RuntimeError("durable performance receipt missing")
        if store:
            store_subtotal = sum(value for name, value in store.items() if name.endswith("_nanos") and name != "total_elapsed_nanos")
            if store_subtotal != store["total_elapsed_nanos"]:
                raise RuntimeError("store performance receipt does not reconcile")
            if store["sync_count"] != store["object_count"] * 2:
                raise RuntimeError("pack sync count does not reconcile with installed objects")
        return report


def paired_once(records: int, rng: random.Random) -> dict:
    order = ["memory", "durable"]
    rng.shuffle(order)
    arms = {mode: run_probe(mode, records) for mode in order}
    return {"order": order, **arms}


def screen_gates(screen: dict[int, dict]) -> list[str]:
    failures: list[str] = []
    for records, pair in screen.items():
        memory, durable = pair["memory"], pair["durable"]
        throughput_ratio = memory["elapsed_nanos"] / durable["elapsed_nanos"]
        baseline_p95 = RECORDED_BASELINE_P95_NANOS.get(records)
        latency_regression = (
            durable["expansion_p95_nanos"] / baseline_p95 - 1 if baseline_p95 else 0
        )
        if records in (100_000, 1_000_000) and throughput_ratio < 0.90:
            failures.append(f"{records}: durable/memory throughput {throughput_ratio:.3f} < 0.90")
        if records in (100_000, 1_000_000) and latency_regression > 0.10:
            failures.append(f"{records}: expansion p95 regression from recorded V2 {latency_regression:.3%} > 10%")
        if records == 10_000 and durable["elapsed_nanos"] - memory["elapsed_nanos"] > 20_000_000:
            failures.append(f"10000: durable overhead exceeds 20 ms")
        if records == 1_000_000:
            if durable["peak_rss_bytes"] > 1024**3:
                failures.append("1000000: durable RSS exceeds 1 GiB")
            if memory["peak_rss_bytes"] and durable["peak_rss_bytes"] / memory["peak_rss_bytes"] > 1.15:
                failures.append("1000000: durable RSS regression exceeds 15%")
            if durable["storage_amplification"] > 2.5:
                failures.append("1000000: V3 storage amplification exceeds 2.5x")
            if durable["store_performance"]["object_count"] > 80:
                failures.append("1000000: immutable pack count exceeds checkpoint-sized bound")
    scaling = (
        screen[1_000_000]["durable"]["expansion_p95_nanos"]
        / screen[100_000]["durable"]["expansion_p95_nanos"]
    )
    if scaling > 1.10:
        failures.append(f"expansion p95 10x scaling ratio {scaling:.3f} > 1.10")
    return failures


def optimization_follow_up(screen: dict[int, dict]) -> dict:
    durable = screen[1_000_000]["durable"]
    receipt = durable["store_performance"]
    total = max(1, receipt["total_elapsed_nanos"])
    shares = {
        "filesystem_synchronization": (receipt["file_full_sync_nanos"] + receipt["directory_sync_nanos"]) / total,
        "encryption_allocation": receipt["frame_encryption_nanos"] / total,
        "page_scans": (receipt["page_scan_nanos"] + receipt["frame_decryption_nanos"]) / total,
        "index_construction": receipt["index_construction_nanos"] / total,
    }
    ordered_remedies = [
        ("filesystem_synchronization", "reduce_pack_count_within_memory_and_checkpoint_caps"),
        ("encryption_allocation", "reuse_zeroizing_frame_buffers_and_remove_duplicate_hash_copies"),
        ("page_scans", "combine_atomic_discovery_and_global_statistics_lane_scan"),
        ("index_construction", "deterministic_fixed_width_radix_sort"),
    ]
    selected = next((remedy for phase, remedy in ordered_remedies if shares[phase] >= 0.10), None)
    return {"phase_shares": shares, "selected_ordered_remedy": selected}


def statistic(values: list[float]) -> float:
    return statistics.fmean(values)


def bca(values: list[float], samples: int = BOOTSTRAPS) -> dict:
    """Deterministic 95% BCa interval for a paired scalar observation."""
    rng = random.Random(SEED ^ len(values))
    observed = statistic(values)
    boot = sorted(statistic([values[rng.randrange(len(values))] for _ in values]) for _ in range(samples))
    normal = statistics.NormalDist()
    below = max(0.5 / samples, min(1 - 0.5 / samples, sum(x < observed for x in boot) / samples))
    z0 = normal.inv_cdf(below)
    jack = [statistic(values[:i] + values[i + 1 :]) for i in range(len(values))]
    jack_mean = statistic(jack)
    numerator = sum((jack_mean - value) ** 3 for value in jack)
    denominator = 6 * sum((jack_mean - value) ** 2 for value in jack) ** 1.5
    acceleration = numerator / denominator if denominator else 0.0

    def adjusted(alpha: float) -> float:
        z = normal.inv_cdf(alpha)
        denominator = 1 - acceleration * (z0 + z)
        return normal.cdf(z0 + (z0 + z) / denominator)

    def quantile(probability: float) -> float:
        index = min(samples - 1, max(0, math.ceil(probability * samples) - 1))
        return boot[index]

    return {
        "estimate": observed,
        "lower_95": quantile(adjusted(0.025)),
        "upper_95": quantile(adjusted(0.975)),
        "resamples": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "validation/v3/native-v3-study.json")
    parser.add_argument("--screen-only", action="store_true")
    arguments = parser.parse_args()
    subprocess.run(
        ["cargo", "build", "--release", "-p", "evidentrail-cli", "--example", "v3_resource_probe"],
        cwd=ROOT,
        check=True,
    )
    rng = random.Random(SEED)
    started = time.time_ns()
    screen = {records: paired_once(records, rng) for records in SCALES}
    diagnostic_release_observations = {
        str(records): [screen[records], *[paired_once(records, rng) for _ in range(4)]]
        for records in (100_000, 1_000_000)
    }
    failures = screen_gates(screen)
    artifact: dict = {
        "schema_version": 3,
        "qualification_eligible": False,
        "host": {"platform": os.uname().sysname, "release": os.uname().release},
        "protocol": {
            "throughput_warmups": 5,
            "throughput_pairs": 30,
            "expansion_warmups": 10,
            "expansion_pairs": 200,
            "bca_resamples": BOOTSTRAPS,
            "latency_regression_baseline": "validation/v3/summary.json V2-adapter point observations",
        },
        "screen": screen,
        "diagnostic_release_observations": diagnostic_release_observations,
        "diagnostic_observations_per_large_scale": 5,
        "optimization_follow_up": optimization_follow_up(screen),
        "screen_failures": failures,
        "full_study_run": False,
    }
    if not failures and not arguments.screen_only:
        observations = {}
        for records in SCALES:
            for _ in range(5):
                paired_once(records, rng)
            pairs = [paired_once(records, rng) for _ in range(30)]
            ratios = [pair["memory"]["elapsed_nanos"] / pair["durable"]["elapsed_nanos"] for pair in pairs]
            observations[str(records)] = {
                "pairs": pairs,
                "throughput_ratio_bca": bca(ratios),
                "expansion_paired_log_ratio_bca": bca([
                    math.log(d / m)
                    for pair in pairs
                    for m, d in zip(pair["memory"]["expansion_nanos"], pair["durable"]["expansion_nanos"])
                ]),
            }
        artifact["full_study_run"] = True
        artifact["observations"] = observations
    artifact["elapsed_nanos"] = time.time_ns() - started
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(arguments.output), "screen_failures": failures}, indent=2))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
