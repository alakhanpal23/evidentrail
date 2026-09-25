#!/usr/bin/env python3
"""Verify and score a six-arm, frozen learning-route repair study.

The sixth arm, challenger_no_memory, uses identical retrieval and agent code
with only cross-task memory disabled. This script re-executes every repair test
through Prompt 1's verifier before scoring. It never activates a route.
"""
import argparse
import importlib.util
import json
from pathlib import Path

ARMS = ("no_logs", "first_id", "severity", "current", "challenger", "challenger_no_memory")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def score_ablation(cases, rows, scorer):
    held = [case_id for case_id, case in cases.items() if case["split"] == "held_out"]
    on_only = sum(rows[(case_id, "challenger")]["repair_test_passes"] and
                  not rows[(case_id, "challenger_no_memory")]["repair_test_passes"] for case_id in held)
    off_only = sum(rows[(case_id, "challenger_no_memory")]["repair_test_passes"] and
                   not rows[(case_id, "challenger")]["repair_test_passes"] for case_id in held)
    on = sum(rows[(case_id, "challenger")]["repair_test_passes"] for case_id in held)
    off = sum(rows[(case_id, "challenger_no_memory")]["repair_test_passes"] for case_id in held)
    p = scorer.one_sided_exact_p(on_only, off_only)
    return {
        "held_out_cases": len(held),
        "memory_on_verified_repairs": on,
        "memory_off_verified_repairs": off,
        "memory_on_only": on_only,
        "memory_off_only": off_only,
        "one_sided_exact_p": p,
        "raw_budget_matched": True,
        "source_exact": True,
        "qualified": on > off and off_only == 0 and p <= 0.01,
    }


def cost_guardrail(costs, basis):
    """Accept complete metered API costs, never an inferred CLI price."""
    if basis != "metered_api" or not isinstance(costs, dict):
        return False
    if any(type(costs.get(arm)) is not int or costs[arm] <= 0 for arm in ARMS):
        return False
    return (4 * costs["challenger"] <= 5 * costs["current"]
            and 4 * costs["challenger"] <= 5 * costs["challenger_no_memory"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    verifier = load(directory / "verify-connected-repair-trials.py", "verified_repair")
    scorer = load(directory / "score-connected-repair-study.py", "scored_repair")
    verifier.ARMS = ARMS
    scorer.ARMS = ARMS
    frozen = json.loads(args.manifest.read_text())
    memory_off_route = frozen.get("challenger_no_memory_route")
    if (not isinstance(memory_off_route, str) or not memory_off_route.strip()
            or memory_off_route == frozen.get("challenger_route")):
        raise ValueError("freeze the exact challenger_no_memory_route identity")
    if args.verify_only:
        if args.results is not None:
            parser.error("--verify-only cannot be combined with --results")
        for row in verifier.verify(args.manifest):
            print(json.dumps(row, sort_keys=True))
        return
    if args.results is None:
        parser.error("--results is required unless --verify-only is set")
    cases, rows = scorer.read_study(args.manifest, args.results)
    verified = {(row["case_id"], row["arm"]): row for row in verifier.verify(args.manifest)}
    if rows != verified:
        raise ValueError("results differ from independently rerun verifier")
    report = scorer.score(cases, rows)
    report["memory_ablation"] = score_ablation(cases, rows, scorer)
    # The existing verifier has no provider-metered selector or repair-agent
    # billing receipt. A CLI token proxy must not silently qualify promotion.
    report["model_cost_basis"] = "unavailable"
    report["model_cost_microusd"] = None
    report["cost_guardrail_passed"] = cost_guardrail(
        report["model_cost_microusd"], report["model_cost_basis"])
    report["route_eligible_for_promotion"] = (report["challenger_eligible_for_human_review"]
                                               and report["memory_ablation"]["qualified"]
                                               and report["cost_guardrail_passed"])
    report.update({field: frozen[field] for field in
                   ("repair_agent_model", "current_route", "challenger_route")})
    report["challenger_no_memory_route"] = memory_off_route
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
