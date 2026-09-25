#!/usr/bin/env python3
"""Summarize CLI tokens and a non-billable API list-price proxy by study arm."""

import argparse
import json
from decimal import Decimal
from pathlib import Path


ARMS = ("no_logs", "first_id", "severity", "current", "challenger",
        "challenger_no_memory")
# USD per million tokens, standard short-context rate on 2026-09-24.
# https://developers.openai.com/api/docs/pricing
RATES = {"gpt-6-sol": (Decimal("2"), Decimal("10")),
         "gpt-6-luna": (Decimal("0.10"), Decimal("0.50"))}


def usage(metrics):
    in_tokens = metrics.get("input_tokens")
    out_tokens = metrics.get("output_tokens")
    cached = metrics.get("cached_input_tokens")
    if any(type(value) is not int or value < 0 for value in
           (in_tokens, out_tokens, cached)) or cached > in_tokens:
        raise ValueError("missing or invalid CLI token usage")
    return in_tokens, out_tokens, cached


def price(model, input_tokens, output_tokens):
    input_rate, output_rate = RATES[model]
    return ((input_rate * input_tokens) + (output_rate * output_tokens)) / 1_000_000


def summarize(pack_lock, trials):
    frozen = json.loads(pack_lock.read_text())
    case_ids = [entry["id"] for entry in frozen["cases"]]
    if len(case_ids) != len(set(case_ids)) or not case_ids:
        raise ValueError("duplicate or empty pack lock")
    summary = {}
    for arm in ARMS:
        agent_input = agent_output = agent_cached = 0
        selector_input = selector_output = selector_cached = 0
        selector_model = None
        for entry in frozen["cases"]:
            case_id = entry["id"]
            metrics = json.loads((trials / case_id / f"{arm}-metrics.json").read_text())
            one_input, one_output, one_cached = usage(metrics)
            agent_input += one_input
            agent_output += one_output
            agent_cached += one_cached
            if arm in ("current", "challenger", "challenger_no_memory"):
                pack = entry["packs"][arm]
                if selector_model is None:
                    selector_model = pack["selector_model"]
                elif selector_model != pack["selector_model"]:
                    raise ValueError("selector model changed across cases")
                selected = pack["selection"]
                values = (selected["selector_input_tokens"],
                          selected["selector_output_tokens"],
                          selected["selector_cached_input_tokens"])
                if any(type(value) is not int or value < 0 for value in values):
                    raise ValueError("invalid selector CLI token usage")
                selector_input += values[0]
                selector_output += values[1]
                selector_cached += values[2]
        agent_proxy = price("gpt-6-sol", agent_input, agent_output)
        selector_proxy = price(selector_model, selector_input, selector_output) if selector_model else Decimal(0)
        summary[arm] = {
            "cases": len(case_ids), "repair_agent_input_tokens": agent_input,
            "repair_agent_output_tokens": agent_output,
            "repair_agent_cached_input_tokens": agent_cached,
            "selector_model": selector_model, "selector_input_tokens": selector_input,
            "selector_output_tokens": selector_output,
            "selector_cached_input_tokens": selector_cached,
            "standard_api_list_price_proxy_usd": str(agent_proxy + selector_proxy),
        }
    return {
        "schema_version": 1, "basis": "codex_cli_tokens_api_list_price_proxy",
        "pricing_as_of": "2026-09-24",
        "pricing_source": "https://developers.openai.com/api/docs/pricing",
        "metered_cost_available": False,
        "notes": "Cached-input discounts, cache-write charges, subscription billing, and one-time annotation costs are excluded. This is not a provider receipt or promotion evidence.",
        "arms": summary,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-lock", required=True, type=Path)
    parser.add_argument("--trials", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.pack_lock, args.trials), sort_keys=True))


if __name__ == "__main__":
    main()
