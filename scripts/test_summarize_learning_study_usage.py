import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "usage", Path(__file__).with_name("summarize-learning-study-usage.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class UsageTests(unittest.TestCase):
    def test_complete_cli_usage_remains_proxy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            selections = {}
            for arm in ("current", "challenger", "challenger_no_memory"):
                selections[arm] = {
                    "selector_model": "gpt-6-sol" if arm == "current" else "gpt-6-luna",
                    "selection": {"selector_input_tokens": 100,
                                  "selector_output_tokens": 20,
                                  "selector_cached_input_tokens": 30},
                }
            lock = root / "lock.json"
            lock.write_text(json.dumps({"cases": [{"id": "bug-1", "packs": selections}]}))
            trial = root / "trials" / "bug-1"
            trial.mkdir(parents=True)
            for arm in MODULE.ARMS:
                (trial / f"{arm}-metrics.json").write_text(json.dumps({
                    "input_tokens": 1000, "output_tokens": 100,
                    "cached_input_tokens": 200}))
            summary = MODULE.summarize(lock, root / "trials")
            self.assertFalse(summary["metered_cost_available"])
            self.assertEqual(summary["arms"]["no_logs"]["standard_api_list_price_proxy_usd"],
                             "0.003")
            self.assertEqual(summary["arms"]["challenger"]["selector_input_tokens"], 100)

    def test_missing_tokens_are_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.usage({"input_tokens": 10, "output_tokens": 1})


if __name__ == "__main__":
    unittest.main()
