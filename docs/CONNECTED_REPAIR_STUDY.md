# Paired coding-agent repair study

Evidentrail can now verify and score a paired study, but no held-out repair
study has qualified a selector. The verifier does not create agent edits. Run
each repair agent in a separate copy of the same buggy repository, with the
same task, tools, edit limit, and output-log budget. Provide only the assigned
pack: no logs, first advertised IDs, severity, current selector, or challenger.
Pin the coding-agent model for every paired arm, and name the current and
challenger retrieval route with their exact selector and model versions.
Keep the regression test in a separate `hidden_test_tree` and the fixed source
out of each agent's workspace. The verifier mounts hidden tests only into
disposable copies. Before any trial, fill the tree SHA-256 fields from
`verify-connected-repair-trials.py --fingerprint-tree DIR` and
`--fingerprint-file FILE`. Freeze each selected log pack with its own
`log_pack_sha256` before the corresponding agent trial, then commit the
manifest. The verifier refuses changed case inputs or packs.

Freeze a manifest before tuning a challenger. Include at least ten held-out
cases across three projects and three fault families. Do not overlap
development and held-out projects or fault families. `raw_budget` is the same
per case for every arm. The source-record inventory contains original
`source_id`, `native_id`, and `raw` (or `raw_base64`) values; each selected pack
uses the connected CLI's JSONL record format. The verifier checks every pack
record by source/native ID and exact bytes, refuses budget overrun and
unauthorized file edits, reruns the buggy and fixed controls, and runs the
same test command in each edited workspace.

Example manifest shape (paths are relative to the manifest):

```json
{
  "schema_version": 1,
  "repair_agent_model": "frozen-coding-agent-model-and-version",
  "current_route": "current-selector-and-model-version",
  "challenger_route": "challenger-selector-and-model-version",
  "cases": [{
    "id": "project-a-issue-1",
    "project": "project-a",
    "fault_family": "migration",
    "split": "held_out",
    "raw_budget": 4096,
    "buggy_tree": "project-a/buggy",
    "fixed_tree": "project-a/fixed",
    "hidden_test_tree": "project-a/hidden-tests",
    "source_records": "project-a/original-records.jsonl",
    "buggy_tree_sha256": "FROZEN_TREE_DIGEST",
    "fixed_tree_sha256": "FROZEN_TREE_DIGEST",
    "hidden_test_tree_sha256": "FROZEN_TREE_DIGEST",
    "source_records_sha256": "FROZEN_FILE_SHA256",
    "editable_paths": ["src/service.py"],
    "test_argv": ["/path/to/venv/bin/python", "-m", "pytest", "-q", "tests/test_regression.py"],
    "arms": {
      "no_logs": {"edited_tree": "project-a/no-logs", "elapsed_ms": 1000, "model_calls": 2},
      "first_id": {"edited_tree": "project-a/first-id", "log_pack": "project-a/first-id.jsonl", "log_pack_sha256": "FROZEN_PACK_DIGEST", "elapsed_ms": 1000, "model_calls": 2},
      "severity": {"edited_tree": "project-a/severity", "log_pack": "project-a/severity.jsonl", "log_pack_sha256": "FROZEN_PACK_DIGEST", "elapsed_ms": 1000, "model_calls": 2},
      "current": {"edited_tree": "project-a/current", "log_pack": "project-a/current.jsonl", "log_pack_sha256": "FROZEN_PACK_DIGEST", "elapsed_ms": 1000, "model_calls": 2},
      "challenger": {"edited_tree": "project-a/challenger", "log_pack": "project-a/challenger.jsonl", "log_pack_sha256": "FROZEN_PACK_DIGEST", "elapsed_ms": 1000, "model_calls": 2}
    }
  }]
}
```

```sh
python3 scripts/verify-connected-repair-trials.py --manifest study.json > verified-results.jsonl
python3 scripts/score-connected-repair-study.py \
  --manifest study.json --results verified-results.jsonl
```

The scorer independently reruns the verifier before accepting the supplied
results. It requires complete paired arms, healthy buggy/fixed controls, exact
source bytes, matched budgets, and an independently run passing test for a
repair. Its provisional review gate requires a one-sided exact paired-test
result at most 0.01 against no logs and each log baseline, no baseline-only successes,
and p95 elapsed time and model calls at most 25% over current. Passing that
gate requests **human review**; it never changes the product route. A repair
test can miss regressions, so larger held-out suites and manual failure review
remain necessary. Existing synthetic and single-case development probes do
not meet this gate.
