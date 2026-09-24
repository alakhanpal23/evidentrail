# Six-arm learning study readiness — 24 September 2026

The connected learning route remains shadow-only. The real repair study on
`eval/multi-bug-repair-study` is complete but measures five arms. Its 11
held-out cases have 11 distinct source IDs, one per bug. The source-local
learner cannot reuse a development label from another case in those isolated
corpora. `score-learning-route.py` rejects that study because it has no frozen
`challenger_no_memory_route` identity or sixth pack. Reusing these inspected
cases as a fresh confirmatory learning set would also leak held-out outcomes.

The six-case shadow replay is synthetic development data with no independent
record labels, and its memory-on and memory-off routes are identical. It
cannot establish downstream repair benefit. No provider-metered selector and
repair-agent cost receipts exist for this run. The promotion path now rejects
missing cost for any arm and rejects CLI-derived/API-equivalent estimates.

To qualify a route, create a new versioned study cohort before viewing repair
outcomes:

1. Screen at least ten fresh executable bugs spanning at least three projects
   and three fault families, with buggy/fixed controls and hidden regression
   tests. Exclude every previously inspected repair-study bug.
2. Build persistent, source-local log histories per project/source. Freeze
   independent development record labels from different bug cases before
   held-out selection. Bind each label to source/native ID, source bytes, bug
   revision, case ID, task digest, reviewer provenance, and split. No fixed
   source, held-out regression output, user rating, or repair result may train
   the learner. Audit distinct case IDs and revisions; development labels may
   share a project/source with held-out cases because the learner is
   intentionally source-local.
3. Freeze six exact-source packs per held-out case, including challenger with
   memory and the same challenger with memory disabled, before any repair
   attempt. Keep task, raw-log cap, repair model, tools, and edit limit equal.
4. Capture provider-metered usage and cost for **every** selector and repair
   call, including retries and cache-write/tool charges, under a pinned model,
   processing tier, region, and price version. Publish contentless per-arm
   micro-USD receipts. The current Codex CLI bridge does not provide these
   billing receipts.
5. Rerun hidden tests independently, score matched repair differences and the
   memory ablation, inspect retrieval-hurt cases, then evaluate the route in
   shadow. Promotion remains a separate action and requires the frozen gates
   plus a current training fingerprint.

This is a readiness record, not a successful evaluation. No six-arm repair
outcomes or model-cost claim are inferred from the prior five-arm study.
