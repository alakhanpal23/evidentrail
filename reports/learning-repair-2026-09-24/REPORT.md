# Frozen six-arm repair study: source-local memory did not help

**Decision:** keep the current connected route and the learner in shadow. The
memory-on challenger fixed 4/12 held-out bugs, versus 5/12 with the same
selector and memory disabled, 7/12 for the current selector, 7/12 with no
logs, and 8/12 with first-ID selection. The independent verifier reran the
buggy/fixed controls and all 72 edited workspaces. The memory ablation was
4 versus 5 (one on-only, two off-only; one-sided exact p = 0.875), far from
the frozen gate. The challenger p95 end-to-end latency was 72.6 seconds versus
48.1 seconds for current. No production promotion is supported.
The current selector also failed to beat no logs (7/12) or first ID (8/12),
so this study does not establish a retrieval-driven repair gain for the
existing route either.

## Study design and integrity

- Twelve previously unstudied, reproducing BugsInPy bugs from Black (6),
  TheFuck (2), and Luigi (4), covering 11 descriptive fault families. Six
  separate development bugs, two per project, provided source-local labels.
  The held-out bug IDs and buggy revisions do not overlap development.
- A blind `gpt-6-sol` reviewer selected original development log IDs from
  tasks and failing logs only. It saw no fixed code, hidden tests, route
  selections, or repair outcomes. These labels are independent of the trial
  outcomes but are **model annotations, not human adjudications**. They were
  frozen before any held-out repair trial.
- Each held-out history contained the two same-project development log
  streams plus only that held-out bug's failing logs. All six arms used the
  same task, `gpt-6-sol` repair agent, edit limits, hidden test, and 1 KiB
  raw-log budget. The challenger used `gpt-6-luna`; its memory-off ablation
  used the identical selector with memory disabled. Arm order rotated by
  frozen case ID. No fixed source or hidden regression test entered an agent
  workspace. Agents did not run tests during editing; the verifier ran the
  hidden regression after each edit.
- Cohort, development, history, label, and pack locks were committed before
  held-out repair trials. The final audit checked exact source bytes, lock
  hashes, selector methods/models, pack hashes, budgets, split IDs, and
  source-local contributions. It passed for all 12 cases. The independent
  verifier checked 72 patches, all buggy/fixed controls, and selected-log
  provenance. No trial timed out or failed the agent protocol.

| Arm | Verified fixes | p95 end-to-end | Counted CLI runs | API list-price proxy* |
| --- | ---: | ---: | ---: | ---: |
| No logs | 7/12 | 64.4 s | 12 | $3.66 |
| First ID | 8/12 | 87.5 s | 12 | $2.94 |
| Severity | 7/12 | 69.9 s | 12 | $3.31 |
| Current (`gpt-6-sol`) | 7/12 | 48.1 s | 26 | $2.98 |
| Challenger, memory on (`gpt-6-luna`) | 4/12 | 72.6 s | 26 | $2.17 |
| Challenger, memory off (`gpt-6-luna`) | 5/12 | 76.5 s | 26 | $2.77 |

*CLI input/output tokens were observed. The dollar figures apply the
[published standard API list prices](https://developers.openai.com/api/docs/pricing)
as a **proxy**, without cache discounts, cache-write charges, subscription
billing, or one-time annotation cost. They are not provider-metered charges.
The blind development annotation consumed another 102,483 CLI input tokens
(42,240 cached) and 354 output tokens. The scorer records cost as unavailable;
the production gate rejects missing or estimated dollar costs, even if a
repair-rate gate were to pass. The `model_calls` field counts repair CLI runs
plus selector invocations; the CLI does not expose its internal model-call
count.

## Per-case verified repairs

`Y` means the hidden regression test passed in an isolated agent-edited copy.
`–` means it did not. Buggy controls failed and fixed controls passed for every
case.

| Bug | No logs | First ID | Severity | Current | Memory on | Memory off |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| black-10 | Y | Y | Y | – | – | – |
| black-12 | – | Y | – | Y | – | Y |
| black-13 | – | – | – | Y | Y | – |
| black-14 | Y | Y | Y | Y | – | – |
| black-15 | – | – | – | – | – | – |
| black-16 | – | – | – | – | – | – |
| thefuck-27 | Y | Y | Y | – | – | – |
| thefuck-31 | Y | Y | Y | Y | – | – |
| luigi-17 | Y | Y | Y | Y | Y | Y |
| luigi-20 | – | – | – | – | – | Y |
| luigi-22 | Y | Y | Y | Y | Y | Y |
| luigi-29 | Y | Y | Y | Y | Y | Y |

The challenger lost three cases to current and gained none. It lost four to
no logs and gained one. In particular, `black-10`, `black-14`, `thefuck-27`,
and `thefuck-31` passed without logs but failed with the challenger pack.
This is a measured regression, not evidence that log access is inherently
harmful; more cases and repeated agent trials would be needed for that claim.

Memory-on and memory-off pack hashes differed in 9/12 cases, but two of those
differences were only record order. Seven changed the selected ID set; three
packs were identical. `black-13` passed only in the memory-on arm even though
the two challenger packs were byte-identical, demonstrating agent-run
variance. `black-12` passed only with memory off although both packs contained
the same IDs in a different order. A single agent run per arm therefore cannot
identify a causal memory benefit. The primary paired result already fails the
gate, so no held-out tuning or post-hoc rerun was used to promote the route.

The project split matters: memory on fixed 1/6 Black, 0/2 TheFuck, and 3/4
Luigi bugs. Selection from prior labeled logs remains a limited source-local
reordering of an existing candidate pool. It cannot retrieve a missing
candidate, and these labels may amplify terms shared across unrelated bugs.
The next product change should target the observed failure modes on a new
development set, then freeze a fresh held-out cohort and repeat the study.

## Reproduction and artifacts

The contentless [results](results.jsonl), [score](score.json),
[audit](audit.json), and [CLI usage](usage.json) are committed alongside the
pretrial locks. Raw logs, source trees, hidden tests, and agent traces remain
outside the repository. The [study instructions](../../docs/LEARNING_REPAIR_STUDY.md)
give the exact commands. The local run used Codex CLI 0.156.1, Python 3.9.6,
and Rust 1.88.0. Reproducing the same measured repairs requires the frozen
private BugsInPy artifacts and packs; model aliases and agent sampling may
change future runs. Passing a targeted hidden regression test does not rule
out unrelated regressions elsewhere in a project.
