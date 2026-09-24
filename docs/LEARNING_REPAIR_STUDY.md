# Frozen source-local learning repair study

This study asks whether prior, independently annotated development logs improve
which logs a coding agent receives and whether that changes verified repairs.
The live connected route stays in shadow unless a separate promotion gate passes.

The frozen cohort contains 12 previously unstudied BugsInPy repairs across
Black, TheFuck, and Luigi, with at least three fault families. Six other bugs
(two per project) supply development log annotations. The annotator saw only
the development task and failing logs, not fixed source, hidden tests,
selector output, or repair outcomes. These are **blind model annotations**, not
human adjudications. `cohort-lock.json`, `development-lock.json`,
`history-lock.json`, `development-labels.jsonl`, and `label-receipt.json` were
committed before selection or held-out repair trials. None of the held-out bugs
contributes a training label.

For each held-out bug, the source history contains the two development log
streams from its project followed by only that bug's failing log stream. The
other held-out logs are excluded. The builder and runner verify the exact
original record IDs and bytes. All six arms share a 1 KiB raw-log budget per
bug and the same `gpt-6-sol` coding agent. They are no logs, first ID,
severity, current `gpt-6-sol` selector, `gpt-6-luna` with source-local memory,
and identical `gpt-6-luna` selection with memory disabled. The repair agent
cannot see fixed source or hidden regression tests. The runner rotates arm
order by frozen case ID. The verifier checks editable files, exact log bytes,
budget, buggy/fixed controls, and held-out tests independently.

The artifact roots used below are private local test fixtures; raw logs, fixed
source, hidden tests, and agent traces do not belong in the repository.

```sh
cargo +1.88.0 build --release -p evidentrail-cli --bin evidentrail-repair-study-select
python3 scripts/build-learning-source-histories.py \
  --cohort-lock reports/learning-repair-2026-09-24/cohort-lock.json \
  --development-lock reports/learning-repair-2026-09-24/development-lock.json \
  --artifacts-root /tmp/evidentrail-learning-candidates \
  --output-root /tmp/evidentrail-learning-histories-rebuilt \
  --output-lock /tmp/evidentrail-history-lock-rebuilt.json
cmp /tmp/evidentrail-history-lock-rebuilt.json \
  reports/learning-repair-2026-09-24/history-lock.json
python3 scripts/run-learning-repair-study.py prepare \
  --case-lock reports/learning-repair-2026-09-24/cohort-lock.json \
  --development-lock reports/learning-repair-2026-09-24/development-lock.json \
  --history-lock reports/learning-repair-2026-09-24/history-lock.json \
  --labels reports/learning-repair-2026-09-24/development-labels.jsonl \
  --artifacts-root /tmp/evidentrail-learning-candidates \
  --histories /tmp/evidentrail-learning-histories \
  --packs /tmp/evidentrail-learning-packs-rebuilt \
  --pack-lock /tmp/evidentrail-pack-lock-rebuilt.json \
  --selector-bin target/release/evidentrail-repair-study-select
```

The committed pack lock is the pretrial record. A new selector run can differ
because model outputs can vary, so do not substitute rebuilt packs into the
frozen trial. To reproduce the original trial, use the committed lock and the
original frozen packs whose SHA-256 values match it. Then
run the paired trials and independently verify and score their manifest:

```sh
python3 scripts/run-learning-repair-study.py run \
  --case-lock reports/learning-repair-2026-09-24/cohort-lock.json \
  --development-lock reports/learning-repair-2026-09-24/development-lock.json \
  --history-lock reports/learning-repair-2026-09-24/history-lock.json \
  --labels reports/learning-repair-2026-09-24/development-labels.jsonl \
  --artifacts-root /tmp/evidentrail-learning-candidates \
  --histories /tmp/evidentrail-learning-histories \
  --packs /tmp/evidentrail-learning-packs \
  --pack-lock reports/learning-repair-2026-09-24/pack-lock.json \
  --output-dir /tmp/evidentrail-learning-trials \
  --python /tmp/evidentrail-repair-venv/bin/python
python3 scripts/score-learning-route.py \
  --manifest /tmp/evidentrail-learning-trials/study.json --verify-only \
  > /tmp/evidentrail-learning-trials/verified-results.jsonl
python3 scripts/score-learning-route.py \
  --manifest /tmp/evidentrail-learning-trials/study.json \
  --results /tmp/evidentrail-learning-trials/verified-results.jsonl
python3 scripts/audit-learning-repair-study.py \
  --case-lock reports/learning-repair-2026-09-24/cohort-lock.json \
  --development-lock reports/learning-repair-2026-09-24/development-lock.json \
  --history-lock reports/learning-repair-2026-09-24/history-lock.json \
  --labels reports/learning-repair-2026-09-24/development-labels.jsonl \
  --artifacts-root /tmp/evidentrail-learning-candidates \
  --histories /tmp/evidentrail-learning-histories \
  --packs /tmp/evidentrail-learning-packs \
  --pack-lock reports/learning-repair-2026-09-24/pack-lock.json \
  --manifest /tmp/evidentrail-learning-trials/study.json
python3 scripts/summarize-learning-study-usage.py \
  --pack-lock reports/learning-repair-2026-09-24/pack-lock.json \
  --trials /tmp/evidentrail-learning-trials
```

Codex CLI usage is a token count, not a provider billing receipt. A dollar
cost derived from public API prices would be a proxy. The scorer reports
`model_cost_basis: unavailable` until every arm has attributable metered API
cost; the Rust route assessor rejects missing, estimated, or over-budget cost.
Do not promote a route from CLI trials alone. One-time development annotation
cost also needs separate reporting before a production economics claim.
