# Multi-bug connected-log repair study

The [final evidence report](REPORT.md) and [contentless per-case results](per-case-results.jsonl)
show 7/11 verified repairs for both connected routes, versus 6/11 with no
logs. Neither connected route passed the paired evidence gate, so no default
model or route was changed.

This is an opt-in, source-exact repair study on pinned historical bugs from
[BugsInPy](https://github.com/reproducing-research-projects/BugsInPy). The
study screened 79 candidate bugs from Black, The Fuck, FastAPI, PySnooper, and
HTTPie in an isolated Python 3.9 environment. Twenty-six reproduced with the
same hidden regression test failing on buggy source and passing on fixed
source. The original lock contains ten cases. PySnooper bug 2 had been used
for an agent-runner pilot before that lock, so its paired results are
**development only**. A separately committed supplement prelocked the next
two eligible, unpiloted Black bugs (8 and 9) and their source-exact packs
before their agent trials. The final held-out analysis therefore contains
eleven cases from Black, The Fuck, and FastAPI, across six fault families,
with a 1,024-byte original-log cap for every arm. The supplement was chosen
after the first two original trial outcomes were visible, which limits the
strength of any confirmatory claim; the choice used numeric eligibility,
not those outcomes or any challenger tuning.

[`locked-cases.json`](locked-cases.json) pins source revisions, exact tree and
log digests, the task, allowed editable files, and the test command. It was
committed before any held-out agent run. [`pack-lock.json`](pack-lock.json)
pins the exact original-log packs and selection metadata; it was committed
before any held-out repair run. The [supplemental case lock](supplemental-cases.json)
and [pack lock](supplement-pack-lock.json) were likewise committed before
their own trials. The public [`artifacts/`](artifacts/) directory
contains the exact source-record inventories and selected packs. Upstream
source trees, hidden tests, agent traces, and trial patches stay outside this
repository. The commands below recreate the source trees from public pinned
revisions. The test
environment packages are frozen in [`requirements.txt`](requirements.txt).

Each case has five arms: no logs, first advertised IDs, severity-only,
connected selection using a Codex CLI GPT-6 Sol study bridge, and the same
connected group-card path using GPT-6 Luna. The repair reader is Codex CLI
GPT-6 Sol at low reasoning effort in every arm. The study bridge exercises
Evidentrail's actual encrypted corpus, group cards, candidate paging, budget
enforcement, and exact source-record resolution, but it is **not** the
production OpenAI API selector adapter. Therefore even a positive result
cannot by itself qualify a production default model. It can expose retrieval
misses and guide a follow-up production-adapter qualification.

The coding agent receives the same source tree, task, tool constraints, and
editable-file limit in every arm. The full regression suite and fixed source
are absent from its workspace. Test output in the log packs can contain
traceback excerpts from hidden tests; it does not include the complete test
file. The independent verifier overlays hidden tests only into disposable
copies and reruns buggy, fixed, and agent-edited controls. The scorer reruns
that verifier before accepting any receipt. A passing regression test is a
necessary repair signal, not proof that a patch is safe across the project;
successful patches also need manual review and broader tests.

Reproduction on macOS with Python 3.9, an authenticated Codex CLI, and the
repository's pinned Rust toolchain:

```sh
python3 -m venv /tmp/evidentrail-repair-venv
/tmp/evidentrail-repair-venv/bin/python -m pip install -r reports/repair-study-2026-09-24/requirements.txt
git clone https://github.com/reproducing-research-projects/BugsInPy.git /tmp/evidentrail-heldout-BugsInPy
git clone --filter=blob:none --no-checkout https://github.com/psf/black.git /tmp/evidentrail-repair-black
git clone --filter=blob:none --no-checkout https://github.com/nvbn/thefuck.git /tmp/evidentrail-repair-thefuck
git clone --filter=blob:none --no-checkout https://github.com/fastapi/fastapi.git /tmp/evidentrail-repair-fastapi
git clone --filter=blob:none --no-checkout https://github.com/cool-RR/PySnooper.git /tmp/evidentrail-repair-PySnooper
for project in black thefuck fastapi PySnooper; do
  python3 scripts/screen-bugsinpy-repair-cases.py \
    --benchmark-projects /tmp/evidentrail-heldout-BugsInPy/projects \
    --repo-root /tmp --output-dir /tmp/evidentrail-repair-cases \
    --project "$project" --python /tmp/evidentrail-repair-venv/bin/python
done
# Fresh test output contains different temporary paths. Restore the exact
# original records whose digests were frozen before the trial.
for case_dir in reports/repair-study-2026-09-24/artifacts/*; do
  cp "$case_dir/source-records.jsonl" "/tmp/evidentrail-repair-cases/${case_dir##*/}/source-records.jsonl"
done
cargo +1.88.0 build -p evidentrail-cli --bin evidentrail-repair-study-select
# `prepare` can rerun selection, but model choices can vary. The committed
# packs are the exact inputs for the paired trials.
python3 scripts/run-connected-repair-study.py run \
  --case-lock reports/repair-study-2026-09-24/locked-cases.json \
  --pack-lock reports/repair-study-2026-09-24/pack-lock.json \
  --artifacts-root /tmp/evidentrail-repair-cases \
  --packs reports/repair-study-2026-09-24/artifacts \
  --output-dir /tmp/evidentrail-repair-study-trials \
  --python /tmp/evidentrail-repair-venv/bin/python
python3 scripts/run-connected-repair-study.py run \
  --case-lock reports/repair-study-2026-09-24/supplemental-cases.json \
  --pack-lock reports/repair-study-2026-09-24/supplement-pack-lock.json \
  --artifacts-root /tmp/evidentrail-repair-cases \
  --packs reports/repair-study-2026-09-24/artifacts \
  --output-dir /tmp/evidentrail-repair-study-supplement-trials \
  --python /tmp/evidentrail-repair-venv/bin/python
python3 scripts/merge-repair-study-manifests.py \
  --primary-manifest /tmp/evidentrail-repair-study-trials/study.json \
  --primary-lock reports/repair-study-2026-09-24/locked-cases.json \
  --supplement-manifest /tmp/evidentrail-repair-study-supplement-trials/study.json \
  --supplement-lock reports/repair-study-2026-09-24/supplemental-cases.json \
  --output /tmp/evidentrail-repair-study-merged.json
python3 scripts/verify-connected-repair-trials.py \
  --manifest /tmp/evidentrail-repair-study-merged.json \
  > /tmp/evidentrail-repair-verified.jsonl
python3 scripts/score-connected-repair-study.py \
  --manifest /tmp/evidentrail-repair-study-merged.json \
  --results /tmp/evidentrail-repair-verified.jsonl
```

The completed [study manifest](study-manifest.json) names the original local
trial directories so the original edits can be reverified on this host. A
fresh run recreates those private edits and produces a new manifest; model
outputs may vary. The Codex CLI exposes turn token counts here, but not a
reliable dollar price or its internal model-call count; reported calls count
CLI invocations only.
