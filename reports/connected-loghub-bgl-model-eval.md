# Live-model selection on the pinned LogHub BGL sample

**Status:** one local-model run completed on 2026-09-23; no hosted model run.

Run `bash scripts/eval-loghub-bgl-model.sh` from the repository root after setting
`EVIDENTRAIL_COMPACT_LOCAL_MODEL` for a running Ollama model or `OPENAI_API_KEY`
for the hosted selector. The opt-in script fetches the same pinned 2,000-line
sample and verifies its SHA-256 in the test before ingesting it into an
encrypted corpus. It calls the product's actual model selector on the same
12 message-derived tasks and 4,096-byte raw-log budget as the deterministic
[BGL proxy](connected-loghub-bgl-2026-09-23.md). Each `BGL_MODEL_EVAL` JSON line
reports label coverage, selected and off-label line counts, candidate and
output truncation, and elapsed time. `BGL_MODEL_SUMMARY` aggregates them.
Every selected line is checked against the stored original bytes.

With `qwen2.5-coder:7b` served by local Ollama at a 32K context, the actual
selector returned an exact source line with the target category in all 12
tasks. It returned 149 lines overall, 107 of which carried a different category
label. Total elapsed time was 494.4 seconds for the 12 sequential queries;
the slowest single query took 157.5 seconds. Four queries reported retrieval
truncation. By comparison, the first-ID and severity baselines both hit 12/12
categories but returned 147/189 and 138/179 off-label lines respectively.
The model improved this narrow output-noise proxy, but often selected the full
12-group allowance, and its latency is not suitable for an interactive default.
This run does not qualify the model for production routing; the separate pinned
RCAEval probe found the labeled root service in only 1/3 cases with this model.

The label is a proxy for task relevance, not proof that another label is
irrelevant or that a coding agent can fix an incident. The tasks were derived
from the sample, so these numbers cannot establish generalization. A run may
make more than one model call per task if service-directory paging is needed;
the timing includes indexing queries and model calls. It does not measure
token cost, repeated-run latency distributions, model comparison, or
downstream task success. Record the exact model name and run date alongside
any result; do not treat this harness alone as a release qualification.
