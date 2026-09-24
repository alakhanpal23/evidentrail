# Connected log selection on executable fault streams (local, 2026-09-24)

This opt-in evaluation reuses three deterministic fault streams from the
repository's executable incident lab. The benchmark helper emits 183 original
stdout lines per case (20.6 KB), including a configuration or deployment
precursor followed by a request failure. Its nonzero exit code and SHA-256 are
frozen in the connected test. The test ingests every line into an encrypted
corpus, asks the case's original question with no time window, and checks every
selected line against its exact source bytes. All arms use a 7,000-byte raw-log
budget; there is no provider connection in this fixture.

| Method | Precursor and symptom both present | Returned lines by case | Limitations |
| --- | ---: | --- | --- |
| First advertised IDs | 3/3 | 4, 4, 6 | Selected every candidate group |
| Critical/error only | 0/3 | 1, 1, 1 | Returned the symptom but omitted the earlier precursor |
| Recent groups | 0/3 | 12, 12, 12 | Returned the symptom but omitted the earlier precursor |
| Local Qwen2.5-Coder 7B | 3/3 | 4, 4, 6 | Also selected every candidate group |

The local-model query observations were 16.1, 4.3, and 6.0 seconds in case
order. The first call includes model warm-up; these single measurements are
not latency distributions. No method reported candidate or output truncation.
The candidate pools contained only 4, 4, and 6 groups, so this probe does not
demonstrate that the model ranks well under heavy noise. It shows the connected
parser and exact-output path can preserve an early causal precursor that two
common baselines drop.

An opt-in downstream arm gave each method's exact selected lines and the same
question to local Qwen2.5-Coder 7B, then passed its proposed single-line patch
to the executable incident verifier. It abstained on all 12 arm/case pairs;
**verified patch success was 0/3 for every arm**, including the model and
first-ID packs with both clues. This is a negative end-to-end result for that
bounded prompt and model. The patch model received no repository code or
configuration schema, so it cannot isolate retrieval quality from the ability
to propose a valid edit. It is not an agent-written repository fix, provider
validation, an independent human relevance study, or evidence of
generalization. A paired coding-agent run with the actual fixture code and
patch verifier remains necessary.

A paired rerun supplied a synthetic configuration schema for each case: the
valid assignment key, value range or migration target syntax, and one-line
patch format. It did not supply the correct setting or migration number. The
same local model still abstained on all 12 arm/case pairs; verified patch
success remained **0/3 for every arm**. This narrows the missing-context
explanation: giving patch syntax alone did not make this prompt and model solve
the faults. It does not establish whether actual repository code, an agentic
edit loop, or a different model would succeed. The selected-log comparison
remains inconclusive because the model and first-ID arms selected every
candidate group in all three cases.

Run `python3 scripts/eval-connected-executable.py` from the repository root.
With a running Ollama model named by `EVIDENTRAIL_COMPACT_LOCAL_MODEL`, or a
hosted `OPENAI_API_KEY`, add `--model` to exercise the product's actual selector.
With a running local Ollama model, add `--downstream` to run the separate
patch-proposal and executable-verifier check; temporary selected-log artifacts
are removed when the script exits.
Add `--schema-context` to give the patch model the fixture's synthetic edit
schema while retaining the same selected-log packs and verifier.
