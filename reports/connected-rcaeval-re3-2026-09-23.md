# Connected log selection on RCAEval RE3 (local, 2026-09-23)

This opt-in probe exercises the connected encrypted corpus with **all logs**
from three [RCAEval](https://github.com/phamquiluan/RCAEval) Online Boutique
code-fault cases. `scripts/eval-rcaeval-connected.py` downloads only the three
pinned `logs.parquet` files at dataset revision
`afeacb11bcc94dadfd1c8f483ee4377b2b8b614e`, checks each SHA-256, and
converts the timestamp, service, and message columns to deterministic NDJSON.
The conversion and original Parquet files remain temporary. No incident time
window, metrics, traces, root-service name, or fault label is given to the
selector. The task is the same in every case: “Investigate service errors and
failed requests.” The raw-log output budget is 32 KiB for every arm.

| Case (labeled service) | Source lines | Indexed groups | Candidate groups | First-ID root lines, before → after diversity safeguard | Severity root lines | Recent root lines |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `re3ob_cartservice_f1_1` (cartservice) | 65,025 | 6,036 | 5 | 6/9 → 6/9 | 6/9 | 4/12 |
| `re3ob_emailservice_f1_1` (emailservice) | 70,076 | 6,422 | 140 | 0/12 → 2/13 | 0/12 | 0/12 |
| `re3ob_adservice_f3_1` (adservice) | 70,558 | 6,673 | 2 | 1/3 → 1/3 | 0/2 | 0/12 |

The 140-group email case exposed a specific retrieval-stage failure. Its
service was advertised in an intermediate page, but page-local first-ID
selection pruned it before the final selector. The previous metadata said
`candidate_pool_truncated=false`, which was true for index retrieval but hid
the intermediate pruning. The connected pack now reports
`prefinal_pruned_groups` separately; this case reports 114 groups pruned
after the safeguard (116 before). Intermediate pages carry one group from
each of up to 16 sparsely represented source/service pairs, prioritizing
severe and rare groups within a pair. The final selector now sees the email service. A
deterministic first-ID selector returns two of its original log lines; a
severity-only selector still returns none. The result demonstrates candidate
coverage and an improvement in this narrow proxy, **not** that those two lines
explain the failure.

Every returned line is compared byte-for-byte with its encrypted source
record. The three cases are repeated injections from one benchmark system,
and labeled root-service membership is not a verified relevance judgment for
each line. No coding agent, provider connection, or downstream fix was
measured. Single debug-build ingestion observations were about 7–9 seconds per
case; deterministic query observations were 1–20 ms. Those are not latency
distributions or production promises. The 16-service
reservation is bounded and cannot guarantee rare evidence from every service;
the pruning count makes that limitation inspectable.

## Local model arms

The same opt-in script ran the product's actual ID-only selector with two
installed local Ollama models at a 32K context. Both models returned only
source-exact records, but each included the labeled service in **1/3** cases,
versus **3/3** for the first-ID baseline. The model received no label or root
service name. The measurements are single runs on this Mac; the larger prompt
in the email case makes latency conspicuous.

| Case | Qwen3 14B root lines / selected lines | Qwen3 query | Qwen2.5-Coder 7B root lines / selected lines | Qwen2.5 query |
| --- | ---: | ---: | ---: | ---: |
| Cart service | 6/9 | 3.8 s | 2/4 | 4.0 s |
| Email service | 0/12 | 91.8 s | 0/12 | 45.8 s |
| Ad service | 0/2 | 1.5 s | 0/2 | 0.6 s |

This is a negative qualification result for using either model as the
unconditional connected selector. It does not establish that the first-ID
lines are causally useful or that a hosted model would perform similarly.
The email case had 140 candidate groups and 114 prefinal groups pruned in
every arm; the sparse service reached the final model page, but neither model
selected it. A larger held-out set with line-level relevance labels and
downstream coding tasks is needed before choosing a model route.

A follow-up Qwen2.5-Coder 7B run used a stricter instruction to select the
smallest directly useful set. It again included the labeled service only in
the cart case (1/3), missing email and ad despite those services appearing in
the final advertised groups. The email model query took 41.5 seconds. A
separate BGL run showed only a small aggregate off-label reduction, so this
instruction was reverted. These are single local runs and root-service
membership remains a proxy, not a causal relevance judgment.

Reproduce with `python3 -m pip install pyarrow==21.0.0` and
`python3 scripts/eval-rcaeval-connected.py`. To add actual model selection,
configure `EVIDENTRAIL_COMPACT_LOCAL_MODEL` for a running Ollama model or
`OPENAI_API_KEY`, then pass `--model`. The local arms above used that same
command. It reports root-service presence, exact-source checks, latency, and
pruning at the same output budget; it still cannot establish causal evidence
or coding-agent task success. No hosted model arm has run.
