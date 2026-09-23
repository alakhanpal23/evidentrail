# RCAEval evidence-selection probes

Most probes here are **selection-only**. The local LLM pilots below also score
root-cause hypotheses; no hosted model was called. The input question was the same in every case:
“Which service and failure mode caused this incident?” It did not name the
labeled service. The probe used metrics only, so public logs that may contain
credentials were not sent to a provider or committed here.

- Evidentrail code revision: `e6488d3`
- Dataset: [`phamquiluan/RCAEval`](https://huggingface.co/datasets/phamquiluan/RCAEval), revision `afeacb11bcc94dadfd1c8f483ee4377b2b8b614e`
- Runtime: Rust 1.88.0, Python 3.9, PyArrow 21.0.0
- Window: 300 seconds before and after each injected fault
- Model-visible limit: 24 metric summaries; five or more points required in each half-window
- Cases: six `catalogue` fault types plus `carts` memory, `orders` disk, `payment` delay, and `user` socket

Reproduce after `cargo build -p evidentrail-cli --bin evidentrail` and
`python3 -m pip install pyarrow==21.0.0`:

```sh
python3 scripts/rcaeval-log-probe.py \
  --with-metrics --metrics-only --generic-question \
  re2ss_catalogue_cpu_1 re2ss_catalogue_mem_1 \
  re2ss_catalogue_disk_1 re2ss_catalogue_delay_1 \
  re2ss_catalogue_loss_1 re2ss_catalogue_socket_1 \
  re2ss_carts_mem_1 re2ss_orders_disk_1 \
  re2ss_payment_delay_1 re2ss_user_socket_1
```

The case-level aggregate output is in `ten-case-metric-only.jsonl`. The
largest-shift metric for the labeled service was visible in all 10 cases, with
at least four metric source-line examples from that service in each case. All
reports remained `partial` because other metric series were omitted. The
largest shift often differed from the injected fault type, so this result
does **not** establish accurate diagnosis or even that the selected metric is
causal. It establishes only that the model would have inspectable evidence
from the labeled service without being told that service in the question.

A deliberately simple comparator chooses the service with the largest bounded
before/after metric shift. It matches the labeled root service in **9 of 10**
cases. That is a small, selected sample, not a general accuracy estimate, but
it sets a concrete bar for the hosted model. The metric selected as largest
within the correct service can still be a symptom of a different injected
fault.

## Expanded RE2 Sock Shop probe

### Confirmed-incident precedent baseline (exploratory)

An optional history of **confirmed**, labeled incidents may help distinguish
failure modes when the current metric peak is only a symptom. To test that
idea without adding a benchmark-specific classifier to the product,
`scripts/score-rcaeval-precedents.py` uses replicate 1 of each service/fault
pair as prior incidents and scores replicates 2 and 3. It first chooses a
service using the largest metric shift, then finds the same-service prior with
the closest equal-weight, log-scaled vector of six metric-family shifts. The
prior's fault label is its prediction. The rule was fixed before probing
Online Boutique and Train Ticket; no LLM was called. These are repeated
injections from one public synthetic benchmark, not independent real-world
incidents or a held-out product score.

| RCAEval system | Window | Test cases | Largest-shift joint hits | Precedent joint hits | Service hits |
|---|---:|---:|---:|---:|---:|
| Sock Shop | ±300 s | 60 | 27 | 36 | 57 |
| Online Boutique | ±300 s | 60 | 22 | 40 | 52 |
| Train Ticket | ±150 s | 60 | 18 | 30 | 35 |

The two methods use the same selected service in each case; the improvement
is in fault-type selection. With matching-service priors withheld, precedent
joint hits were 30, 36, and 24 respectively. Train Ticket required a shorter
window because its ±300-second metric input exceeded Evidentrail's 16 MiB
per-input limit; its baseline and precedent scores both use ±150 seconds.
The service selector is the limiting factor there. A simple metric-dominance
abstention rule was also checked on Sock Shop and remained wrong in 20 of 41
cases where it answered, so dominant shifts should not be treated as causal
confidence.

The probe emits only aggregate metric-family shifts and case identifiers. To
reproduce the three complete public datasets, use `--all-re2-ss`,
`--all-re2-ob`, or `--all-re2-tt` with `--with-metrics --metrics-only
--generic-question`; add `--window-seconds 150` for Train Ticket. Pass each
resulting JSONL file to `scripts/score-rcaeval-precedents.py`. These findings
justify testing an explicitly supplied, operator-labeled incident history.
Evidentrail's optional `--confirmed-incidents` input now supplies such matches
as advisory context to its LLM. The input labels are operator assertions, not
independently verified facts. The model still must cite current source lines,
and causal fault accuracy needs evaluation on independent incidents.

[`nine-case-local-precedent-paired.jsonl`](nine-case-local-precedent-paired.jsonl)
records a small paired local-model pilot. The same generic question and
metric-only ±300-second window were used with and without a 30-case history
built from replicate-1 injected labels. `qwen3:14b` ran with a loaded 32,768
token context. The nine replicate-2 cases were selected adaptively during
development: all six `catalogue` fault types, `carts` memory and disk, and
`payment` disk. Exact service-plus-fault top-1 hits were **4/9 without**
history and **5/9 with** history. Memory on `catalogue` changed from an
incorrect CPU label to the correct memory label. The other eight did not
change their correctness, including `payment` disk, where the closest prior
incorrectly suggested memory. All 18 runs returned partial reports with
source citations. The artifact records case-level outcomes and the exact
binary SHA-256 of each arm; a CLI parsing/help edit caused one batch to use a
different binary, without changing the diagnosis logic.

This is a development smoke test, not a reliable estimate of uplift. The
nearest-neighbor baseline above predicts many faults correctly only because
the training and test cases repeat synthetic injection patterns. The live LLM
sometimes ignores a useful prior and sometimes rejects a misleading one. A
larger frozen test across services and independent, approved real incidents
is still required before claiming improved diagnosis accuracy.

The next [case list](frozen-precedent-replicate3-cases.json) was committed
before model inference. It selected two replicate-3 cases per fault type by a
fixed SHA-256 rule, spanning all five Sock Shop services. The
[`frozen12` paired artifact](frozen12-local-precedent-paired.jsonl) uses the
same clean Evidentrail binary, local model, question, and ±300-second metric
window in both arms. Exact top-1 service-plus-fault hits were **7/12 with or
without history**, identical to the largest-shift baseline on these cases.
Top-3 joint hits were 9/12 without and 10/12 with history, but no additional
case reached rank one. All 24 reports were partial and asked for more
evidence. This does **not** validate a diagnosis-accuracy benefit from the
history option. The current model continues to struggle with loss and socket
faults; the next iteration should use additional current-incident evidence,
especially trace timing and status changes, rather than stronger wording for
the same prior labels.

`ninety-case-metric-only.jsonl` records all 90 pinned RE2 Sock Shop cases at
Evidentrail revision `7202a7b`. Reproduce with:

```sh
python3 scripts/rcaeval-log-probe.py \
  --with-metrics --metrics-only --generic-question --all-re2-ss
```

The 24-summary model context contained a metric from the labeled service in
all 90 cases. The largest-shift metric for that service was visible in all 90.
A naive baseline that selects the service of the single largest bounded metric
shift identifies the labeled service in **84/90** cases. If it also maps that
metric's name to a fault (`cpu`, `mem`, `socket` directly; `diskio` to `disk`,
`latency-*` to `delay`, `error` to `loss`), it predicts the injected fault type
in **42/90** and the correct service-plus-fault pair in **37/90**.

| Fault | Cases | Naive service | Naive fault | Joint |
|---|---:|---:|---:|---:|
| CPU | 15 | 15 | 15 | 15 |
| Delay | 15 | 12 | 15 | 12 |
| Disk | 15 | 14 | 7 | 7 |
| Loss | 15 | 13 | 2 | 0 |
| Memory | 15 | 15 | 3 | 3 |
| Socket | 15 | 15 | 0 | 0 |

This is an exploratory public-data baseline, not a hidden test. We previously
inspected and adjusted selection on a subset of these cases. No LLM was run
for the 90-case baseline; its model service-plus-fault score remains unmeasured.
The baseline shows that a
model must add value beyond a strong service-localization heuristic, especially
for fault-type discrimination.

The six `catalogue` fault-1 cases illustrate why service localization and
failure-mode diagnosis need separate scores. In the metric-only selection
window, the disk case has no `diskio` signal for `catalogue`, and the loss case
has no `error` signal for that service. The socket case does expose a socket
change, but its CPU relative shift is much larger. These are properties of the
selected summaries, not evidence that the injected faults did not occur. A
metric-only model should be allowed to return `unknown` or abstain when the
visible signals cannot distinguish the failure mode; a fault-type hit rate
without that abstention count would overstate diagnostic usefulness.

### Local LLM diagnostic pilot

[`twelve-case-local-qwen3-14b-16k.jsonl`](twelve-case-local-qwen3-14b-16k.jsonl)
records `qwen3:14b` (Ollama manifest `bdbd181c33f2`) on the six fault-1
cases each for `catalogue` and `carts`, with a generic question and metric-only
input. Ollama reported a **16,384-token** loaded context and no prompt
truncation warnings. All 12 cases returned valid partial reports with direct
source citations. The model identified the labeled service in **12/12**, but
the exact service-plus-fault pair in only **4/12**, the same four found by the
largest-metric-shift baseline. It added **zero** joint hits and averaged
**34.661 seconds** per case. This selected public development sample does not
qualify a model or establish accuracy on held-out incidents.

### Local log-and-metric pilot

[`six-case-local-qwen3-14b-32k-challenger.jsonl`](six-case-local-qwen3-14b-32k-challenger.jsonl)
records all six `catalogue` fault-1 cases with logs and metrics, a generic
question, and the local `qwen3:14b` model under a loaded 32,768-token Ollama
context. The two batches of two and four cases used the same Evidentrail
revision (`be30240`) and executable SHA-256, recorded in the artifact. Before
analysis, the probe redacted sensitive field values in **3,408 log events**;
the product's citations refer to those sanitized input lines. No raw logs or
model explanations are committed.

All **6/6** cases returned partial reports. The leading hypothesis identified
the labeled service in **6/6**, but the exact service-plus-fault pair in only
**2/6** (CPU and delay), the same two as the naive largest-metric-shift
baseline. The model added **zero** joint hits. It launched an independent
metric-only challenge in five cases where log-heavy hypotheses conflicted
with stronger metric changes, discarded three invalid hypotheses across the
run, and averaged **122.351 seconds** per case. The remaining fault labels
were wrong: memory, disk, and socket were called CPU; loss was called delay.
All cases requested more evidence. These are selected public development
cases, not a held-out accuracy estimate or a qualified RCA model.

The log stream explains the challenge. In the CPU case, `queue-master` emitted
1,224 alerts before and 1,224 after the incident while `catalogue` had the
dominant CPU change. Alert volume alone repeatedly pulled the model toward
the wrong service. Temporal alert counts and the metric-only challenger
corrected service localization in this small sample but did not solve
fault-type discrimination. Direct metric or log citations validate the
reported source line, not the causal fault label.

Reproduce with Ollama configured for at least a 32K context, then run:

```sh
EVIDENTRAIL_ANALYZE_LOCAL_MODEL=qwen3:14b \
  python3 scripts/rcaeval-log-probe.py --with-metrics \
  --generic-question --live-model \
  re2ss_catalogue_cpu_1 re2ss_catalogue_mem_1 \
  re2ss_catalogue_disk_1 re2ss_catalogue_delay_1 \
  re2ss_catalogue_loss_1 re2ss_catalogue_socket_1 \
  > local-combined.jsonl
python3 scripts/score-rcaeval-live.py local-combined.jsonl
```

The committed artifact was split into two batches for execution; its header
records the identical executable used for both batches. Local model outputs
can vary across runs, so score the full denominator and retain failures.

The earlier [six-case artifact](six-case-local-qwen3-14b-truncated.jsonl)
used Ollama's 4K default context. Server logs showed a roughly 7.7K-token
prompt truncated to about 2K tokens, so its four valid reports and zero joint
hits are **not** a fair model-quality comparison. Evidentrail now checks the
loaded local context and rejects windows under 16K rather than presenting
answers produced under that known-bad setting.

Start Ollama with a 16K context in one shell, then run the probe in another:

```sh
OLLAMA_CONTEXT_LENGTH=16384 ollama serve
```

```sh
EVIDENTRAIL_ANALYZE_LOCAL_MODEL=qwen3:14b \
  python3 scripts/rcaeval-log-probe.py --with-metrics --metrics-only \
  --generic-question --live-model \
  re2ss_catalogue_cpu_1 re2ss_catalogue_mem_1 re2ss_catalogue_disk_1 \
  re2ss_catalogue_delay_1 re2ss_catalogue_loss_1 re2ss_catalogue_socket_1 \
  re2ss_carts_cpu_1 re2ss_carts_mem_1 re2ss_carts_disk_1 \
  re2ss_carts_delay_1 re2ss_carts_loss_1 re2ss_carts_socket_1
```

## Combined log-and-metric selection probe

`six-case-combined.jsonl` records the six `catalogue` fault types with both
logs and metrics, a generic question, and no hosted model call. Reproduce with:

```sh
python3 scripts/rcaeval-log-probe.py --with-metrics --generic-question
```

The earlier `a29e6fb` selection reserved no log space when metrics were
present. It exposed 1, 1, 1, 1, 4, and 1 log groups across these six cases.
With an 8 KiB log reserve, the counts are 2, 3, 2, 2, 5, and 2. The model
still sees 19–20 metric summaries (previously 24), including the labeled
service's largest-shift metric in all six cases. A shorter, wider retrieval
inventory includes every omitted log group in these six cases; the earlier
16 KiB inventory included only 56 of 98 omitted groups in the CPU case.

This is evidence-coverage testing, not root-cause accuracy. All reports are
`partial` because many groups and metric series remain outside the final
diagnosis window. A live model may choose poor groups or interpret visible
signals incorrectly. The exact line-citation verifier checks attribution,
not whether a causal claim is true.

## All 90 cases with logs and metrics

`ninety-case-combined.jsonl` is the aggregate output of the same generic
question and ±300-second window across every pinned RE2 Sock Shop case:

```sh
python3 scripts/rcaeval-log-probe.py \
  --with-metrics --generic-question --all-re2-ss
```

All 90 cases ran within the product's input limits and returned `partial`
selection reports, with no product errors. The strongest metric shift within
the labeled service was visible in all 90. Only seven cases had any alert
group from the labeled root service. Those seven contained 79 such groups;
14 were initially visible and all 79 were either visible or listed in the
model's group-selection inventory. This is a **retrieval opportunity**, not
proof the model chooses those groups or diagnoses the cause.

Nine high-noise cases exceeded the 24 KiB group-inventory budget, leaving
some non-root groups unlisted (up to 104 in one case). The inventory rotates
across services, which preserved access to every labeled-root alert group in
this dataset. That result does not guarantee coverage on another incident
distribution. The model may expand at most four groups per run, and no hosted
model was called for this probe.

This run also normalizes embedded date, clock-time, and 13-digit timestamp
shapes when grouping alerts, while preserving status codes and exact source
lines. Compared with the [pre-normalization run](https://github.com/alakhanpal23/evidentrail/blob/b9a20d8/reports/rcaeval-selection/ninety-case-combined.jsonl),
total alert groups fell from **10,752 to 9,508** across the 90 cases; 10
cases changed. Unlisted inventory groups fell from **1,501 to 259**. All 79
labeled-root alert groups, their 14 initially visible groups, and all 90
labeled-service strongest metric signals stayed in the same coverage states.
This checks noise reduction and evidence availability, not whether the grouped
alerts carry the right causal story.

## Trace-observed service graph probe

Sock Shop has no traces in this pinned dataset. `six-case-trace-graph.jsonl`
therefore uses six selected RE2 Online Boutique cases spanning all six fault
types and five labeled root services. It passes metrics plus in-window trace
spans, with no logs or hosted model call. Reproduce with:

```sh
python3 scripts/rcaeval-log-probe.py \
  --with-metrics --metrics-only --with-traces --generic-question \
  re2ob_checkoutservice_cpu_1 re2ob_currencyservice_mem_1 \
  re2ob_emailservice_disk_1 re2ob_productcatalogservice_delay_1 \
  re2ob_recommendationservice_loss_1 re2ob_checkoutservice_socket_1
```

All six returned nine observed cross-service edges from unambiguous
same-trace parent-child span joins. Across 942,308 in-window spans, 883,331
had matched parents. Another 532 parent references were missing, 23 pointed
to ambiguous parents, and 96 span rows had duplicated identities; those
uncertain rows yielded no edge. The labeled service's strongest metric shift
remained visible in all six cases. Each report records example parent and
child `T<n>` source-line IDs and SHA-256 digests per edge. These cases demonstrate graph extraction and
provenance, not cause identification; the six selected cases are not a held-out
accuracy estimate.

### One live case with log evidence and a trace graph

[`one-case-local-ob-loss-32k-graph.jsonl`](one-case-local-ob-loss-32k-graph.jsonl)
records a local `qwen3:14b` run on
`re2ob_recommendationservice_loss_1` using logs, metrics, and trace spans.
The artifact records Evidentrail revision `ba04bfe`, the executable digest,
and a clean worktree. The report derived **nine** service edges, kept all
**five** alert groups from the labeled root service visible, rejected **two**
invalid model retrieval IDs, and returned a partial report in **31.247
seconds**. Its leading service was correct (`recommendationservice`), but
its fault label was `delay` rather than the injected `loss`. The simple metric
baseline also chose delay. This single selected case verifies the live
log-plus-metric-plus-graph path and its safe fallback on invalid group IDs;
it does not demonstrate a causal accuracy gain from the graph.

Reproduce with a local model and a 32K Ollama context:

```sh
EVIDENTRAIL_ANALYZE_LOCAL_MODEL=qwen3:14b \
  python3 scripts/rcaeval-log-probe.py --with-metrics --with-traces \
  --generic-question --live-model re2ob_recommendationservice_loss_1 \
  > local-graph.jsonl
python3 scripts/score-rcaeval-live.py local-graph.jsonl
```

### Full Online Boutique trace selection scan

[`ninety-ob-trace-operation-selection.jsonl`](ninety-ob-trace-operation-selection.jsonl)
records a fixed-binary, selection-only pass over all 90 pinned RE2 Online
Boutique injections (15 each of CPU, memory, disk, delay, loss, and socket).
The header records Evidentrail revision `d87c8f1`, a clean worktree at launch,
and the SHA-256 of the immutable executable copy. All **90/90** reports
completed without product errors. The 14,494,071 in-window span rows yielded
nine observed cross-service edges per case; 13,601,395 rows had matched
parents. Missing, ambiguous, or duplicated span identities were excluded from
edge construction.

Operation-level nonzero status was present in **12/15 loss** cases and **6/15
memory** cases, and absent in the other four fault families. The strongest
operation signal carried an explicitly typed gRPC `UNAVAILABLE` status in
11/15 loss and 3/15 memory cases. This is a useful retrieval signal for a
diagnostician to inspect alongside metrics, logs, and dependency direction;
it does not uniquely identify packet loss. This pass contains no LLM
diagnosis and is **not** an accuracy score.

Reproduce after building the CLI by copying the executable to a fixed path
before the scan:

```sh
cp target/debug/evidentrail /tmp/evidentrail-fixed
python3 scripts/rcaeval-log-probe.py --binary /tmp/evidentrail-fixed \
  --with-metrics --metrics-only --with-traces --generic-question --all-re2-ob \
  > ninety-ob-trace-operation-selection.jsonl
```

### Frozen metric versus metric-and-trace local-model comparison

The [12-case list](frozen-ob-trace-paired-cases.json) was committed before
inference. For each fault family, it selects two replicate-3 Online Boutique
case names by a fixed SHA-256 rule, without looking at their telemetry or model
outputs. The [selection pass](frozen-ob-trace-selection.jsonl) completed all
12 cases, covering 1,964,133 trace span rows, and found nine observed service
edges in each case. The [metric-only arm](frozen-ob-metric-only-live.jsonl)
and [metric-and-trace arm](frozen-ob-metric-trace-live.jsonl) used the same
immutable Evidentrail executable, `qwen3:14b`, generic question, and ±300-second
metric window. All 24 live analyses completed without product errors. Their
headers show different script revisions only because the live metric-and-trace
probe timeout was raised from 75 to 180 seconds; neither arm timed out, and
the product binary SHA-256 is identical.

| Outcome on the same 12 cases | Metrics only | Metrics + traces |
| --- | ---: | ---: |
| Exact top-1 service and fault matches | 3 | 5 |
| Wrong top-1 attributions | 2 | 7 |
| Abstentions | 7 | 0 |
| Mean local-model latency | 34.5 s | 58.1 s |
| Verified `T<n>` source-line citations | 0 | 2 |

The simple largest-metric-shift baseline also got **5/12** exact pairs. Trace
context helped the model answer both delay cases and one socket case that it
previously left unanswered, but it lost one previously correct CPU and one
disk answer. Neither loss case became an exact match. The two trace citations
occurred in **wrong** loss diagnoses. This is not evidence that the graph or
RPC-status context improves diagnostic accuracy: it increased useful answers
and false attributions together. A valid citation proves an observed span
existed, not that the proposed fault label follows from it. The set is small,
synthetically injected, and from the same benchmark used during development;
production incident accuracy remains unverified.
