# RCAEval evidence-selection probes

This is a **selection-only** result. No hosted model was called, and no
root-cause diagnosis was scored. The input question was the same in every case:
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
inspected and adjusted selection on a subset of these cases. No LLM was run;
its service-plus-fault score remains unmeasured. The baseline shows that a
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
