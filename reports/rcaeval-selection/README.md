# Ten-case RCAEval evidence-selection probe

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
