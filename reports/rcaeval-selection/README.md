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
