# Connected retrieval fixture v1

Run `cargo test -p evidentrail-cli frozen_connected_retrieval_reports_graph_ablation_and_recent_baseline -- --nocapture` to reproduce the results from [`fixtures/connected-retrieval-v1.json`](../fixtures/connected-retrieval-v1.json). Each case inserts its labeled records and 300 newer, distinct noise groups into a source-bound encrypted corpus. The last case makes the noise groups errors too. All policies have the same 4,096-byte raw-output cap. The recent baseline returns up to 12 newest group representatives; the connected policies use the same indexed candidate and output path as the product. The test runs both an all-candidate upper bound and a simple deterministic severity selector in place of a model.

| Case | Graph candidate upper bound | Deterministic severity selection | Lexical only | Recent baseline |
| --- | ---: | ---: | ---: | ---: |
| Old rare failure | 1/1 | 1/1, 0 irrelevant | 1/1 | 0/1 |
| Graph-linked clue | 2/2 | 2/2, 0 irrelevant | 1/2 | 0/2 |
| Wording mismatch | 1/1 | 1/1, 0 irrelevant | 1/1 | 0/1 |
| Wording mismatch amid 300 newer errors | 1/1 | 1/1, 11 irrelevant | 1/1 | 0/1 |

The error-storm case initially missed the old billing line when the fallback took only the newest 256 severe groups. The fallback now interleaves oldest and newest severe groups using an indexed, bounded scan, so this particular old clue enters the candidate pool. It still emits 11 irrelevant lines and reports the pool as truncated. The recent baseline emitted 12 irrelevant lines per case.

These are **synthetic results**, not evidence that the hosted or local model chooses the right IDs, that a different old clue survives a larger severe pool, or that downstream coding succeeds. The deterministic selector made no external model call and therefore incurred no model API cost. The test prints one local selection-time observation per case; those microsecond values are not a latency distribution or service-level claim. Required next evaluations include frozen real-world labeled corpora, actual local and hosted model selectors at matched budgets, graph ablation across more service topologies, repeated latency and cost measurements, downstream fixes, and security failure cases.
