# Connected retrieval fixture v2

Fixture SHA-256: `4aec1c0d2d485d60748b11ad88b38839ce927ddda161ddf25060d1ed31d693f2`.

Run `cargo test -p evidentrail-cli frozen_connected_retrieval_v2_reports_graph_ablation_and_recent_baseline -- --nocapture` to reproduce the results from [`fixtures/connected-retrieval-v2.json`](../fixtures/connected-retrieval-v2.json). Each case inserts its labeled records and deterministic noise groups into a source-bound encrypted corpus. Four cases use 300 newer groups; two bracket the required clue with 600 and 800 error groups. All policies have the same 4,096-byte raw-output cap. The recent baseline returns up to 12 newest group representatives; the connected policies use the same indexed candidate and output path as the product. The test runs both a selector that retains the first advertised IDs and a simple deterministic severity selector in place of a model. The first-ID selector is not a true candidate-recall upper bound because it is still limited to 12 output lines.

| Case | First-ID selector with graph | Deterministic severity selection | Lexical only | Recent baseline |
| --- | ---: | ---: | ---: | ---: |
| Old rare failure | 1/1 | 1/1, 0 irrelevant | 1/1 | 0/1 |
| Graph-linked clue | 2/2 | 2/2, 0 irrelevant | 1/2 | 0/2 |
| Wording mismatch | 1/1 | 1/1, 0 irrelevant | 1/1 | 0/1 |
| Wording mismatch amid 300 newer errors | 1/1 | 1/1, 11 irrelevant | 1/1 | 0/1 |
| Middle clue amid 600 surrounding errors | 1/1 | 1/1, 11 irrelevant | 1/1 | 0/1 |
| Dense middle clue amid 800 surrounding errors | 1/1 | 1/1, 11 irrelevant | 1/1 | 0/1 |

The older-error case initially missed the billing line when the fallback took only the newest 256 severe groups. Old/new sampling recovered that case, but a clue in the middle of 600 errors was still absent from the candidate pool. Timeline sampling recovered that case but missed a denser 800-error case. The fallback now includes indexed representatives from rare and common services alongside samples from the ends and eight interior time anchors; the billing clue is present in the 800-error candidate set and selected output. All error-storm cases report the candidate pool as truncated. The recent baseline emitted 12 irrelevant lines per case.

These are **synthetic results**, not evidence that the hosted or local model chooses the right IDs, that an arbitrary clue survives a larger or skewed error pool, or that downstream coding succeeds. Service and timeline sampling still cannot guarantee candidate recall under a fixed cap. Connected queries now have bounded model-selected service-directory paging, but this fixture does not measure live model decisions or its added latency and cost; a separate test exercises exact service-ID validation. The deterministic selector made no external model call and therefore incurred no model API cost. The test prints one local selection-time observation per case; those microsecond values are not a latency distribution or service-level claim. Required next evaluations include frozen real-world labeled corpora, actual local and hosted model selectors at matched budgets, graph ablation across more service topologies, repeated latency and cost measurements, downstream fixes, and security failure cases.
