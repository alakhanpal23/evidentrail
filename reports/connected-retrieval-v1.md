# Connected retrieval fixture v1

Archived first evaluation from commit `d72694d`. Check out that commit to
reproduce this report with its original selector; the current retrieval
evaluation is [v2](connected-retrieval-v2.md).
Fixture SHA-256: `a19348b07213cbe366cc5b2ae9e823d00d7f496a9251965bce59b3f7ec4b5780`.

Run `cargo test -p evidentrail-cli frozen_connected_retrieval_reports_graph_ablation_and_recent_baseline -- --nocapture` to reproduce the results from [`fixtures/connected-retrieval-v1.json`](../fixtures/connected-retrieval-v1.json). Each case inserts its labeled records and 300 newer, distinct noise groups into a source-bound encrypted corpus. All policies have the same 4,096-byte raw-output cap. The recent baseline returns up to 12 newest group representatives; the connected policies use the same indexed candidate and output path as the product, with an all-candidate selector in place of a model.

| Case | Graph candidates: required lines | Lexical only: required lines | Recent baseline: required lines | Finding |
| --- | ---: | ---: | ---: | --- |
| Old rare failure | 1/1 | 1/1 | 0/1 | Indexed terms preserve the old error despite newer noise. |
| Graph-linked clue | 2/2 | 1/2 | 0/2 | One explicit service edge contributes the otherwise missed ledger record. |
| Wording mismatch | 1/1 | 1/1 | 0/1 | A bounded high-severity fallback covers this zero-term-match case. |

The connected policies emitted 0 irrelevant lines in these three small cases. The recent baseline emitted 12 irrelevant lines per case. These figures are **retrieval-stage synthetic results**, not evidence that the hosted or local model chooses the right IDs, that the fallback works with many unrelated severe groups, or that downstream coding succeeds. The matcher still has a hard candidate cap; a truncated pool must remain visible in query metadata. Required next evaluations include frozen real-world labeled corpora, model and deterministic selectors at matched output budgets, graph ablation across more service topologies, latency and cost, downstream fixes, and security failure cases.
