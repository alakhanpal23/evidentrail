# Connected corpus scale exercise (local, 2026-09-23)

The ignored `connected_compaction` scale tests exercise the connected product's
encrypted corpus and global log-selection path. They insert 100,000 and
1,000,000 distinct source records and template groups in 512-record pages.
Three labeled error clues occur at the start, middle, and end; the rest are
unique routine info lines. The deterministic test selector chooses advertised
error group IDs. Both a clue-word query and a wording-mismatch fallback query
use a 4,096-byte raw-log budget. Each selected clue is checked against its
stored original bytes and exact repeat count.

| Records / groups | Ingest | Indexed query | Fallback query | Required clues |
| ---: | ---: | ---: | ---: | ---: |
| 100,000 / 100,000 | 12,536 ms | 21 ms | 27 ms | 3/3 in both queries |
| 1,000,000 / 1,000,000 | 191,762 ms | 351 ms | 270 ms | 3/3 in both queries |

These are single **debug-build local observations** on an Apple M5 Pro,
24 GiB RAM, Rust 1.98.0. They are not p50/p95 measurements or a production
latency target. The fixture contains synthetic JSON logs and only three severe
groups; it does not test a noisy error storm, provider transport or sync,
model quality, directory-page selection, downstream agent success, or
concurrent users. The frozen [retrieval fixture](connected-retrieval-v2.md)
tests some noisy candidate behavior at much smaller scale. Realistic labeled
large histories and matched-budget model/baseline evaluations are still needed.

Reproduce individually with:

```sh
cargo test -p evidentrail-cli large_connected_history_returns_exact_old_middle_and_new_clues -- --ignored --nocapture
cargo test -p evidentrail-cli million_record_connected_history_returns_exact_old_middle_and_new_clues -- --ignored --nocapture
```
