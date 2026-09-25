# Evidentrail

**Give coding agents the logs that matter.** Connect a log source, describe the bug, and hand the agent a focused pack of **original log lines** it can inspect and expand. Evidentrail searches accessible history without requiring an incident time window, groups repeated events, and uses the task and observed service relationships to find candidates.

The result is small enough to fit an agent workflow, yet every returned line points back to its source. No paraphrased “evidence,” no invented log text. Coverage and truncation travel with the pack so the agent knows what it has actually seen.

| Verified fixes | Log pack | Indexed search |
| ---: | ---: | ---: |
| **7** | **16 of 2,000 lines** | **351 ms at 1M records** |
| Current route in a 12-bug held-out repair study; the no-logs arm also fixed 7. | One 4 KiB BGL task; exact lines, with expansion available. | One local debug-build synthetic query; excludes model and sync time. |

These are [measured examples](#benchmarks), not production guarantees. Evidentrail is a **research preview**: the connected CLI and MCP path works locally, while live-provider coverage and a repair advantage over simple baselines remain unproven. See the [full benchmark ledger](docs/BENCHMARKS.md) for every connected-path experiment and its limits.

## What it does

- **Connect and keep up:** checkpointed backfill and continuous sync for read-only CloudWatch log groups and Sentry project error events. Each source has its own encrypted corpus and authorization checks.
- **Compress without rewriting evidence:** group repeated templates for indexing, then return selected **exact source records**, source IDs, and repeat counts under a raw-byte budget. Expand a selected record into bounded chronological neighbors.
- **Search by task, not by guessed timestamp:** lexical matches, severity, service summaries, an explicit-peer service graph, and time-spread fallback form a bounded candidate pool. A local or hosted selector chooses only advertised IDs.
- **Expose uncertainty:** source freshness, failed syncs, candidate limits, and output truncation travel with the result, separate from the log text.
- **Learn cautiously:** selected-line feedback is stored per source. Independently labeled development records can reorder source-local candidates in a shadow route; held-out repairs, measured cost, versioned promotion, and rollback gate any live change. Ratings alone do not automatically train ranking.

## System architecture

```mermaid
flowchart LR
    A["Read-only log sources<br/>CloudWatch · Sentry errors"] --> B["Authorize + checkpointed sync"]
    B --> C["Encrypted, source-bound corpus<br/>original records + template index"]
    C --> D["Candidate search<br/>task terms · severity · service graph · time spread"]
    D --> E["Bounded selector<br/>chooses advertised IDs"]
    E --> F["Exact log pack<br/>source IDs · repeat counts · coverage"]
    F --> G["CLI / MCP coding agent"]
    G --> H["Result-scoped expansion + feedback"]
    H -. "independent labels; shadow evaluation" .-> D
```

The model can choose records; it cannot invent the returned log text. Source bytes remain available for verification and expansion. The service graph is built only from relationships observable in logs, such as explicit peer-service fields; it is not an inferred map of every dependency. [Design and limits](docs/LOG_ONLY_PRODUCT_PLAN.md) · [Source-coverage gates](docs/SOURCE_COVERAGE_GATES.md) · [Learning policy](docs/ROUTE_POLICY.md)

## Try it

Requires macOS, Rust 1.88+, a read-only AWS profile for the CloudWatch example, and either a running [Ollama](https://ollama.com/) model with a 32K context or `OPENAI_API_KEY` for hosted selection. Start with a local model to keep log selection local.

```sh
cargo build --release -p evidentrail-cli --bin evidentrail
target/release/evidentrail sources setup
target/release/evidentrail sources connect-cloudwatch \
  --account 123456789012 --region us-west-2 \
  --log-group /aws/example --profile my-readonly-profile
target/release/evidentrail sources sync
target/release/evidentrail sources list

EVIDENTRAIL_COMPACT_LOCAL_MODEL=qwen3:14b \
  target/release/evidentrail logs \
  --task "Find the logs that explain failed checkout requests" \
  --max-raw-bytes 32768
```

`sources setup` reports the next connection, sync, recovery, or query action without exposing credentials. `logs` searches connected, currently authorized sources and writes selected original records as JSONL; source status and truncation metadata go to stderr. The byte budget limits raw log bytes, not rendered JSON or model tokens. For an agent tool loop, run `target/release/evidentrail serve-mcp` and use `evidentrail_connected_logs` followed by `evidentrail_connected_expand`. The expansion handle expires after 30 minutes and checks source access again.

For a single supplied file, `compact` is a separate, bounded local-input prototype:

```sh
EVIDENTRAIL_COMPACT_LOCAL_MODEL=qwen3:14b \
  target/release/evidentrail compact \
  --task "Find logs relevant to checkout failures" < app.log
```

The supplied-log path has a 16 MiB input limit and does not create a continuously synced corpus. [Full CLI and onboarding details](docs/LOG_ONLY_PRODUCT_PLAN.md) · [Source adapter contract](docs/SOURCE_ADAPTER_CONTRACT.md)

## Benchmarks

These are different experiments, each with its own corpus, selector, and budget. The repair studies measured real executable bugs; the retrieval and scale probes measured earlier stages of the product. **Neither held-out repair study qualified a new default route.**

| Experiment | Evidentrail result | Comparison and meaning |
| --- | --- | --- |
| [Frozen six-arm repair study](reports/learning-repair-2026-09-24/REPORT.md) | **7 verified fixes**; current route p95 end-to-end **48.1 s** | Twelve BugsInPy bugs, 1 KiB log budget: no logs **7**, first-ID **8**, severity **7**. Shadow memory on **4**, off **5**. All 72 agent edits independently verified; no repair gain established. |
| [Earlier five-arm repair study](reports/repair-study-2026-09-24/REPORT.md) | **7 verified fixes**; current route p95 end-to-end **76.4 s** | Eleven different held-out BugsInPy bugs, 1 KiB budget: no logs **6**, first-ID **5**, severity **4**, challenger **7**. Difference missed the paired significance gate. Different protocol; do not pool with the six-arm study. |
| [LogHub BGL, 12 task categories](reports/connected-loghub-bgl-2026-09-23.md) | Exact target-category line in **12 of 12** message-derived tasks | Deterministic first-ID and severity selectors also hit all 12; newest-group baseline hit **1**. This is a relevance proxy, not a repair result. |
| [RCAEval Sock Shop, seven full histories](reports/connected-rcaeval-labeled-2026-09-24.md) | **3 of 7** exact published lines; **7 of 7** matching templates with first-ID selection | Generic task over **596,494** source rows per case, 32 KiB output cap. Local Qwen2.5-Coder 7B got **1** exact line and **3** templates; selection remains difficult. |
| [Executable fault streams](reports/connected-executable-2026-09-24.md) | Earlier precursor plus failure symptom in **3 of 3** small streams | First-ID and local model both retained all candidates; severity and recent-only retained neither precursor. Synthetic downstream edits did not show an Evidentrail-specific advantage. |

| Scale and reduction | Measured result | What was actually timed or reduced |
| --- | --- | --- |
| [Connected encrypted corpus: **1 million logs**](reports/connected-scale-local-2026-09-23.md) | Ingest **191.8 s**; indexed query **351 ms**; fallback query **270 ms**; **3 of 3** planted clues returned exactly in both | One local debug-build run, 1 million distinct synthetic groups, 4 KiB pack, deterministic selector. Query times exclude ingestion, provider sync, and model inference. |
| [Connected encrypted corpus: 100,000 logs](reports/connected-scale-local-2026-09-23.md) | Ingest **12.5 s**; indexed query **21 ms**; fallback **27 ms**; **3 of 3** clues | Same single-run fixture and limits as the 1-million-log case. These are observations, not p95 latency targets. |
| [BGL grouping and output](reports/connected-loghub-bgl-2026-09-23.md) | **2,000 original lines → 1,374 template groups**; one task returned **16 exact lines** under 4 KiB | **31.3% fewer groups** and **99.2% fewer lines presented** for that task. Original bytes remain stored; neither figure is a storage-compression or general recall claim. |
| [RCAEval parser grouping](reports/connected-rcaeval-labeled-2026-09-24.md) | **379,858 → 353,222 groups** across seven pinned histories | **7.0% fewer groups** after parser improvements, with exact original records retained; measured deterministic recall did not improve. |
| [Repair-study pack preparation](reports/learning-repair-2026-09-24/pack-lock.json) | Current selector: **4.5 s median**, **12.6 s p95** | Twelve local cases; includes scratch-corpus loading and model selection, excludes live provider catch-up and agent editing. |

The [benchmark ledger](docs/BENCHMARKS.md) also covers local-model pilots, synthetic graph/learning probes, the older million-record repository-component test, and failed experiments. It distinguishes the current connected path from the older `analyze`/`brief` research path. Source-exact output is verified in the cited retrieval studies. Model dollar costs in the repair report are **API list-price proxies**, not billing receipts; unavailable provider-metered cost blocks learning-route promotion.

## Continuous learning, with an evidence gate

Feedback from a selected result is attached to its exact source record and task. User ratings are weak signals, so they do not silently change cross-task ranking. The source-local learner uses separately labeled development records (blind model annotations in the current study), evaluates memory-on versus memory-off on frozen repairs, and stays in shadow until the downstream benefit and cost gates pass. Route versions retain a training fingerprint and support atomic rollback; stale labels or revoked sources cause selection to fall back to the current route.

Today, that gate **did not pass**: memory on fixed 4 bugs versus 5 with memory off in the 12-bug study. This is an active research area, not a shipped self-improving accuracy claim. [How the route is governed](docs/ROUTE_POLICY.md) · [Study protocol](docs/LEARNING_REPAIR_STUDY.md)

## Release status

| Surface | Current state |
| --- | --- |
| CloudWatch connected logs | Read-only registration, encrypted backfill, sync, query, and expansion are implemented; live AWS sandbox and full-history coverage validation remain open. |
| Sentry | Project **error events** are implemented and contract-tested; live-project validation is open. This is not complete Sentry structured-log ingestion. |
| Datadog | Registration and credential handling exist, but sync and cached queries fail closed until Data Access Control scope can be verified safely. |
| CLI / MCP | Connected query, exact-line output, source-scoped expansion, and onboarding status are implemented on macOS. Live credential and LaunchAgent operation need validation. |
| Learning and default model | Cross-task learning is shadow-only. The held-out study did not qualify a better selector or prove a repair advantage. Provider-metered cost is unavailable. |

For a pilot, verify each source's access and freshness status before trusting a pack. The product never claims that a bounded result contains **all** relevant lines. [Implementation status](docs/LOG_ONLY_PRODUCT_PLAN.md) · [Security model](SECURITY.md)

## Development

```sh
cargo +1.88.0 fmt --all -- --check
cargo +1.88.0 clippy --workspace --all-targets -- -D warnings
cargo +1.88.0 test --workspace --all-targets
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The older `analyze` and `brief` research commands remain in the workspace while the connected log-only path is validated. Their incident-analysis results are documented separately; they are not the connected product described here.

Licensed under either [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
