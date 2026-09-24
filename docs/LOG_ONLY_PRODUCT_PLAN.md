# Evidentrail: connected log selection for coding agents

**Status:** product target and acceptance plan, with the current implementation
status below. This plan supersedes the two-path direction in `PRODUCT_ROADMAP.md`.

## Implementation status (2026-09-23)

The connected macOS CLI and MCP path is implemented but is **not production
validated**. Users can register read-only CloudWatch log groups or Datadog
storage tiers, then run bounded checkpointed backfill and continuous sync into
source-bound encrypted corpora. Connected queries search those corpora without
a user-selected time window, let a local or hosted model select advertised
IDs, and resolve the selected lines to exact original records. Result-scoped
MCP expansion reads bounded chronological neighbors after checking the source
connection again. Sync attempts, candidate truncation, and output truncation
are reported separately from the log body.
After a recent lookback replay, spare sync budget now sweeps older history from
a durable source-local cursor and resumes after restart. This can discover
older late arrivals but does not prove complete provider coverage, especially
when source retention expires or scans repeatedly hit page limits.

The corpus maintains a versioned template index, severe-service directory,
and explicit-peer service graph. Lexical search, priority fallback, and graph
neighbors provide bounded group candidates. When lexical search or fallback
truncates, model-selected directory pages show bounded original-log examples
and can retrieve additional severe service groups across eligible sources.
Connected queries now accept more than 32 registered sources; directory pages
remain bounded to 32 service cards and report truncation when their page budget
cannot inspect every service.
This remains a bounded search with no
guarantee of finding every relevant record. The frozen encrypted-corpus
fixture measures exact evidence recall, irrelevant lines, a recent-log
baseline, and graph ablation with deterministic selectors. It does not measure
live model choices or downstream coding-agent success.
An ignored local scale exercise also checks exact clue bytes and counts at
100,000 and 1,000,000 indexed records; its single-run debug timings do not
qualify production latency or noisy model retrieval.
A pinned LogHub BGL sample adds one real-log task with alert labels. A versioned
parser rebuild recognizes its preamble, reducing 2,000 lines from 2,000 to
1,374 groups; one required representative is selected and its adjacent
repeated alert is recovered by expansion. This is still not a multi-incident
relevance or downstream-task benchmark.

Local connector and authorization contract tests pass. Live CloudWatch and
Datadog sandbox validation, complete provider-coverage proofs under retention
and late arrivals, live Datadog credential-rotation validation, LaunchAgent operation with live
credentials, model-routing qualification, and real-incident downstream
benchmarks remain release gates. The supplied-log `compact` command and older
RCA/brief commands still exist; delete those obsolete product paths only after
the connected replacement and migration contract are verified. The
[README](../README.md) describes the current user flow and its limits; this
plan defines the target behavior and acceptance gates.

## One product contract

Connect read-only log sources once. Evidentrail backfills **all logs available
through each connection**, then continuously ingests new records. When a coding
agent calls it, Evidentrail catches up and searches that entire indexed corpus;
the user does not choose a time window or export files. It parses every record
it acquired, compresses repeated patterns, and returns only the most relevant
original log lines. The agent can expand a
selected line or group to inspect nearby original records. Evidentrail does not
write a diagnosis, invent a replacement log line, or require users to prepare
metrics, traces, or a service graph.

```text
User connects CloudWatch / Datadog / another supported log source
  -> background full backfill, checkpoint, and continuous read-only sync
  -> parse, group, and index every acquired log record
  -> build an evidence-backed system graph from log fields and correlations
  -> coding agent calls evidentrail_logs(task, token budget)
  -> catch up connected sources and search the whole indexed corpus
  -> model selects relevant groups and may inspect original examples
  -> verifier resolves selected IDs back to source records
  -> agent receives a compact log pack and can call evidentrail_expand
```

The **log pack body** contains only source log lines, short source references,
and exact repeat counts. For example:

```text
[L42 × 816] 2026-09-23T12:10:02Z checkout ERROR database connection refused
[L98] 2026-09-23T12:10:03Z database ERROR disk full on orders volume
```

Acquisition status, inaccessible or expired history, omitted-record counts, model/configuration identity, and
budget usage are separate machine-readable tool metadata. The coding agent
must see a partial status when a provider, permission, retention boundary,
deadline, or cap stopped backfill or catch-up. “All logs” means every record
the connected sources make accessible under the granted permissions and
retention policies. The product must never silently turn an incomplete source
into a claim of complete history. No user-facing time-window parameter exists.

## Reuse and remove from the current codebase

| Existing component | Use in the single flow |
| --- | --- |
| `evidentrail-ingest` CloudWatch adapter and shared acquisition contracts | Keep pagination, source identity, caps, and completion checks; add a real authenticated transport and source binding. Current transport is an interface, not a working AWS connection. |
| Core ledger and `evidentrail_expand` | Keep exact source retention and bounded expansion so a selected line can be inspected later. |
| `incident_analysis` log parser, fingerprints, grouping, and model group requests | Extract into a log-only indexing/retrieval module. Remove hypothesis, fault-type, metric, trace, and topology requirements from this product path. |
| `brief` budgeting and evidence receipts | Reuse the strict output budget and completeness accounting internally. Replace the public brief renderer with the log-pack renderer. |
| Current `evidentrail_logs` MCP tool | Change input from caller-supplied Base64 log bytes to the agent task and budget. Search all connected, authorized indexes after catch-up. Keep an explicit supplied-log adapter for local development, not a second product track. |

Deprecate `analyze` and the old `brief` behavior from the main CLI/MCP surface
after the new contract and migration tests pass. Do not delete the exactness,
authorization, or benchmark machinery merely because the user-facing product
is simpler.

## The selection engine

1. **Backfill, sync, and parse all accessible records.** Page through the full
   available history of each connected source into a durable, bounded-memory
   index. Freeze a backfill high-water mark, persist completed partitions and
   stable event identities, and continuously catch up after backfill. Do not
   assume a provider page token survives a process restart: resume from a
   durable timestamp partition with overlap, deduplicate by source-native ID,
   and reconcile late arrivals. A recent lookback replay and durable cursor
   for older sweeps are implemented; provider-specific consistency tests are
   still required before claiming full accessible-history coverage. Preserve
   original bytes, source identity, provider event ID/cursor, timestamps when
   present, and parse confidence.
   Group by stable template, service, severity, and diagnostic fields. Repeated
   request IDs and timestamps should collapse; distinct error codes and
   unexpected values should remain distinguishable. Malformed records remain
   addressable rather than disappearing.
2. **Build a bounded candidate index.** Record group count, first/last
   occurrence, onset/change, rare events, and representative exact lines.
   Cover services and eras so one noisy service cannot crowd out a sparse clue.
   Partition the index for large histories; never silently sample and claim
   complete coverage. Calls search the index rather than refetching or placing
   the entire raw corpus in a model prompt.
3. **Build a log-derived system graph.** Normalize service identities from
   structured log metadata, including OpenTelemetry `service.name` where
   available. Add a directed relationship only when log fields explicitly name
   a peer or trace/request correlation supplies supporting records; attach
   source IDs, confidence, count, and observed period to every edge. Keep
   ambiguous co-occurrence as a weak candidate, not a verified dependency or
   causal link. Version the graph as services and deployments change. Use it
   internally to search neighboring services and distinguish repeated
   downstream symptoms from a rare upstream clue. The graph is not part of
   the agent's log-only output.
4. **Let the LLM choose evidence.** Give the model group cards and the coding
   agent's task, then allow bounded read-only requests for more examples or
   neighboring records. The model returns group/event IDs only. Code checks
   every ID, resolves exact lines, enforces the token budget, and renders no
   model-authored log text. A small model is a cost candidate for first-pass
   selection; GPT-6 Sol is an accuracy challenger for hard cases. Choose the
   routing policy only after paired evaluation.
5. **Keep uncertainty honest.** If the model declines to select, backfill or
   catch-up is partial, or the output budget cannot fit critical evidence, report
   that in metadata. The log body still contains only logs.

This uses deterministic code for fidelity and accounting, and LLM judgment for
relevance. Sending every raw line to one prompt is not the target architecture:
it loses reliable count/coverage information and scales poorly. The model can
inspect more source lines through bounded retrieval when group cards are
insufficient.

## Connected sources, in order

1. **CloudWatch Logs:** complete the existing adapter with an AWS SDK-backed
   read-only `FilterLogEvents` transport, account/region/log-group binding,
   credential isolation, full-history pagination, durable checkpoints,
   incremental catch-up, and source-native event references. Continue through
   empty pages when `nextToken` exists; an empty page is not completion.
   Verify identity and completeness on every call. [AWS API](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html).
2. **Datadog Logs:** implement the same source contract using the paginated
   Logs Search API, internally partitioned absolute bounds from the earliest
   accessible history to the frozen high-water mark, index/site binding, and
   `logs_read_data` permission. [Datadog API](https://docs.datadoghq.com/api/latest/logs/search-logs-post/).
3. **Sentry Logs:** validate whether the customer's enabled Sentry log dataset
   and API can supply the requested coverage. Sentry's Explore table endpoint
   supports a logs dataset but explicitly is not a full-export endpoint. Do
   not offer it as an “all logs” connection until a validated export or
   equivalent complete-ingestion route exists.
   [Sentry API](https://docs.sentry.io/api/explore/query-explore-events-in-table-format/).
4. Add other sources through the same acquisition and completeness contract,
   starting with sources customers actually request. The evidence-backed
   system graph is built from these logs and remains an internal ranking asset.

## The graph and learning moat

The differentiated asset is a versioned, customer-specific memory of what the
system emits: service identities, changing log templates, supported
relationships, and which lines helped solve verified coding tasks. Each graph
edge and template points back to original records; deletion or permission
changes remove inaccessible evidence and derived state. A generic LLM can read
an excerpt, but it does not automatically have this complete, continually
updated, source-verifiable history. The graph should improve retrieval only
when ablations show that it finds required clues the non-graph selector misses.

Raw logs and graph evidence must remain tenant-isolated, encrypted at rest,
and subject to source-level access checks at query and expansion time. A
connection has an explicit provider identity and allowed resource scope;
revocation stops sync and invalidates indexed records, graph edges, caches,
and any consented training data derived from that scope. Model routing must
honor each customer's data-processing choice, with a local-only option.

## Continuous improvement without self-reinforcing errors

Log every *contentless* selection decision with source/configuration digests,
selected IDs, expansions, and latency. With separate customer consent, collect
feedback on which selected or omitted lines helped the coding agent make a
verified fix. Do not treat the model's own explanation, a click, or an
unverified fix as ground truth. Use those labels to evaluate changed prompts,
retrieval policies, model routes, and eventually a smaller ranker. Freeze
training/test splits by customer, project, time, and incident family. Run new
rankers in shadow mode; promote only after held-out improvement and retain a
one-step rollback. Revoked data must leave the training set.

The first useful learning loop is simpler than online model training: compare
the selected log pack with lines the agent subsequently expanded or used in a
verified fix, identify repeated omission patterns, and improve candidate
coverage. Cache results only for the same source snapshot, scope, task, and
model/policy version; a changed source invalidates the cache.

## Delivery sequence and acceptance gates

The [frozen connected retrieval v2 fixture](../reports/connected-retrieval-v2.md)
runs through the encrypted corpus and compares graph-enabled selection, graph
ablation, and recent-log selection under the same raw-byte cap. Its six
synthetic cases exposed missed old and middle clues. The connected fallback
now combines rare/common service representatives with temporal samples and
reports truncation; the noisy cases still emit 11 irrelevant lines. A separate
multi-service test exercises model-selected paging through an encrypted service
directory when lexical search has no match. The fixture uses deterministic
selectors, not a live model, and does not satisfy the live-provider,
downstream-task, scale, latency, cost, or security gates below.

| Milestone | Concrete deliverable | Gate |
| --- | --- | --- |
| 1. One log-pack contract | Connected CLI/MCP selection; exact source/native IDs, repeat counts, bounded result-scoped expansion, metadata outside the log body | Output contains no generated logs or diagnosis; every selected line resolves to an original stored record. The connected MCP flow now supports local expansion with authorization recheck; live provider validation and complete coverage semantics remain. Old commands remain as compatibility wrappers pending replacement verification. |
| 2. Full-corpus index and graph | Durable streaming parser, checkpointed template index, evidence-backed service graph, log-only query API | Every acquired record is accounted for; graph edges have source support; a 100K/1M-line corpus is searchable without a user time window or silent truncation. |
| 3. Model-guided selection | Bounded group cards, retrieval of more examples, verified ID-only selection, local and hosted model options | Rare required clues survive noisy full-corpus tests; graph ablation measures incremental value; output stays within budget. |
| 4. CloudWatch connection | Real read-only AWS transport, full backfill, incremental sync, and connected-source MCP call | Sandbox account proves empty-page continuation, crash/restart cursors, retention boundaries, permissions/caps, identity checks, and no false-complete result. |
| 5. More sources | Datadog full-history sync; Sentry only after a complete route is validated | Provider-specific conformance fixtures and live sandbox checks; incomplete query capabilities are exposed rather than hidden. |
| 6. Learning loop | Consented feedback labels, offline challenger evaluation, versioned routing and rollback | Held-out required-evidence recall and downstream coding-agent task success improve at a matched output budget, without worse citation integrity, false omissions, latency, or data handling. |

Before calling this an accuracy improvement, compare it with current `brief`,
`analyze` highlights, provider-native searches, grep/tail, lexical retrieval,
and a bounded full-log model on frozen incidents. Measure required-evidence
recall, irrelevant-line rate, compression ratio, agent fix success, expansion
rate, p50/p95 latency, model calls, and cost. Report by provider, log format,
incident family, and rare-event position. The existing synthetic pilots do
not establish real-user utility for this new log-only contract.
