# Evidentrail: connected log selection for coding agents

**Status:** product plan, not a description of shipped behavior. This plan
supersedes the two-path product direction in `PRODUCT_ROADMAP.md`.

## Implementation status

The current `evidentrail compact` command is a supplied-log prototype. It
accepts up to 16 MiB/100,000 UTF-8 lines on standard input, groups those
lines, asks a local or hosted model to select group IDs, verifies the IDs, and
emits selected original lines with repeat counts. Its in-process API can
expand an advertised line to bounded original neighbors; no cross-call
expansion handle is shipped. Its graph currently consists only of explicitly
named peer services in JSON log records. It has no task-searchable full-history retrieval path,
connector credentials, background synchronization, cross-call graph memory,
or verified learning loop. These
are release requirements, not existing capabilities. The current group-card
selection also needs held-out relevance tests before it can be trusted to
preserve rare clues in very large histories.

The ingestion crate now also has a provider-neutral full-history sync contract.
It paginates internal time partitions from a store checkpoint to a frozen
high-water mark, continues through empty pages, and advances the checkpoint
only after the final page of a partition. A SQLCipher-encrypted per-source
corpus now durably stores raw records and completed-partition checkpoints.
Reopening after an incomplete partition replays pages idempotently, while
conflicting native IDs, wrong keys, and tenant/source mismatches fail closed.
The ingestion contract now supports a bounded reconciliation replay of
already-checkpointed partitions to capture late provider arrivals without
moving the forward checkpoint. It reports partial replay on page or partition
limits. This is not wired to a connected scheduler and cannot establish full
coverage of arbitrarily late records or history already expired at the source.
The corpus now maintains exact template-group counts and first/last source
references in the same transaction as raw ingestion, using the same parser as
the CLI. It has an encrypted lexical group index and a bounded task-query API
that reports candidate truncation; this is an unvalidated candidate stage,
not yet the connected product. The CLI library now has an internal indexed
selector that gives a local or hosted model bounded group cards, validates
selected group IDs, and resolves selected first/last records to their original
bytes and exact repeat counts. Its output metadata reports candidate and output
budget truncation. It operates on one already-authorized store; the public
connected query, multi-source catch-up, completeness receipt, and source-level
query authorization remain missing. The corpus also maintains
versioned, explicitly observed service edges whose counts and endpoint records
resolve to original logs; unrelated service co-occurrence does not create an
edge. Indexed selection now adds a bounded set of groups from services linked
to lexical matches by those explicit edges. This is candidate expansion, not
a causal inference or a measured accuracy improvement; held-out graph ablation
is still required. The parser now recognizes Datadog's nested message, service, severity,
and explicit peer fields while the corpus retains the exact API log record.
Existing v1 corpora transactionally reset derived indexes and rebuild them
under parser/graph v2; unknown versions fail closed. A source-bound macOS login
Keychain authority can now create, reopen, and revoke an add-only SQLCipher key;
its live create/load/delete check passed on a local unlocked Keychain. The
authority can also register and list bounded, non-secret source descriptors
without returning keys, deriving each source digest from its descriptor. A
live macOS create/list/reopen/revoke check passed. Provider-specific descriptor
validation and credential storage are still caller responsibilities. The
macOS CLI now offers `sources connect-cloudwatch` and `sources list`. Registration
checks the AWS caller account and probes unfiltered log-group read access before
creating a source-bound Keychain entry and private SQLCipher corpus. A live
local Keychain/corpus reopen test passed, while `sources list` returned an empty
catalog on this host. No AWS sandbox connection has been validated. Registration
explicitly reports backfill pending. A manual `sources sync` command now makes
bounded forward progress with adaptive partition widths and replays a recent
lookback when it reaches the high-water mark. An encrypted-corpus fixture proves
forward scan plus deduplicated replay, and an endless-pagination fixture proves
the per-source page cap preserves a partial status and checkpoint. The current
scan starts at epoch because a verified provider availability boundary is not
yet persisted; coarse partitions may spend calls on empty early history. A
`sources sync` smoke run on this Mac waited for a Keychain authorization prompt
after rebuilding the binary and was stopped. It reports provisional coverage; the
connected scheduler, query, and verified completeness semantics remain missing.
The corpus still receives its key from a caller; cross-platform key authority,
query access control, broader graph-aware retrieval, and the complete connected
user flow are missing. The login Keychain is used because this
unsigned development binary cannot access the entitlement-gated macOS data
protection Keychain; the login Keychain choice must be documented in the user
security model. A CloudWatch history-source
adapter maps internal partitions to unfiltered log-group page requests. An
optional AWS SDK transport now loads a configured identity, verifies its STS
caller account on each page, binds source account/region/log group, and makes
signed `FilterLogEvents` requests. A local HTTP contract test exercises
empty-page continuation and exact event mapping. Live AWS sandbox validation,
live connected backfill/catch-up validation and scheduled reconciliation are still missing. One scan
to a high-water mark does not prove complete
coverage under provider eventual consistency; reconciliation is required.
The Datadog source now queries `*` across all indexes for one explicitly
chosen storage tier, pages by `meta.page.after`, and rejects partial warnings
or malformed events before checkpoint advancement. A connected run must cover
each authorized tier (indexes, online archives, and Flex) and report tiers it
cannot access. Local HTTP fixtures cover empty-page continuation and exact
source JSON retention; live Datadog validation and credential/org binding are
still missing.

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
   and reconcile late arrivals. The initial reconciliation replay covers a
   configured recent lookback; add a durable reconciliation cursor and
   provider-specific consistency tests before claiming full accessible-history
   coverage. Preserve original bytes, source identity,
   provider event ID/cursor, timestamps when present, and parse confidence.
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

| Milestone | Concrete deliverable | Gate |
| --- | --- | --- |
| 1. One log-pack contract | CLI/MCP supplied-log prototype; exact line IDs, repeat counts, expansion, metadata outside the log body | Output contains no generated logs or diagnosis; every selected line resolves to an input record; old commands remain only as compatibility wrappers. The current CLI covers selection and line verification; expansion, MCP integration, and completeness metadata remain. |
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
