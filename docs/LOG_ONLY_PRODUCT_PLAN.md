# Evidentrail: connected log selection for coding agents

**Status:** product plan, not a description of shipped behavior. This plan
supersedes the two-path product direction in `PRODUCT_ROADMAP.md`.

## One product contract

Connect a read-only log source once. When a coding agent asks a debugging
question, Evidentrail fetches the approved logs for that task and time window,
parses every record it actually retrieved, compresses repeated patterns, and
returns only the most relevant original log lines. The agent can expand a
selected line or group to inspect nearby original records. Evidentrail does not
write a diagnosis, invent a replacement log line, or require users to prepare
metrics, traces, or a service graph.

```text
User connects CloudWatch / Datadog / another supported log source
  -> coding agent calls evidentrail_logs(source, task, time window, token budget)
  -> bounded read-only acquisition with an honest completeness receipt
  -> parse and group every acquired log record
  -> model selects relevant groups and may inspect more original examples
  -> verifier resolves selected IDs back to source records
  -> agent receives a compact log pack and can call evidentrail_expand
```

The **log pack body** contains only source log lines, short source references,
and exact repeat counts. For example:

```text
[L42 × 816] 2026-09-23T12:10:02Z checkout ERROR database connection refused
[L98] 2026-09-23T12:10:03Z database ERROR disk full on orders volume
```

Acquisition status, omitted-record counts, model/configuration identity, and
budget usage are separate machine-readable tool metadata. The coding agent
must see a partial status when a provider, permission, deadline, or cap stopped
the fetch. “All logs” means all records returned by the explicitly scoped,
completed query—not every log in the customer's account.

## Reuse and remove from the current codebase

| Existing component | Use in the single flow |
| --- | --- |
| `evidentrail-ingest` CloudWatch adapter and shared acquisition contracts | Keep pagination, source identity, caps, and completion checks; add a real authenticated transport and source binding. Current transport is an interface, not a working AWS connection. |
| Core ledger and `evidentrail_expand` | Keep exact source retention and bounded expansion so a selected line can be inspected later. |
| `incident_analysis` log parser, fingerprints, grouping, and model group requests | Extract into a log-only indexing/retrieval module. Remove hypothesis, fault-type, metric, trace, and topology requirements from this product path. |
| `brief` budgeting and evidence receipts | Reuse the strict output budget and completeness accounting internally. Replace the public brief renderer with the log-pack renderer. |
| Current `evidentrail_logs` MCP tool | Change input from caller-supplied Base64 log bytes to an approved connected-source binding plus task/window. Keep an explicit supplied-log adapter for local development, not a second product track. |

Deprecate `analyze` and the old `brief` behavior from the main CLI/MCP surface
after the new contract and migration tests pass. Do not delete the exactness,
authorization, or benchmark machinery merely because the user-facing product
is simpler.

## The selection engine

1. **Parse all acquired records.** Preserve original bytes, source identity,
   provider event ID/cursor, timestamps when present, and parse confidence.
   Group by stable template, service, severity, and diagnostic fields. Repeated
   request IDs and timestamps should collapse; distinct error codes and
   unexpected values should remain distinguishable. Malformed records remain
   addressable rather than disappearing.
2. **Build a bounded candidate index.** Record group count, first/last
   occurrence, onset/change, rare events, and representative exact lines.
   Cover services and time slices so one noisy service cannot crowd out a
   sparse clue. If a query is too large to inspect completely, return an
   explicit partial result or partition it; never silently sample and claim
   complete coverage.
3. **Let the LLM choose evidence.** Give the model group cards and the coding
   agent's task, then allow bounded read-only requests for more examples or
   neighboring records. The model returns group/event IDs only. Code checks
   every ID, resolves exact lines, enforces the token budget, and renders no
   model-authored log text. A small model is a cost candidate for first-pass
   selection; GPT-6 Sol is an accuracy challenger for hard cases. Choose the
   routing policy only after paired evaluation.
4. **Keep uncertainty honest.** If the model declines to select, the provider
   query is partial, or the output budget cannot fit critical evidence, report
   that in metadata. The log body still contains only logs.

This uses deterministic code for fidelity and accounting, and LLM judgment for
relevance. Sending every raw line to one prompt is not the target architecture:
it loses reliable count/coverage information and scales poorly. The model can
inspect more source lines through bounded retrieval when group cards are
insufficient.

## Connected sources, in order

1. **CloudWatch Logs:** complete the existing adapter with an AWS SDK-backed
   read-only `FilterLogEvents` transport, account/region/log-group binding,
   credential isolation, and source-native event references. Continue through
   empty pages when `nextToken` exists; an empty page is not completion.
   Verify identity and completeness on every call. [AWS API](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html).
2. **Datadog Logs:** implement the same source contract using the paginated
   Logs Search API, fixed absolute time bounds, index/site binding, and
   `logs_read_data` permission. [Datadog API](https://docs.datadoghq.com/api/latest/logs/search-logs-post/).
3. **Sentry Logs:** validate whether the customer's enabled Sentry log dataset
   and API can supply the requested coverage. Sentry's Explore table endpoint
   supports a logs dataset but explicitly is not a full-export endpoint; do
   not label a bounded table query as complete account-wide ingestion.
   [Sentry API](https://docs.sentry.io/api/explore/query-explore-events-in-table-format/).
4. Add other sources through the same acquisition and completeness contract,
   starting with sources customers actually request. Normalize service names
   using provider metadata and OpenTelemetry `service.name` where available;
   the main product does not need a separate service graph.

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
| 1. One log-pack contract | CLI/MCP supplied-log prototype; exact line IDs, repeat counts, expansion, metadata outside the log body | Output contains no generated logs or diagnosis; every selected line resolves to an input record; old commands remain only as compatibility wrappers. |
| 2. Model-guided selection | Bounded group cards, retrieval of more examples, verified ID-only selection, local and hosted model options | Rare required clues survive noisy 10K/100K-line tests; no silent truncation; log-only output stays within budget. |
| 3. CloudWatch connection | Real read-only AWS transport and connected-source MCP call | Sandbox account integration proves pagination, empty-page continuation, permission/cap failures, identity checks, and no false-complete result. |
| 4. More sources | Datadog, then validated Sentry log query | Provider-specific conformance fixtures and live sandbox checks; incomplete query capabilities are exposed rather than hidden. |
| 5. Learning loop | Consented feedback labels, offline challenger evaluation, versioned routing and rollback | Held-out required-evidence recall and downstream coding-agent task success improve at a matched output budget, without worse citation integrity, false omissions, latency, or data handling. |

Before calling this an accuracy improvement, compare it with current `brief`,
`analyze` highlights, provider-native searches, grep/tail, lexical retrieval,
and a bounded full-log model on frozen incidents. Measure required-evidence
recall, irrelevant-line rate, compression ratio, agent fix success, expansion
rate, p50/p95 latency, model calls, and cost. Report by provider, log format,
incident family, and rare-event position. The existing synthetic pilots do
not establish real-user utility for this new log-only contract.
