# Evidentrail: connected log selection for coding agents

**Status:** product target and acceptance plan, with the current implementation
status below. This plan supersedes the two-path direction in `PRODUCT_ROADMAP.md`.

## Implementation status (2026-09-24)

The connected macOS CLI and MCP path is implemented but is **not production
validated**. Users can register read-only CloudWatch log groups and run bounded
checkpointed backfill and continuous sync into source-bound encrypted corpora.
Datadog registration remains experimental: its sources are blocked from sync,
connected queries, and expansion because the current access fingerprint cannot
verify Data Access Control policy. Connected CloudWatch queries search the corpus without
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
An expanded 12-category proxy on that same sample finds at least one labeled
line for all 12 message-derived tasks with either deterministic selector,
versus one with a newest-group baseline, but 147/189 and 138/179 returned
lines carry other labels. That is a noisy proxy, not a model-quality result or
proof that those other lines are irrelevant.
The group cards now expose up to 256 characters from bounded original-log
head and tail samples, with an explicit omission marker for longer records.
The previous 160-character prefix cap hid several BGL diagnostic suffixes
after long system-log prefixes. This increases model input size; live-model
selection quality and cost still need measurement.
An opt-in [connected RCAEval RE3 probe](../reports/connected-rcaeval-re3-2026-09-23.md)
now measures three 65–70K-line code-fault corpora without a query time window.
It found a root-service candidate dropped by intermediate page selection
despite an untruncated index pool. The connected result now counts
`prefinal_pruned_groups`, and intermediate selection preserves a bounded
representative from sparsely represented services. A first-ID selector now
returns a root-service line in all three cases, but this is only a
service-membership proxy. Actual local Qwen3 14B and Qwen2.5-Coder 7B
selection each found that service in only one of the three cases, with the
hardest query taking 92 and 46 seconds respectively. Neither route is
qualified by this probe; downstream coding tasks remain unevaluated.
An additional local GPT-OSS 20B run on the same three cases found the labeled
service in two cases, but still missed the sparse email-service case that the
first-ID baseline found. That query took 213 seconds. Model size alone has not
qualified a selector, and this service-membership proxy cannot establish that
the returned lines would help an agent fix the fault.
The [seven-case RCAEval line-label probe](../reports/connected-rcaeval-labeled-2026-09-24.md)
adds a stronger target: a published root-cause log message present once per
case in 596,494 full-history Sock Shop records. First-ID selection found the
labeled service in 7/7 but the exact labeled line and its parsed template in
0/7; severity-only and twelve recent representatives also found no labeled
line. The parser now recognizes complete Spring Boot and HTTP access preambles,
with a version-5 rebuild of derived group indexes. Group count fell from
379,858 to 353,222 in an exploratory matched-corpus comparison, while
line/template recall remained 0/7 before the retrieval change. A stage audit
found all seven labeled groups in the encrypted corpus but none among lexical
candidates. Bounded repeated-severity candidates raised first-ID exact-line
recall to 3/7 and parsed-template recall to 7/7 at the same output budget;
selector calls rose from 17 to 28 and all seven candidate pools reported
truncation. A lexical-strength gate preserved the prior BGL category results
for message-specific tasks. These are deterministic selector proxies, not
proof that repetition implies causal relevance. An actual local Qwen2.5-Coder
7B run with a 32K context found the labeled template in 3/7 cases and the
exact line in 1/7, taking 370.7 seconds across 28 selector calls. It is not a
qualified default. No hosted route or downstream repair was evaluated on
these seven cases.
The intermediate pager now carries at most eight high-repeat severe groups
through to final ranking alongside rare-service representatives. A paired
seven-case local-model rerun reached 4/7 labeled templates and 7/7 labeled
services, but still only 1/7 exact lines while returning 154 rather than 130
lines. The extra non-root-service lines have no relevance labels. This keeps
the model route unqualified until useful-answer and downstream-fix evaluations
can test the recall/noise tradeoff.
An evaluation-only replay reserving two final slots for repeated severe groups
recovered 7/7 labeled templates and 3/7 exact lines in one paired run, versus
4/7 and 1/7 for the local model, with 156 versus 154 returned lines. The
first-ID baseline matched its label coverage with 154 lines. The replay made
no additional model calls but displaced selected groups in three cases; their
usefulness is unknown. The safeguard is not shipped pending held-out relevance
and downstream repair evaluation.
An opt-in live-model harness now runs the actual selector over the same pinned
12-category BGL proxy and verifies every emitted line against the encrypted
corpus. A local Qwen2.5-Coder 7B run hit 12/12 categories with 107 off-label
lines among 149 returned, but took 494 seconds in total; four queries reported
retrieval truncation. This proxy does not qualify production routing;
accuracy and cost claims remain open.
An opt-in connected probe now ingests three frozen executable fault streams
from the repository's incident lab into encrypted corpora. A local Qwen2.5-Coder
7B selector and first-ID baseline each returned the known precursor and symptom
in 3/3 cases, but each selected all 4–6 candidate groups. Severity-only and
recent-group baselines missed every precursor. This remains a small synthetic
retrieval result. A separate local patch-proposal model abstained on all 12
arm/case combinations despite receiving the selected logs. A paired rerun
with synthetic configuration schemas also yielded 0/3 verified fixes for
every arm; patch syntax alone did not change the result. Neither run supplied
actual repository code or an agentic edit loop. A real paired coding-agent
fix study and model-routing qualification remain open.
A separate scripted file-read/edit probe using temporary synthetic configs
found verifier-accepted edits in 3/3 cases for every log arm and 2/3 with no
logs. Its initial two-field abstention contract produced contradictory model
answers; a single empty-line abstention contract corrected the measurement.
Because every log arm passed, this still provides no evidence that connected
selection improves downstream fixes over baselines. The fixture verifier
checks a bounded assignment, not a real service repair.
The workspace probe now also runs an executable synthetic service test after
each edit and asserts that the unedited service fails. A repeat local-model
run kept the same 3/3 for every log arm and 2/3 with no logs. This verifies an
actual behavior change in that small fixture but remains too easy to show
incremental selection value or real-repository repair success.
An exploratory [real-repository repair probe](../reports/connected-real-repair-tqdm-2026-09-24.md)
reproduced BugsInPy `tqdm` bug 1: the buggy revision failed its regression
test, and the fixed revision passed. Connected selection kept the offending
traceback line in 12 original lines (795 bytes) for both first-ID and local
model arms under a 4 KiB budget; severity-only selection returned three lines
without it. Neither Qwen2.5-Coder 7B nor Qwen3 14B made a verified one-line
fix within two edits in any log or no-log arm. This one development case is
negative downstream evidence, not a held-out product qualification.

The CLI now has `sources setup`, a read-only onboarding status that uses the
registered-source catalog to give the next connect, sync, recovery, service,
or query action while marking coverage provisional. Its pure status mapping
and CLI library tests pass. The live command on this host waited inside the
macOS login Keychain, so a clean-user onboarding smoke test remains open.

Local connector and authorization contract tests pass. Live CloudWatch and
Datadog sandbox validation, complete provider-coverage proofs under retention
and late arrivals, live Datadog credential-rotation validation, LaunchAgent operation with live
credentials, model-routing qualification, and real-incident downstream
benchmarks remain release gates. The supplied-log `compact` command and older
RCA/brief commands still exist; delete those obsolete product paths only after
the connected replacement and migration contract are verified. The
[README](../README.md) describes the current user flow and its limits; this
plan defines the target behavior and acceptance gates.
Connected queries now pin a consistent encrypted WAL read snapshot after
catch-up and release the catalog lock during model selection. Background sync
can append records while a model works, without changing the query's candidate
or original-record view. Before any result leaves the process, the query
reacquires the lock, checks that every selected source still has the same
registration and corpus-key generation, and revalidates CloudWatch identity/read
access or Datadog identity/access scope. A changed or unavailable source fails
the whole query, including a disconnect/reconnect with the same descriptor.
An isolated macOS Keychain test exercises that same-descriptor replacement
while an old corpus snapshot is still open; the generation check rejects it.
The lock remains held through result delivery. A long read snapshot can prevent
WAL reset while sync appends records. Before each synced page, the writer now
checks a 512 MiB per-corpus WAL threshold, attempts a checkpoint if exceeded,
and reports `StoreWalPressure` rather than appending another page when a reader
still blocks reset. A pressure-only watcher pass retries at its normal interval
and resumes after the query ends. One page can overshoot the threshold, and
migration/backfill writes on corpus open are not covered by this guard. Live
concurrent sync/revocation tests and a measured disk-resource bound remain
release gates. Final revalidation waits up to 60 seconds for an active sync
pass before failing closed; a slow pass can still waste the completed model
selection. The watcher treats lock contention as a normal retry rather than
exponentially backing off.

CloudWatch registration now pins the STS caller ARN in the source descriptor.
Every transport reconnect and provider page checks the same ARN, and legacy
descriptors without a pinned ARN fail closed until reconnected. This catches a
principal or assumed-role session switch within the same AWS account. It does
not establish that IAM permissions attached to an unchanged principal remain
unchanged; a live narrowed-policy sandbox test and a reliable cache invalidation
strategy for that case remain release gates.

Interrupted Datadog rotations are now detected from staged encrypted corpus
files, and all tiers in that connection are excluded from query, expansion,
and sync. An explicit `recover-datadog` command validates replacement
credentials, drops cached records, and starts fresh backfill. Live crash and
recovery tests remain release work.

Datadog restriction queries can change which logs a role may read without a
credential change. A successful empty search or organization check does not
prove that previously cached logs remain accessible. New Datadog descriptors
pin the authenticated user and sorted role IDs. Sync,
query, and expansion exclude legacy descriptors and descriptors whose user or
role assignments change. The connector now also fetches the user's effective
restriction-query definitions through the read-only `logs_read_config` API and
reads the user's effective global permissions through the user-permissions API.
The combined fingerprint binds to the encrypted corpus. A changed fingerprint
excludes the corpus; cached records without the current-version fingerprint
cannot be adopted and require reconnecting. Indexed-tier registration, sync,
query, and expansion now fail closed when effective `logs_read_index_data` is
missing or scoped to particular indexes. Datadog documents that per-index
grants are configured through its UI, while the user-permissions API only
exposes whether the permission is restricted. Other accessible tiers can still
register. Data Access Control policies remain an unverified cache-access
guard and release gate. All Datadog tiers now report
`access_scope_unverifiable` and are excluded from sync, connected queries,
and expansion before their cached records are opened. This protects existing
caches while full DAC verification and live narrowed-scope tests remain open.
The identity fields come from Datadog's
[current-user API](https://docs.datadoghq.com/api/latest/users/get-current-user/).
A legacy or changed-identity connection must be disconnected and
reconnected; retention-expired logs may then be unrecoverable. Live provider
validation of the identity response and change behavior is still required.
Before production use, obtain and verify a current access-scope fingerprint covering role assignments,
role permission grants, restriction-query definitions, any supported scoped
index permissions, and any enabled Data Access Control policies.
Invalidate affected records and derived state on any change. Fail closed when
the scope cannot be verified. Exercise a narrowed-scope change in a live
sandbox and prove that
queries and expansion cannot return prior out-of-scope records. The
[Datadog restriction-query API](https://docs.datadoghq.com/api/latest/logs-restriction-queries/)
documents the access behavior; its configuration read endpoint requires the
read-only `logs_read_config` permission. The
[user-permissions endpoint](https://docs.datadoghq.com/api/latest/users/get-a-user-permissions/)
which requires `user_access_read`. Datadog also documents
[Data Access Control](https://docs.datadoghq.com/account_management/rbac/data_access/)
as another way API query visibility can change. The complete scope gate is not
implemented yet.
The read-only [dataset list](https://docs.datadoghq.com/api/latest/datasets/get-all-datasets/)
can reveal configured boundaries, but the documented Strict/Standard mode and
unrestricted-group behavior must also be covered; hashing only the dataset list
would be an incomplete access fingerprint.

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

### Completion goal: usable onboarding and verified log selection

Finish the connected product only when a new user can install the CLI, connect
a read-only CloudWatch or Datadog source, understand exactly what history was
acquired, keep it synced, and retrieve and expand source-verifiable logs from
the CLI or MCP without choosing a time window. The public default selector must
be chosen from held-out evidence and improve a coding agent's verified fixes,
not merely match a root-service or message-template proxy. The existing
seven-case RCAEval set is development data, not a qualification set.

The remaining release gates are:

1. **CLI onboarding:** provide one discoverable setup flow with prerequisite
   checks, read-only credential and access validation, source discovery and
   registration, a first-sync progress/status command, a sample query and
   expansion, recovery/disconnect instructions, and actionable errors. Never
   print secrets. Verify the flow from a clean user environment with a fresh
   CloudWatch connection and a fresh Datadog connection.
2. **Independent usefulness evaluation:** freeze incident cases by repository,
   service, time, and fault family before tuning. At equal raw-log budgets,
   compare first-ID, severity, current local model, any guarded challenger,
   provider-native search, and a no-logs control. Score required original-line
   recall, off-task lines only where independent labels support that judgment,
   exact-source integrity, expansion use, p50/p95 latency, model calls/cost,
   and verified coding-agent repairs. Publish per-case failures and graph
   ablation. Promote a selector only on held-out downstream benefit without a
   material security, omission, latency, or cost regression; keep rollback.
3. **Live source conformance:** in sandbox accounts, exercise complete
   accessible-history backfill, empty and partial pages, retention edges,
   late arrivals, crash/restart checkpoints, ongoing sync, credential rotation,
   narrowed access and revocation, and result-scoped expansion. Prove cached
   records and graph state cannot escape a changed authorization scope.
   Datadog must fail closed unless all applicable log visibility controls,
   including Data Access Control, can be verified; an unverified tier cannot
   count as a validated production connection.
4. **Ship and simplify:** pass onboarding, scale, integration, security, and
   CI gates on the final code. Document measured limits and partial-coverage
   states in the CLI and README. Remove obsolete RCA, brief, and supplied-log
   product paths after migration checks prove that the connected CLI/MCP path
   replaces them, while retaining provenance and benchmark machinery.

Unavailable live credentials or independently labeled incidents are explicit
validation limits, not passing results. Do not mark the product complete or
claim production readiness while one of these gates remains unverified.

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
