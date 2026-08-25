# Evidentrail source adapter contract

**Status:** Normative for every deterministic greenfield source adapter

**Last updated:** August 24, 2026

**Applies to:** file, stdin, `run`, Docker, journald, macOS unified logs, Kubernetes, CloudWatch, and benchmark replay

**Related policy:** [Threat model](./THREAT_MODEL.md) and [local data policy](./LOCAL_DATA_POLICY.md)

## Purpose

A source adapter turns one explicitly approved, bounded source operation into an ordered stream of exact records and an honest terminal completeness statement. It does not parse evidence, decide relevance, summarize logs, widen access, or hide provider limitations.

The contract makes local and cloud sources interchangeable above acquisition:

```text
metadata-only discovery
  -> approved SourceBinding
  -> requested QueryIntent
  -> binding intersection
  -> immutable QueryPlan
  -> cancellable execute(plan, sink)
  -> ordered RawEnvelope stream
  -> Complete | Partial | Unknown FetchCompletion
```

A policy-aware ledger sink is the sole consumer of `RawEnvelope`. No parser, grouper, ranker, renderer, diagnostic logger, or model may sit between the adapter and that sink. The exact envelope may exist only in bounded process memory until the sink records one authorized outcome.

## Contract principles

1. **Discovery reads no log content.** It may inspect source identity and capabilities only.
2. **The binding is the authority.** A request may narrow an approved binding but cannot widen it.
3. **Plans are typed and immutable.** Adapters never accept raw provider argument arrays from the agent.
4. **Bytes precede interpretation.** Every emitted payload is exact bytes with source and ordering provenance.
5. **Completeness is earned.** Process success or pagination progress alone does not imply `Complete`.
6. **No silent loss.** Caps, cancellation, source changes, parse failures, permissions, and provider uncertainty are terminally visible.
7. **Backpressure cannot become dropping.** The adapter pauses, durably spools within policy, or stops partial.
8. **Expansion is not an adapter operation.** It reads the encrypted local result snapshot and never silently requeries the source.

## Responsibilities and non-responsibilities

### Every adapter owns

- metadata-only discovery for its source family;
- capability and identity reporting;
- validating that an approved binding applies to the effective source;
- compiling a request into a bounded `QueryPlan`;
- revalidating source identity immediately before execution;
- executing through a source API or approved direct-argv command preset;
- streaming exact ordered `RawEnvelope` objects;
- enforcing acquisition caps, deadlines, cancellation, and backpressure;
- reporting terminal `FetchCompletion` with all applicable reasons;
- sanitizing human-visible plans without weakening executable provenance.

### An adapter does not own

- repository-to-service approval UI;
- evidence parsing, multiline reconstruction, redaction, grouping, ranking, or packing;
- determining root cause or diagnostic importance;
- assigning final ledger event references or coverage dispositions;
- uploading content, telemetry, benchmark cases, or training data;
- expanding a prior result;
- executing instructions found in source content.

## Normative interface

The exact Rust types may evolve while the schemas are pre-release, but every implementation must preserve this semantic interface:

```text
trait SourceAdapter {
  metadata() -> AdapterMetadata
  discover(DiscoveryRequest) -> DiscoveryReport
  plan(ApprovedBinding, QueryIntent) -> PlanOutcome<QueryPlan>
  execute(QueryPlan, RawEnvelopeSink, Cancellation) -> FetchCompletion
}
```

`execute` returns only after every emitted envelope has either been acknowledged as persisted by the sink or the completion explicitly reports why delivery stopped. An adapter cannot report more delivered records or bytes than the sink acknowledged.

Planning failures are not fetch completions:

- `NeedsApproval` — requested scope is not a subset of the binding;
- `IdentityChanged` — the effective source no longer matches the binding;
- `Unsupported` — requested bound/filter cannot be represented safely;
- `Unavailable` — required executable, API, file, socket, or provider is unavailable;
- `InvalidRequest` — malformed, contradictory, or unbounded intent;
- `PolicyDenied` — organization or local policy forbids the operation.

If execution has begun, every termination path produces a `FetchCompletion`, including zero-record authentication failures and cancellation.

## Adapter metadata and capabilities

`AdapterMetadata` is static product information:

```text
adapter_kind
adapter_version
contract_version
supported_platforms
supported_source_features
supported_filter_fields
supported_bound_types
supported_ordering_guarantees
supported_identity_proofs
```

Capabilities are claims, not guesses. An adapter must not advertise exact time bounding, stable cursors, stream identity, or provable completeness unless its conformance suite proves that capability for the supported provider/runtime versions.

Capability changes require an adapter version change and new conformance results.

## Metadata-only discovery

Discovery exists to show the user what can be approved. It is never a sampling or indexing step.

### Discovery may read

- executable presence, absolute resolved path, version, and signed/package identity where available;
- authenticated provider identity such as AWS account and region or Kubernetes cluster identity;
- repository-local configuration already inside the current approved repository;
- names and metadata of candidate containers, units, log groups, namespaces, or services when that provider operation is metadata-only;
- local candidate path metadata: canonical path, type, size, modification time, owner/permissions, and rotation naming;
- source capability and permission status without retrieving log messages.

### Discovery must not read

- a sample line, record body, stack trace, event field, or provider stderr containing log content;
- arbitrary files to infer that they look like logs;
- a home directory, parent directory, mount, container estate, cloud account, namespace, or log group recursively without an explicit metadata scope and cap;
- historical data for template warming, ranking, indexing, or format learning;
- Evidentrail's active snapshot, diagnostic, telemetry queue, key-envelope, or support-bundle directories.

Discovery output is sensitive metadata. It is displayed locally and is not product telemetry.

### Discovery result

Each candidate includes:

```text
adapter_kind
effective_source_identity
human_display_name
available_scope_dimensions
capability_flags
permission_state
identity_checked_at
metadata_expiry
```

It contains no credential, credential path value, raw provider response, or content-derived field.

## Approved source binding

A `SourceBinding` is a versioned local capability, not a convenient default. It contains no credential.

Required binding fields are:

```text
binding_id and binding_version
contract_version and policy_version
repository_identity
adapter_kind and minimum adapter version
effective source identity constraint
allowed source selectors
allowed local roots or provider resources
allowed environment/namespace/service/resource/container/unit sets
allowed query/filter fields and operators
maximum lookback and future-clock tolerance
maximum records, source bytes, expanded bytes, pages, and wall time
approved command preset, if used
snapshot mode and maximum TTL
created_at, approved_at, and optional expiry
binding digest
```

The effective source identity uses provider-native immutable identity where available: account ID and region, cluster UID/API server identity, log-group ARN, container ID and daemon context, journal boot/machine identity, file root plus filesystem identity, or replay manifest checksum. A mutable display name alone is insufficient.

### Binding intersection

`plan(binding, intent)` computes an intersection. It never replaces a missing request field with a broader source default.

Rules:

- requested set-valued selectors must be subsets of their allowed sets;
- requested time interval is intersected with the binding's lookback and absolute limits;
- requested caps become the minimum of request, binding, adapter, and policy caps;
- requested filters are added with logical `AND`; they cannot remove binding predicates;
- an omitted optional selector resolves to the binding's already approved value, never to provider-wide scope;
- provider, account, cluster, region, namespace, local root, repository, and command preset cannot be overridden;
- aliases and mutable names are resolved to immutable identities before comparison;
- an empty intersection returns `InvalidRequest`, not a broad fallback;
- an incomparable or ambiguous request returns `NeedsApproval` with a local scope diff;
- a semantic keyword or anomaly filter may create an additional bounded lane, but it cannot replace the unfiltered approved acquisition unless the user explicitly requested that exact exclusion and the plan records it.

The intersection implementation must be property-tested for monotonicity: every accepted plan is no broader than its binding along every dimension.

## Query plan

`QueryPlan` is immutable, versioned, serializable for provenance, and executable only by its named adapter. It separates canonical provenance, sanitized display, and any internal executable representation.

Required fields:

```text
contract_version
plan_id
adapter_kind and adapter_version
binding_id, binding_version, and binding_digest
policy_version
repository_identity digest
effective source identity and identity proof timestamp
resolved source members
incident time interval and optional reference interval
exact selectors and provider-side filters
filter provenance: binding | explicit user | adapter-required
ordering request and source ordering capability
record, source-byte, expanded-byte, page, decompression, and wall-time caps
per-record and per-stream limits
snapshot mode and expiry
expected completeness capability
continuation start, when explicitly authorized
canonical plan bytes and digest
sanitized human display
created_at and execute_before
```

The canonical plan contains no secret but is C2 sensitive metadata. It must distinguish all inputs that can change acquired bytes or completion. Equivalent plans produce identical canonical bytes; materially different bounds, source members, filters, executable versions, or identity proofs do not.

The sanitized display shows effective account/cluster/root, exact scope, time interval, filters, caps, source members where safe, and expected completeness limitations. It removes credentials and secret-bearing environment values; it does not hide scope.

Before reading content, `execute` revalidates:

- plan has not expired;
- adapter and contract version are supported;
- binding and policy have not been revoked or changed;
- executable/source identity still matches;
- local root/source members still satisfy containment;
- effective provider identity still matches the plan.

A changed identity fails before acquisition. A source that changes after acquisition starts follows the source-changed rules below.

## Raw envelope

`RawEnvelope` is an immutable transport object for one source-defined record or record fragment. It is byte-oriented; it must not require valid UTF-8.

For every envelope, the sink atomically records exactly one of `SourceExact`, `PostPolicy { policy_digest, transformation_receipt_id }`, or `OmittedByPolicy { policy_digest }`. It acknowledges the envelope only after that outcome is durable or retained in explicit memory-only mode. IDs and content hashes are computed over the retained authorized basis; when policy forbids retaining even an original-content commitment, no source-content hash survives. Only `SourceExact` may claim source-byte expansion.

Required fields:

```text
contract_version
retrieval_id
adapter_kind and adapter_version
plan_id and plan_digest
source identity digest
source member identity
acquisition sequence: monotonically increasing across acknowledged envelopes within retrieval
source-native event ID or cursor, as exact bytes when available
source-native stream identity: stdout | stderr | container | journal | log stream | file member | other
lane sequence: monotonically increasing within one source-member/stream lane
exact payload bytes
exact record terminator bytes, when source-defined and separate from payload
provider timestamp raw bytes and parsed value, when available
ingestion/provider-observed timestamp, when available
adapter emission wall time, when available
native metadata in lossless typed form
record state: complete | source-truncated | adapter-fragment
format and encoding hints, explicitly non-authoritative
```

### Byte and provenance rules

- The payload and terminator are the exact bytes emitted by the approved source operation or exact bytes of the approved file range.
- Invalid UTF-8, embedded NUL, blank records, duplicate records, malformed JSON, and very long records are valid inputs.
- Adapters may parse provider framing to find record boundaries, but they may not normalize whitespace, line endings, Unicode, timestamps, severity, JSON key order, escaping, or message content.
- Native structured fields are additive provenance. They do not replace the exact payload.
- Duplicate payloads receive different acquisition sequences and remain separate envelopes.
- Global ordering uses acquisition sequence. Atomic block contiguity uses lane sequence within `(source member, stream)`. Parsed timestamps never replace either sequence because clocks can collide or move backward.
- `RawEnvelope` has no durable pre-policy content hash. After authorization, the sink computes an `AuthorizedContentHash` over persisted `SourceExact` or `PostPolicy` bytes; `OmittedByPolicy` retains no content-derived commitment. A source-supplied transport checksum may be verified transiently but is not receipted or persisted unless policy explicitly authorizes it.
- Encrypted object identity, authorized byte span, authorized content hash, and sink receipt time belong to the persisted `EventRecord` and sink acknowledgement, not the pre-policy envelope.
- Transport credential values, auth headers, bearer tokens, signed URLs, and secret environment values used to call the provider must never enter an envelope. Credential-looking bytes returned as part of a log record are source content and follow the explicit policy outcome; they must not be silently removed.
- If a provider response contains both record data and operational diagnostics, only the record data becomes normal `RawEnvelope`. Free-form provider diagnostics are stored, if needed, as a separate encrypted C3 attachment referenced by a stable completion error code.

For a source whose record is larger than a hard byte cap, the adapter may emit an exact fragment only if it marks `adapter-fragment` or `source-truncated`, reports partial completion, and records which bound caused truncation. It may never present a fragment as a complete event.

### Sink acknowledgement

The sink acknowledges the acquisition sequence and authorized byte count. The adapter:

- must not reuse or skip an acquisition sequence or a lane sequence within its lane;
- must stop if acknowledgements become invalid or out of order;
- reports delivered counts from acknowledgements, not attempted sends;
- cannot return `Complete` until every emitted envelope is acknowledged;
- retains no unencrypted retry queue after `execute` returns.

## Fetch completion

`FetchCompletion` is the terminal fact about provider acquisition. It is separate from both downstream receipts: `AcquisitionReceipt` accounts for every acknowledged `SourceRecordId` as persisted or policy-omitted, while `PresentationReceipt` accounts for every persisted `EventId` as shown, pattern-represented, or retained raw. Neither receipt can turn an incomplete or unknowable provider acquisition into a complete result.

All variants include:

```text
retrieval_id, plan_id, and plan_digest
started_at and ended_at
acknowledged record, payload-byte, and source-byte counts
pages/source members attempted and completed
first and final cursor/high-water mark, where available
cap usage
stable adapter outcome and error codes
```

### `Complete`

`Complete` means the adapter can prove that every record inside the exact bounded `QueryPlan` was emitted and acknowledged. Proof is source-specific and recorded in the completion.

The following are not sufficient by themselves:

- child exit code zero;
- reaching EOF on a provider stream whose retention or rotation behavior is unknown;
- receiving fewer records than a cap;
- receiving no continuation token when the API does not define that as exhaustion;
- successfully parsing all records that happened to arrive;
- reconciling either downstream receipt.

### `Partial`

`Partial` means a known condition prevented full acquisition. It contains one or more stable reasons and any safe continuation state:

```text
RowCap | SourceByteCap | ExpandedByteCap | PageCap | WallTimeCap
Timeout | Cancelled | BackpressureLimit
PaginationIncomplete | ProviderCap | ProviderTruncation
PermissionLimited | AuthenticationChanged | RetentionBoundary
SourceChanged | SourceDisappeared | SourceReadError
ChildExitFailure | ChildKilled | NetworkFailure
MalformedProviderFraming | RecordTruncated | DecompressionLimit
SinkFailure | OtherVersionedReason
```

Free-form error bodies are C3 and do not belong in normal completion details or diagnostics. A safe detail may contain only enumerated context and numeric counts.

### `Unknown`

`Unknown` means acquisition ended without an observed truncating failure, but the source or adapter cannot prove that every in-bound record was available and returned. Examples:

- a log driver does not expose rotation or retention loss;
- a provider CLI gives no reliable exhaustion signal;
- a live or eventually consistent source cannot establish a fixed high-water mark;
- permissions allow a query but not enough metadata to prove completeness;
- provider documentation leaves pagination or ordering semantics unspecified for the used mode.

Unknown is not partial success disguised as complete. It carries a stable reason such as:

```text
ProviderHasNoCompletenessProof
RetentionUnobservable
HighWaterMarkUnverifiable
EventuallyConsistentWindow
LiveStreamOpenEnded
AdapterCapabilityLimit
```

The Log Brief must display both `Partial` and `Unknown` prominently. Only `Complete` may produce a provider-complete claim.

## Cancellation, deadlines, caps, and backpressure

### Cancellation

- Every execution accepts a cancellation token and absolute deadline.
- Cancellation stops new reads immediately and returns `Partial(Cancelled)` with exact acknowledged counts.
- Direct child processes run in a dedicated process group; cancellation sends the configured graceful termination, then force-kills and reaps the full group within a bounded interval.
- Network requests and pagination loops must be cancellable between and during requests where the client permits.
- Cancellation cannot discard already acknowledged envelopes or convert them into unaccounted records.
- Cancellation before any content is received still returns a zero-record partial completion once execution has started.

### Caps

Every plan carries independent limits for:

- records;
- source bytes read;
- expanded/decompressed bytes;
- pages or source members;
- per-record bytes;
- in-flight memory;
- persistent encrypted spool bytes;
- wall time;
- child stderr/diagnostic attachment bytes.

The effective cap is always the strictest of user request, binding, policy, adapter, and product limit. Hitting any cap is partial unless the adapter can prove the bounded source was already exhausted before the cap.

Where possible, stop on a source record boundary. If the source cannot expose a boundary without crossing a cap, retain the exact allowed fragment, mark it, and report `RecordTruncated` plus the governing cap.

The output-token budget is not an acquisition completeness signal. Evidence packing happens after capture.

### Backpressure

The sink uses a bounded channel and acknowledges persistence. An adapter must:

1. pause or slow the source when possible;
2. otherwise use the approved encrypted bounded spool;
3. stop with `Partial(BackpressureLimit)` before dropping or overwriting a record.

In-memory unbounded queues, lossy sampling, overwrite rings, and silent provider-page abandonment are forbidden. Backpressure timing contributes to the wall-time cap and is reported separately in metrics.

## Source-changed semantics

Source identity and content can change between discovery, planning, opening, and completion. The contract distinguishes these times.

### Before execution

If account, cluster, daemon, root, executable, file target, replay manifest, or other effective identity differs from the plan, execution fails with `IdentityChanged` before reading content.

### After execution starts

- **Append after a fixed file high-water mark:** does not make the snapshot partial when the adapter reads the exact originally recorded range and verifies it. New bytes are outside the plan.
- **Rename/rotation with the original handle open:** may remain complete for the original identity and high-water mark. The replacement is outside the plan and is disclosed.
- **Truncate below the planned high-water mark:** `Partial(SourceChanged)`.
- **Replace, inode/device change, or symlink retarget before a safe handle is acquired:** fail before acquisition.
- **Identity change detected after some records were acquired:** preserve acknowledged records and return `Partial(SourceChanged)`.
- **Container name now resolves to another container ID, pod name to another UID, Kubernetes context to another cluster, or AWS identity to another account:** fail before acquisition or partial if the provider changed mid-request.
- **Provider retention advances through the requested interval:** `Partial(RetentionBoundary)` when known, otherwise `Unknown(RetentionUnobservable)`.
- **Eventually consistent late arrivals:** use `Unknown(EventuallyConsistentWindow)` unless the provider offers a documented finality/high-water mechanism.

No adapter silently follows a rotated replacement, resubmits against a new provider identity, or widens time to compensate. A refresh is a new plan.

## Exact file snapshot adapter

The file adapter is the reference implementation for exact capture.

### Discovery

Discovery reads path metadata only. It does not open and sample content. It rejects active Evidentrail data directories and reports symlinks as metadata rather than following them into content discovery.

### Planning

Planning:

1. validates the approved root;
2. resolves an explicit path or bounded glob into a deterministic manifest;
3. canonicalizes and checks containment;
4. rejects special files;
5. sorts manifest members deterministically;
6. records member identity, size, modification time, and requested byte range;
7. calculates a fixed high-water mark for each member;
8. applies file, source-byte, expanded-byte, and wall-time caps;
9. records whether the first/last byte may be a record fragment.

### Execution

Execution opens each member without following a final symlink where supported, verifies the opened handle, reads only the planned range, snapshots bytes before framing, and verifies identity/size after the read.

Line endings and separators are evidence bytes. The adapter must preserve `LF`, `CRLF`, lone `CR`, missing final terminators, blank lines, invalid UTF-8, and embedded NUL. It must never use a lossy string reader.

If planning starts inside a line for a bounded tail, the leading fragment is emitted and marked as a fragment unless the adapter safely scans backward within an independently capped boundary.

### Rotated and compressed files

- Every rotated member is explicit in the manifest.
- Rotation after opening follows the source-changed semantics above.
- Gzip or another approved compressed member is preserved as exact source bytes. Decompressed bytes are a deterministic derived capture with compressor/member/version provenance and independent expansion limits.
- Archive members cannot write to disk, escape the approved manifest, recurse, or enroll additional sources.
- Decompression failure preserves source bytes and returns partial; it never silently skips the member.

### File completeness proof

The adapter may return `Complete` only when every manifest member was opened as planned, every byte through its fixed high-water mark was read and acknowledged, before/after identity checks pass, and no bound terminated execution. Completeness is relative to that explicit manifest and high-water mark, not to other files that may exist.

## Replay adapter

Replay is a hermetic source for contract tests and EvidentrailBench. It must exercise the identical `RawEnvelope` and `FetchCompletion` path used by live adapters.

A replay case includes:

```text
manifest version and case ID
source blobs and checksums
exact planned source identity
ordered envelope boundaries and native provenance
virtual timestamps and deterministic sequence
expected Complete, Partial, or Unknown completion
optional scripted cancellation, cap, corruption, delay, and source-change events
```

Replay requirements:

- verify every manifest and blob checksum before emitting the first envelope;
- access no path outside the approved case root;
- use a virtual clock for delays, deadlines, and cancellation;
- reproduce bytes, boundaries, sequence, cursors, completion, and faults deterministically;
- support duplicate bytes, invalid UTF-8, embedded NUL, malformed provider framing, empty pages, repeated tokens, and source changes;
- fail the case rather than silently adapting to a missing or changed fixture;
- report itself as `replay`; it must never claim to be a live provider result.

Private replay blobs remain outside the product repository and ordinary CI under the private-data policy.

## Direct argv command runner

Command-backed adapters share one reviewed runner. There is no shell-string API.

An executable plan contains:

```text
approved preset ID and version
resolved absolute executable path and identity
argv as an ordered vector of separately validated values
allowlisted environment variable names
approved working directory
stdin policy
stdout/stderr framing policy
process-group and cancellation policy
byte/time caps
sanitized display argv
```

Requirements:

- spawn the executable directly;
- do not invoke `/bin/sh`, `bash`, `zsh`, PowerShell, `cmd.exe`, or equivalent as an implementation detail;
- do not concatenate, interpolate, reparse, or evaluate argv;
- reject unknown flags, subcommands, positional arguments, response files, config overrides, plugin loaders, output redirections, and provider endpoints;
- use `--` where supported to terminate options before validated literal selectors;
- never place credentials in argv;
- use an environment allowlist and redact values from all display and diagnostics;
- close stdin and unrelated file descriptors;
- capture stdout and stderr separately;
- terminate and reap the process group on all exit paths;
- record executable identity, exit category, and stable error code in completion;
- treat free-form stderr as encrypted C3 content, not a diagnostic string.

The human-facing `run` path still uses direct argv. If a user needs shell composition, the user runs that shell themselves and pipes the resulting bytes to Evidentrail's stdin adapter. A shell executable cannot be promoted into an agent-accessible source binding.

## Mandatory conformance suite

No adapter is enabled in a release until it passes the shared suite plus its source-specific cases. A capability may be marked unsupported; it may not be claimed without tests.

### Shared conformance tests

| ID | Required behavior |
| --- | --- |
| `SRC-001` | Discovery performs metadata operations only; content canaries are never read or returned. |
| `SRC-002` | Every accepted plan is a subset of its binding across identity, selectors, time, filters, and caps. |
| `SRC-003` | Canonical plan bytes and digest are deterministic; sanitized display contains scope but no secrets. |
| `SRC-004` | Execution-time identity mismatch fails before content acquisition. |
| `SRC-005` | Invalid UTF-8, embedded NUL, blanks, terminators, and duplicate payloads are emitted byte-exactly and distinctly. |
| `SRC-006` | Acquisition sequence is unique, contiguous, and deterministic globally; lane sequence is unique and contiguous within each source-member/stream lane; timestamp collisions and cross-lane interleaving do not change either. |
| `SRC-007` | Native IDs, cursors, stream identity, source members, and byte spans survive ledger ingestion. |
| `SRC-008` | `Complete` is returned only with the adapter's documented proof; partial and unknown cases cannot render complete. |
| `SRC-009` | Every record/byte/page/time/decompression cap stops honestly with acknowledged counts and no silent drop. |
| `SRC-010` | Bounded backpressure pauses, encrypted-spools, or returns partial; it never loses or overwrites a record. |
| `SRC-011` | Cancellation and timeout stop acquisition, kill/reap descendants where applicable, and preserve acknowledged records. |
| `SRC-012` | Source replacement, truncation, rotation, identity change, and retention movement follow the source-changed rules. |
| `SRC-013` | Provider stderr and free-form failures do not enter contentless diagnostics, telemetry, or support bundles. |
| `SRC-014` | Log-borne instructions do not influence a later command, query, path, scope, policy, or completion status. |
| `SRC-015` | Active Evidentrail data directories cannot be enrolled or reached by an adapter. |
| `SRC-016` | A sink failure cannot produce inflated delivered counts or `Complete`. |
| `SRC-017` | Repeated execution of a frozen replay plan produces identical envelopes and completion. |
| `SRC-018` | Credentials and secret-bearing environment values appear in neither plans, envelopes, diagnostics, nor fixtures. |

### Adapter certification matrix

Every cell marked **Required** must have at least one passing automated case. **Conditional** means the adapter may declare the capability unsupported; if it supports the mode, the test becomes required.

| Adapter | Metadata-only discovery | Immutable binding identity | Required query boundary | Exact record provenance | `Complete` proof | Required partial/unknown cases | Cancellation/backpressure | Source-specific gate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| File | Required | Canonical root plus opened file identity | Explicit manifest and byte high-water marks | File member, device/inode equivalent, offset, payload and terminator | All manifest bytes through verified high-water marks acknowledged | Symlink/path denial, disappear, truncate, rotate, append, permission | Required | No lossy string read; no special file; compressed files are unsupported in v1; source removal after snapshot does not break local expansion |
| stdin | Explicit invocation; no discovery | Invocation/session identity | EOF or explicit byte/time cap | stdin stream plus arrival sequence and exact terminators | EOF reached before any cap | Cancel, producer error, byte cap, open-ended stream unknown/partial | Required | No reread assumption; expansion uses local snapshot only |
| `run` | Executable metadata only | Preset ID plus absolute executable identity | Direct argv, working directory, record/byte/time caps | Separate stdout/stderr streams, process identity, arrival sequence | Child exits successfully, streams reach EOF, and no cap; only for a source whose command contract defines success as exhaustive | Nonzero exit, signal, child leak, stderr cap, timeout, cancellation | Required; process group reaped | No shell; hostile metacharacters remain one literal argv element or are rejected |
| Docker | Context and container/service metadata only, including Compose labels | Daemon context plus immutable container IDs | Explicit container set, since/until or fixed high-water mode, caps | Container ID, stream, daemon timestamp/details, sequence | Only when the supported log driver/API exposes an exhaustive fixed boundary | Container replacement, restart, unsupported driver, rotation/retention unknown, daemon change, cap | Required | Mutable names and Compose services resolve to IDs and are revalidated; all-container is scope widening |
| journald | Unit/boot/machine metadata only | Machine/boot identity plus exact unit set | Units, boot/cursor, since/until, caps | Cursor, boot ID, unit/transport metadata, exact exported record bytes | Final documented cursor/bound reached with permissions sufficient for the approved units | Cursor invalidation, journal vacuum/retention, permission, boot change, follow cancellation | Required | JSON/export parsing never replaces exact journal payload; system-wide scope requires approval |
| macOS | Unified-log store/predicate capability metadata only | Host/store identity plus approved predicate scope | `log show` start/end and bounded predicate; `log stream` deadline | Process/subsystem/category fields plus exact command output record bytes | Conditional; only if the supported macOS mode provides a documented exhaustive bounded-store proof | Retention unobservable, permission, store change, `log stream` open-ended, cap | Required | Exit zero alone is normally `Unknown`, not proof of complete historical availability |
| Kubernetes | Context metadata, namespaces, workloads, pods/containers only | Cluster identity, namespace, pod UID, container and restart instance | Explicit snapshotted pod/container set, bounded since/time/tail/bytes | Cluster, namespace, pod UID, container, restart instance, stream/timestamp, sequence | Conditional; only for a tested API mode that proves the entire fixed pod/container boundary | Pod replacement, container restart, previous-log gap, rotation, permission, context change, tail/byte limit | Required | Names are never identity; pod list and per-container acquisition completeness are both reported |
| CloudWatch | Account/region/log-group metadata only | Account ID, region, partition, log-group ARN and allowed stream set | Start/end milliseconds, exact group/streams, approved filter and page/byte/time caps | Event ID, log-stream name, event and ingestion timestamps, exact message bytes, page sequence | All pages exhausted using documented token semantics with no service/local cap or error | Empty page with token, repeated token, throttling, permission, retention, eventual consistency, page/time cap | Required | Account identity rechecked; pagination continues through empty pages; duplicate event IDs handled explicitly |
| Replay | Manifest metadata and checksums only | Case root plus manifest digest | Frozen manifest scenario | Manifest-defined exact bytes, virtual provenance, sequence | Expected completion proof encoded and checksum-verified | Every partial/unknown reason can be scripted | Virtual deterministic cancellation/backpressure | Zero host-source discovery; checksum mismatch emits nothing |

### Adapter-specific minimum fixtures

#### File

- LF, CRLF, missing terminator, blank line, invalid UTF-8, NUL, duplicate bytes;
- symlink inside root, symlink escape, final-component swap, path traversal, special file;
- append after high-water, truncate, rename with open handle, replacement inode, disappear before open;
- explicit rotation manifest and a new unapproved rotation member;
- compressed input is rejected as unsupported in v1; before compressed sources graduate, add a versioned derived-exact transformation chain plus success, corruption, expansion-ratio, and expanded-byte-cap fixtures;
- file deletion after successful snapshot followed by exact local expansion.

#### stdin and `run`

- EOF success, cancellation before first byte, cancellation after acknowledged bytes;
- producer faster than sink, backpressure timeout, output cap;
- stdout/stderr interleaving and identical timestamps;
- hostile argv values containing whitespace, quotes, semicolons, pipes, substitutions, newlines, and option prefixes;
- nonzero exit, signal, descendant process, executable replacement, environment-secret canary.

#### Docker and operating-system sources

- mutable name resolving to a changed immutable ID;
- logs that rotate or disappear during acquisition;
- permission that permits metadata but not content and the inverse;
- live/follow mode cancellation;
- provider/driver mode with no completeness proof returning `Unknown`;
- prompt-injection content that resembles a command or policy update.

#### Kubernetes

- multiple pods with colliding names/timestamps and deterministic acquisition plus lane sequences;
- pod deletion/recreation, container restart, init container, previous instance;
- partial RBAC across pods/containers;
- context change after planning;
- server-side tail/limit truncation;
- one member failure while others succeed, producing aggregate partial completion.

#### CloudWatch

- empty page with a next token;
- next-token repetition/end semantics;
- duplicated event IDs and out-of-order event timestamps;
- throttling with bounded retry, timeout, and cancellation;
- one denied stream/group scope;
- retention boundary and late-arriving/eventually consistent events;
- account or region change after planning.

## Aggregate completion for multi-member sources

File manifests, Docker sets, Kubernetes pod/container sets, and CloudWatch stream sets contain multiple members. The adapter records a member completion for each and produces an aggregate:

- aggregate `Complete` only when every approved member is complete;
- aggregate `Partial` when any member has a known partial reason;
- aggregate `Unknown` when none is partial but at least one is unknown;
- if some members are partial and others unknown, aggregate is partial and preserves both the known reasons and member-level unknown statuses;
- a missing approved member is not equivalent to an empty member;
- member failures and zero-record members remain visible in the query plan and completion.

The adapter may continue other members after one fails when policy and deadline allow. It cannot omit the failed member from the aggregate denominator.

## Versioning and compatibility

- Contract, adapter, binding, canonical-plan, envelope, and replay-manifest versions are explicit.
- A newer adapter may read an older binding only through a tested migration that preserves or narrows authority.
- Unknown security- or scope-relevant fields fail closed. They are not ignored for forward compatibility.
- Unknown native metadata may be retained losslessly as content but cannot affect scope or commands until understood.
- Completion reason additions are versioned; an older renderer must display an unknown reason as non-complete.
- Changing canonicalization, identity proof, record boundaries, or completeness proof requires updated golden fixtures and benchmark provenance.

## Release and operational gates

An adapter is blocked from release if any of the following is true:

- discovery reads source content;
- an accepted plan is broader than its binding;
- executable or provider identity can change without detection;
- any source byte is normalized, decoded lossily, silently skipped, or emitted without provenance;
- a cap, cancellation, source change, permission limitation, provider uncertainty, or sink failure can become `Complete`;
- backpressure can drop or overwrite a record;
- cancellation leaks a child process or provider request beyond the grace period;
- credentials or source content appear in a sanitized plan, diagnostics, telemetry, support bundle, fixture failure, or ordinary CI artifact;
- log content can influence a later source operation;
- active Evidentrail data paths can be self-ingested;
- the adapter lacks passing shared and source-specific conformance results for its claimed capabilities.

Certification results must identify adapter version, provider/runtime version, operating system, fixture manifest, and test revision. A provider upgrade that changes pagination, output framing, identity, or completeness semantics invalidates the affected certification until rerun.
