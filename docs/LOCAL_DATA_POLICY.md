# Evidentrail local data policy

**Status:** Normative for the deterministic greenfield product  
**Last updated:** August 24, 2026  
**Default posture:** Local processing, minimum acquisition, encrypted short-lived expansion snapshot, and no content egress

## Purpose

This policy defines how Evidentrail discovers, reads, snapshots, transforms, displays, expands, diagnoses, exports, and deletes local or locally retrieved log data. It applies equally to local application logs, child-process output, Docker and OS logs, downloaded CI artifacts, and cloud-provider logs retrieved through local credentials.

Terms such as **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Product-level commitments

1. Evidentrail MUST read only an explicitly approved, bounded source.
2. Evidentrail MUST NOT crawl a home directory, repository parent, mounted drive, container estate, or cloud account for log content.
3. Discovery MUST be metadata-only until the user approves a binding or one-time query.
4. Exact source bytes MUST stay on the user's machine by default.
5. Persistent raw data MUST be authenticated-encrypted and expire automatically.
6. Evidentrail MUST NOT send content, questions, paths, templates, fields, embeddings, or evidence features as telemetry.
7. Telemetry, remote content, evaluation, and training permissions MUST be independent.
8. No local or customer log becomes benchmark or training data by virtue of being processed by Evidentrail.

## Data classification

### Class C0 — Public product material

Examples: public documentation, public schemas, synthetic fixtures specifically authored for publication, and public dataset manifests. C0 may be committed and included in ordinary CI.

### Class C1 — Contentless operations

Allowlisted numeric or enumerated facts required to operate and improve reliability:

- schema, component, adapter, and policy versions;
- source kind, not source name;
- success, partial-reason, and error codes;
- record, byte, page, pattern, candidate, and selected counts;
- configured limits and output token budget;
- phase timings, peak memory, and process exit category;
- whether expansion occurred, not what was expanded;
- consent-policy version and enabled category bits.

C1 MUST NOT contain free-form strings, exact timestamps tied to a customer incident, paths, account names, questions, query text, evidence, templates, identifiers, hashes derived from content, or high-cardinality labels.

### Class C2 — Sensitive metadata

Examples: repository paths and remotes, provider/account/cluster identity, namespaces, service names, file manifests, source cursors, incident timestamps, repository-to-service bindings, result IDs, and query predicates. C2 remains local unless a specific product function and consent authorize its export.

### Class C3 — Log and diagnostic content

Examples:

- raw bytes, provider stdout and stderr, stack traces, test output, and CI artifacts;
- questions, alerts, filenames, source paths, code symbols, and search terms;
- parsed fields, templates, summaries, embeddings, model features, and redacted evidence;
- exact citations, diagnoses, root causes, fixes, and support attachments.

Derived data remains C3 unless a documented one-way aggregation proves it satisfies the C1 allowlist. Redaction does not automatically turn C3 into C1.

### Class C4 — Governed evaluation and training data

C4 is C2/C3 plus provenance, consent, incident labels, annotations, outcomes, splits, and retention terms. C4 requires a separately approved benchmark or training purpose and never enters the ordinary product repository or CI.

## Discovery and approval

### Metadata-only discovery

Before approval, Evidentrail MAY inspect:

- whether an approved executable is installed;
- provider identity metadata required to show the current account or cluster;
- repository configuration files already within the current repository;
- candidate file path, type, size, permissions, modification time, and rotation naming;
- container names and labels without reading their log output.

Evidentrail MUST NOT sample content to guess whether a source is interesting. Format detection that requires bytes happens only after approval and counts as acquisition.

### Binding approval

The approval display MUST identify:

- source kind and effective identity;
- local root or provider account/cluster/project;
- repository, environment, namespace, service/resource, container, or unit scope;
- allowed time-window and row/byte/wall-time limits;
- exact executable preset, if any;
- raw snapshot TTL and data location;
- whether the result can be complete and how partial results are reported.

Bindings contain no provider credential. They MUST be stored under user-only permissions and keyed to the repository identity. A binding from one repository or tenant MUST NOT be silently reused by another.

Requests may narrow an approved binding. Widening requires a new approval showing the before/after scope.

## Local source rules

### Explicit files and globs

- A user MUST approve an explicit path, root, or resolved glob.
- The query plan MUST list resolved files before content is returned and MUST state any file-count cap.
- Recursive discovery is off by default. A recursive root requires an explicit depth, file-count, byte, and time cap.
- Evidentrail MUST canonicalize roots and targets and enforce containment after opening the file.
- The file adapter MUST reject directories as content, devices, sockets, named pipes, and executable invocation through a path.
- The snapshot MUST record device/inode or platform equivalent, byte offsets, initial and final size, modification time, and read outcome.
- If rotation, truncation, replacement, or concurrent writing makes the boundary uncertain, Evidentrail MUST preserve captured data and label the acquisition partial.
- A rotated or newly created file is a separate source member and MUST NOT be enrolled invisibly.
- Active Evidentrail snapshot, key-envelope, diagnostic, telemetry-queue, and support-bundle directories MUST be excluded from file bindings and resolved globs. This prevents recursive ingestion and accidental elevation of internal artifacts into evidence. An intentionally selected diagnostic artifact must first be copied outside the active Evidentrail data directories and approved as a new source.

### stdin and child-process streams

- stdin is complete only after EOF; cancellation or a cap produces partial status.
- stdout and stderr MUST retain separate stream provenance and a deterministic arrival sequence.
- Provider stderr is C3. It MUST NOT be copied into ordinary diagnostic error text.
- Backpressure and byte limits MUST prevent an unbounded producer from exhausting memory or disk.

### Command presets

- Agent-accessible execution MUST use an approved absolute executable and a reviewed typed-argv template.
- The process MUST be spawned directly without a shell.
- Unknown subcommands, flags, positional arguments, response files, and plugins MUST be rejected.
- The environment MUST be an allowlist. Credential values may be inherited when the provider CLI requires them, but they MUST NOT be persisted or displayed.
- The child working directory MUST be within the approved context.
- stdin MUST be closed unless the preset explicitly defines a safe input protocol.
- The process tree MUST be terminated and reaped on timeout or cancellation.
- Log content and provider output MUST NOT influence a later executable, argument, path, environment value, or source scope.

An advanced command wrapper invoked directly by a human is not automatically safe for agent use. It MUST remain unavailable from normal MCP tools unless the exact command has graduated into a reviewed preset.

### Docker, operating-system logs, and CI artifacts

- Docker and Compose bindings MUST identify exact containers/services and daemon context.
- Journal bindings MUST identify exact unit(s), boot/time boundary, and cursor semantics.
- macOS unified-log bindings MUST show the exact bounded predicate and time interval.
- Downloaded CI artifacts MUST be treated as explicit file manifests with checksums.
- OS-wide or all-container requests are scope widening and require explicit approval.

## Raw snapshot and ledger policy

### Capture order

An adapter MUST capture the approved exact bytes and provenance into bounded process memory as a `RawEnvelope`. A policy-aware ledger sink is the sole downstream consumer. Before any parser or selector can observe an envelope, the sink MUST atomically choose and record exactly one authorized outcome:

1. `SourceExact`: retain payload and terminator byte-for-byte;
2. `PostPolicy`: retain the output of a versioned deterministic transformation plus a `TransformationReceipt`; or
3. `OmittedByPolicy`: retain the policy identity and accounting fact without a payload.

The sink acknowledges an envelope only after the selected outcome is durable or retained in explicit memory-only mode. Parsing, normalization, patterns, rankings, and rendered evidence are derived only from the authorized ledger.

Invalid UTF-8, malformed structured records, duplicates, and unparsed input remain valid when their authorized outcome retains content. A parser failure MUST NOT delete or replace the authorized record.

### Storage modes

Evidentrail supports:

1. **Encrypted expansion mode:** default; persists a short-lived encrypted snapshot so references can expand exactly.
2. **Memory-only mode:** explicit option; permits expansion only while the process/session retains the result.

There is no plaintext persistent mode. If secure persistence cannot initialize, Evidentrail MUST use the explicitly selected memory-only mode or return an error before acquisition.

### Encryption and keys

- Every result MUST use a fresh random data-encryption key.
- Every persisted object MUST use authenticated encryption from a reviewed library and a unique nonce.
- Result ID, object type, schema version, and sequence MUST be authenticated as associated data.
- The data key MUST be wrapped by a key-encryption key stored in the OS keychain or an enterprise-approved equivalent.
- Key material MUST NOT be stored in the result directory, configuration, environment, command line, diagnostics, telemetry, support bundle, or crash output.
- Plaintext staging files are forbidden. Writes MUST stage ciphertext and atomically publish it.
- Secrets and plaintext buffers SHOULD be short-lived and zeroized where the language/runtime permits. Evidentrail does not claim protection from a same-user memory or root attacker during active processing.

### Filesystem placement and permissions

- Snapshots MUST be stored in the platform's user cache/data directory, never inside the source repository by default.
- Directories MUST be accessible only to the current user; files MUST be created user-read/write only.
- Minimal unencrypted cache indexing MAY contain only random result ID, schema version, object count/size, creation time, expiry, and cleanup state. It MUST NOT contain source identity, path, question, hash, template, or evidence.
- Filenames MUST use random identifiers and MUST NOT include source-derived strings.

### Retention and deletion

- Default raw snapshot TTL is 30 minutes from creation.
- Expansion MUST NOT silently extend the TTL.
- A local configuration MAY shorten the TTL. A longer TTL requires an explicit setting and MUST respect an organization maximum.
- Product setup MUST display the active TTL and cache location.
- Deletion MUST first make the wrapped data key unavailable, then remove ciphertext and indexes on a best-effort basis.
- A periodic sweeper and startup recovery MUST remove expired results, stale locks, abandoned ciphertext temporary files, and key envelopes.
- Uninstall instructions MUST identify all local data locations and provide a scoped purge operation.

Because reliable SSD overwrite is not guaranteed, Evidentrail relies on cryptographic erasure and MUST NOT claim forensic physical erasure.

### Crash behavior

- A crash at any write phase may leave authenticated ciphertext or an incomplete ciphertext temporary file, never an intentional plaintext file.
- Startup recovery MUST validate manifests without decrypting unrelated results, delete incomplete objects, and expire stale keys.
- Core dumps, panic hooks, and crash reporters MUST NOT intentionally serialize raw or derived content.
- Crash-recovery tests MUST cover every state transition in snapshot creation, key wrapping, manifest publication, expansion, and deletion.

## Parsing, redaction, and exact evidence

- Every retained event declares `exactness_basis = SourceExact | PostPolicy { policy_digest, transformation_receipt_id }`.
- Source-exact bytes are immutable within their authorized local retention mode.
- A post-policy payload is immutable and exact relative to its recorded deterministic transformation; it MUST NOT be described as source-exact.
- Display-only redaction and reversible tokenization create a separate view and an auditable transformation record.
- Every transformation record MUST identify policy version, transformation type, affected byte span or field, and whether authorized local reversal is possible.
- Unmarked mutation, paraphrase, repair, character replacement, Unicode normalization, and model-authored evidence are forbidden.
- When policy forbids retaining the original, transformation MUST occur in bounded memory before persistence. IDs and hashes commit only to the post-policy basis; Evidentrail MUST NOT retain an original-content hash when the policy forbids even a content-derived commitment.
- Parsing and multiline reconstruction MUST retain source-record membership and confidence.
- Every selected event, pattern, and expansion reference MUST resolve to ledger IDs belonging to the same result.

Acquisition authorization MUST reconcile before ledger coverage:

```text
envelopes_acknowledged = source_exact + post_policy + omitted_by_policy
```

The `AcquisitionReceipt` maps each acknowledged `SourceRecordId` to `Persisted { event_id, exactness_basis }` or `OmittedByPolicy { policy_digest }`. The `SourceRecordId` is result-local and derives from acquisition identity and source position, never payload content. The `PresentationReceipt` MUST then reconcile only retained authorized events:

```text
events_persisted =
    displayed_verbatim
  + represented_only_by_pattern
  + raw_addressable_only

unaccounted = 0
```

Provider-side exclusions, caps, timeouts, retention gaps, and permission failures are reported separately in `FetchCompletion` because those records were never received. `FetchCompletion`, `AcquisitionReceipt`, and `PresentationReceipt` form three non-interchangeable loss boundaries.

## Expansion policy

- Expansion is authorized only for an unexpired result and a reference belonging to that result.
- It reads the local snapshot and MUST NOT trigger an implicit provider query.
- A refresh or wider acquisition is a new query requiring normal scope validation.
- Expansion honors the binding and redaction policy snapshot captured with the result.
- Cross-result references, guessed IDs, modified handles, and expired results MUST fail without revealing whether another result exists.
- Expansion output is C3 and follows the same rendering, diagnostic, and egress controls as the initial Log Brief.

## Evidentrail diagnostic logs

Evidentrail's own logs use a closed schema of C1 fields. They MUST NOT accept arbitrary strings from adapters or core evidence types.

Allowed examples:

```text
operation_started component_version source_kind
fetch_completed status records bytes pages elapsed_ms partial_reason
compile_completed framed patterns candidates selected rendered_tokens elapsed_ms
expansion_completed relation count elapsed_ms
cleanup_completed results_deleted ciphertext_bytes_deleted error_code
```

Forbidden examples include raw messages, provider stderr, query text, question text, paths, filenames, account/cluster/service names, event IDs, source cursors, templates, stack excerpts, hashes of content, and debug serialization of request/result objects.

Diagnostic files MUST rotate, use user-only permissions, and have a documented TTL. Errors use stable codes plus numeric context. A provider's free-form error response is content; it may be retained only in the encrypted result or an explicitly approved private diagnostic attachment.

### No-content canary gate

Every release test injects distinct canaries into:

- raw source content;
- the debugging question;
- file and repository paths;
- provider account/service metadata;
- credential and environment values;
- provider stderr;
- private benchmark annotations.

The test scans diagnostic files, terminal diagnostics, telemetry payloads and queues, panic output, process snapshots created by the harness, cache filenames and unencrypted indexes, support bundles, and CI artifacts. Any canary occurrence outside the encrypted content store or expected user-facing evidence blocks release.

## Consent and egress

Evidentrail maintains four independent controls:

| Control | Default | Permits | Does not permit |
| --- | --- | --- | --- |
| Contentless telemetry | Off | Approved C1 events only | C2/C3, benchmark use, training |
| Remote content processing/retention | Off | The named content path, provider, purpose, and TTL | Evaluation or training reuse |
| Evaluation/benchmark contribution | Off | Approved cases for a named evaluation and retention period | Model training |
| Training contribution | Off | Approved content/labels for a named model purpose | Unrelated models or indefinite retention |

Local encrypted retention for the displayed expansion TTL is part of the local product mode, not remote-content consent. Memory-only mode remains available.

Consent MUST be:

- explicit rather than inferred from product use;
- versioned by policy text and purpose;
- scoped by organization/project/source and data classes;
- visible and revocable;
- independent, so changing one control leaves the others unchanged;
- enforceable before any export, not reconciled after upload.

Revocation MUST stop new collection/use immediately and schedule retained data, derived content, and keys for deletion according to the applicable agreement. Aggregate statistics that are demonstrably C1 and no longer attributable may be retained only when the consent text permits it.

## Benchmark and private incident handling

### Public data

- Dataset manifest MUST record origin, license, version, checksum, acquisition command, allowed uses, and required notices.
- Large public data SHOULD be fetched into a dedicated external data directory rather than committed.
- Generated reports MUST identify the exact manifest and split.

### Private and design-partner data

- Private raw cases, questions, annotations, outcomes, and labels MUST remain outside the product repository and ordinary CI.
- Each case MUST record data owner, approved purposes, collection date, policy version, retention deadline, deletion state, and permitted reader/judge environments.
- Access MUST be least-privilege and auditable.
- Storage and transfer MUST be encrypted.
- Reports default to opaque case IDs and aggregate metrics. Snippets and case narratives require an approved private destination.
- Test labels SHOULD remain hidden from implementation owners to reduce leakage and benchmark gaming.
- A third-party model or judge MUST NOT receive private content without an independently approved processor and data path.
- Evaluation permission MUST NOT be interpreted as training permission.

### Local dogfood data

Existing application logs, IDE logs, agent histories, traces, and crash logs on a developer machine are not automatically Evidentrail data. They MAY be used for local dogfood only after an explicit source manifest is approved. They MUST NOT be committed, uploaded, added to EvidentrailBench, or used for training without the relevant additional consent and review.

Unlabeled dogfood logs may test framing, format drift, throughput, and partial-result behavior. They do not establish diagnostic outcome quality without an authentic question, verified cause/fix, and evidence annotation.

### Training handoff

The deterministic program may define provenance and annotation schemas, but MUST NOT create a training export by default. Model-planning work begins only after the benchmark, consent, and product gates defined by the canonical execution program pass.

## Support bundles

`evidentrail doctor --bundle` MUST:

- build from an allowlist of C1 files and fields;
- exclude raw snapshots, evidence, questions, bindings, credentials, environment values, paths, provider output, and private benchmark content;
- show a manifest and human-readable preview before export;
- create the bundle locally with user-only permissions;
- require a separate explicit action to send it;
- expire or be deleted according to a displayed local TTL.

An optional content-bearing attachment is a separate C3 export with its own preview, destination, purpose, and consent. It is never added implicitly to a support bundle.

## User-visible controls

The product MUST eventually expose:

- active source bindings and their exact scope;
- active local snapshot mode, cache location, and TTL;
- a scoped list and deletion operation for unexpired results;
- metadata-only telemetry status;
- remote-content, evaluation, and training permission status;
- the effective organization policy and any locked settings;
- a preview before any support, benchmark, or training export.

Absence of a UI does not weaken these requirements; the CLI and configuration must provide the same visibility.

## Required verification

Before release, automated tests MUST prove:

1. path traversal, symlink races, rotation, and special files cannot escape approved acquisition;
2. command metacharacters cannot create a second command or change argv structure;
3. every accepted request scope is a subset of its binding;
4. provider identity changes fail before content acquisition;
5. cache and temporary files contain no plaintext canary;
6. unavailable key storage never causes plaintext fallback;
7. crash recovery and TTL cleanup crypto-erase and remove stale results;
8. forged, expired, and cross-result expansion references reveal no content;
9. diagnostic, telemetry, support, panic, and CI outputs contain no content canary;
10. every combination of the four consent controls remains independent;
11. private benchmark content remains outside public/product artifacts and unapproved model calls;
12. every transformation is declared, every acknowledged source record has one acquisition outcome, and every persisted event has one presentation disposition.

The detailed test identifiers and release-blocking criteria are defined in the [Evidentrail threat model](./THREAT_MODEL.md).

## Exceptions

An exception requires:

- a written threat and data-impact assessment;
- the exact data classes, sources, users, environments, and duration affected;
- an owner and expiration date;
- compensating controls;
- user-visible disclosure where behavior changes;
- approval before deployment.

Exceptions do not permit undeclared training use, plaintext persistent log storage, shell execution from the agent path, or silent source-scope widening.
