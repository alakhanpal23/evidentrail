# Phase 1 parallel backlog: trustworthy local walking skeleton

**Objective:** One explicitly approved local file or replay case becomes an immutable local result, returns an exact passthrough Log Brief with reconciled acquisition and presentation receipts, and expands every retained reference byte-exactly relative to its declared basis.

**Out of scope:** learned models, semantic embeddings, production cloud access, generated diagnosis, broad connectors, and structural compression.

## Merge order

```text
P0 contracts
  |-- P1 ledger + receipt + expansion
  |-- P2 source/replay contract + local file snapshot
  |-- P3 benchmark case + raw/grep-tail baselines
  `-- P4 threat/data policy + store interface

P1 + P2 + P4 -> P5 encrypted local snapshot store
P1 + P2      -> P6 framing and passthrough Log Brief
P1 + P3 + P6 -> P7 end-to-end benchmark replay
P5 + P6 + P7 -> P8 CLI/MCP walking skeleton
```

Root manifests, shared schemas, and CI are integration-owned. Parallel lanes work in disjoint crates or documentation paths.

## P0 — Contract lock

**Owner:** integration  
**Dependencies:** none  
**Files:** `crates/evidentrail-schema`, `schemas/`, ADRs

Deliver:

- versioned `QueryPlan`, `SourceIdentity`, `SourceRecordId`, `RawEnvelope`, `FetchCompletion`, `AcquisitionReceipt`, `EventRecord`, `EventBlock`, `EvidenceReference`, `PresentationDisposition`, `PresentationReceipt`, `ResultStatus`, `LogBrief`, `ExpansionRequest`, and EvidentrailBench manifest types;
- stable serialization with unknown-field/version rules;
- global acquisition sequence plus source-member/stream lane sequence and timestamps as distinct deterministic ordering facts;
- random result ID and deterministic result-local event references;
- SHA-256 authorized-content hash computed only over a retained exactness basis and used for mutation checking, not deduplication;
- exact distinction among provider records never received, acknowledged records omitted by policy, and persisted events omitted from presentation;
- golden JSON fixtures.

Decisions that cannot drift:

```text
envelopes_acknowledged = source_exact + post_policy + omitted_by_policy
events_persisted       = shown_verbatim + pattern_represented + retained_raw
unaccounted            = 0
```

A declared transformation is recorded and every acknowledged envelope has exactly one `SourceExact`, `PostPolicy`, or `OmittedByPolicy` authorization outcome. Exactness claims name their basis; a post-policy payload never silently becomes source-exact.

**Exit:** serialization replay is stable, the policy-aware acknowledgement boundary is represented, and all dependent lanes compile against the same shared schema. Provisional ingest-private transport types do not satisfy this exit.

## P1 — Immutable ledger, receipt, and expansion

**Owner:** core/trust  
**Dependencies:** P0 types  
**Files:** `crates/evidentrail-core`

Deliver:

- append-only ledger builder and sealed result ledger;
- exact byte payloads including invalid UTF-8 and embedded NUL;
- deterministic result-local references that distinguish duplicate payloads;
- source metadata, cursor/offset, stream, global acquisition sequence, and lane-sequence preservation;
- content hash verification;
- exact expansion by event/block reference;
- receipt builder that rejects missing, unknown, or multiply assigned records;
- provider completeness and partial reasons carried into the result;
- passthrough identity helper.

Tests:

- fixed input produces the same references and receipt;
- identical duplicate bytes produce distinct events and identical content hashes;
- mutation fails verification;
- invalid UTF-8 expands exactly;
- all acquisition outcomes and all three presentation dispositions are mutually exclusive;
- a missing, duplicate, or foreign reference fails reconciliation;
- provider cap/timeout is not counted as a local disposition;
- fitting payloads retain exact content and order.

**Exit:** contract gates pass without any parser or model.

## P2 — Replay and local file snapshot

**Owner:** ingestion  
**Dependencies:** P0 types  
**Files:** `crates/evidentrail-ingest`

Deliver:

- `SourceAdapter` interface: metadata discovery, bounded plan, cancellable execute;
- replay adapter for hermetic tests;
- explicit-file adapter with canonicalized approved roots;
- exact snapshot high-water mark using path, file identity, offset/size and modification metadata;
- line/record framing that never drops malformed data;
- byte/record/time caps and clear `FetchCompletion` reasons;
- no home crawl, no shell, no implicit globs outside an approved binding;
- source conformance test harness.

Tests:

- symlink escape is rejected;
- rotation/racing append yields an honest partial or high-water-mark-complete result;
- missing permissions and disappearing files are explicit;
- blank lines, malformed JSON and invalid UTF-8 remain addressable;
- caps stop acquisition without pretending completeness;
- replay output is deterministic.

**Exit:** exact envelopes stream through acknowledged authorization into the ledger, and a trustworthy completion state seals the acknowledged prefix.

## P3 — EvidentrailBench smoke harness and cheap baselines

**Owner:** evaluation  
**Dependencies:** P0 types  
**Files:** `crates/evidentrail-bench`, `fixtures/contract`, `benchmark/`

Deliver:

- case manifest with question, acquisition, required/supporting/precursor/symptom/distractor IDs, split keys, budgets and expected partial state;
- deterministic replay runner;
- raw passthrough/truncation baseline;
- deterministic reserved-quota hybrid over validated IDs/lexical matches, head, tail, and coverage sentinels;
- external-command adapter reserved for pinned old Evidentrail/Drain;
- evidence recall, block integrity, accounting, output bytes/tokens, latency and determinism metrics;
- case-level machine-readable results;
- bootstrap module interface for later outcome suites.

Fixtures:

- exact small passthrough;
- repeated noise with one causal clue;
- error symptom before lower-severity precursor;
- multiline stack and nested cause;
- malformed NDJSON and invalid UTF-8;
- severity-overmerge challenge;
- numeric-looking opaque IDs;
- provider cap/timeout;
- log-borne prompt injection;
- secret/redaction boundary;
- file rotation.

**Exit:** the two cheap baselines run reproducibly and the harness can fail a release on evidence loss.

## P4 — Threat model, local data policy, and store contract

**Owner:** security/privacy  
**Dependencies:** P0 vocabulary  
**Files:** `docs/THREAT_MODEL.md`, `docs/LOCAL_DATA_POLICY.md`, store ADR

Deliver:

- trust boundaries, assets, attacker actions and mitigations;
- approved-command rule using executable plus argv, never a shell string;
- path canonicalization and symlink/rotation policy;
- log-borne prompt injection boundary;
- provider scope and credential rules;
- encrypted local snapshot requirements, TTL, deletion and crash recovery;
- diagnostic-log allowlist and no-content canaries;
- separate telemetry, content retention, dogfood, benchmark and training consent;
- private benchmark handling and deletion requirements.

**Exit:** no unresolved design question can force raw evidence into product telemetry or give log text command authority.

## P5 — Encrypted TTL snapshot store

**Owner:** local storage/security  
**Dependencies:** P1, P2, P4  
**Files:** `crates/evidentrail-store`

Deliver:

- authenticated-encryption envelope and pluggable key provider;
- OS-keychain implementation plus ephemeral test provider;
- directory/file permissions, atomic writes and fsync policy;
- per-result expiry, access-time extension policy, cleanup and crash recovery;
- hash verification on read;
- deletion and support-bundle exclusion;
- recursion protection so Evidentrail cannot ingest its own store or diagnostic logs by default.

**Exit:** expansion survives source rotation but not expiry; ciphertext tampering is detected; no raw bytes appear in operational logs.

## P6 — Lossless framing and passthrough Log Brief

**Owner:** evidence skeleton  
**Dependencies:** P1, P2  
**Files:** `crates/evidentrail-core`, `crates/evidentrail-evidence`

Deliver:

- provider-native event framing plus conservative multiline state machines;
- event blocks reference every raw member and expose confidence;
- ambiguous records keep a raw-addressable view;
- exact passthrough renderer when content fits;
- scope, completion, evidence, coverage and expansion sections from one structured `LogBrief`;
- deterministic ordering and token/byte accounting.

**Exit:** a small local incident returns all exact evidence, its receipt reconciles, and every block expands after the source is removed or rotated.

## P7 — End-to-end benchmark replay

**Owner:** evaluation/integration  
**Dependencies:** P1, P3, P6

Deliver:

- full fixture replay through acquisition, ledger, framing, brief and expansion;
- golden receipt and exact-byte comparisons;
- deterministic run manifest containing source revision, fixture checksum, configuration, platform and result hashes;
- CI smoke thresholds and a separate nightly-suite interface.

**Exit:** no silent-loss regression can merge.

## P8 — CLI and MCP walking skeleton

**Owner:** product surface  
**Dependencies:** P5, P6, P7  
**Files:** `crates/evidentrail-cli`

Deliver:

- explicit local file binding;
- metadata-only `evidentrail setup` for the file path;
- `evidentrail logs` development CLI;
- `evidentrail_logs` and `evidentrail_expand` MCP tools using the same structured service path;
- `evidentrail doctor` showing source capability and contentless health state;
- stable errors for partial reads, expired results, policy rejection and unknown references.

**Current checkpoint:** the bounded memory-only subset is implemented as
`evidentrail brief` plus `evidentrail serve-mcp`. The MCP process supports 2026-07-28 and a
2025-11-25 initialize fallback, accepts only explicit canonical Base64 bytes,
serves `evidentrail_logs` and result-scoped `evidentrail_expand`, and expires/drops state in
memory. A library-only injected backend can recover one explicitly supplied,
fully authenticated ciphertext result and serve exact aliases after the
original session is dropped; the default binary cannot activate it until a
production key provider, authenticated expected-context catalog, ciphertext
root configuration, and startup selection exist. `evidentrail doctor --file PATH` is
now implemented as a metadata-only, exact-one-file diagnostic: it runs the
frozen 13-cell macOS/APFS evidence matrix, rejects unsafe target shapes, reads
no target contents, and emits only stable contentless capability, receipt, and
explicit non-admission codes. Approved local-file binding, `setup`, the `logs`
product path, production startup recovery, and cross-process expansion remain
open, so the P8 exit is not yet met.

**Exit:** a coding agent can ask about one approved local file, receive exact passthrough evidence and expand a reference without provider syntax.

## Phase 1 completion gate

Phase 1 is complete only when:

- all contract, ingestion, store, replay and CLI tests pass with warnings denied;
- the committed adversarial suite has zero unmarked mutations and zero unaccounted records;
- every valid reference expands byte-exactly before TTL expiry;
- a rotated/deleted source does not break expansion;
- a partial acquisition is impossible to render as complete;
- no raw evidence appears in Evidentrail diagnostics, CI logs, benchmark reports or telemetry;
- old Evidentrail is still only an external future baseline and no product crate depends on it.

Only then should Phase 2 parallelize the conservative grouper, six evidence views, reference contrasts, evidence graph, and monotone constrained packer. Candidate generation must be evaluated at a frozen vector cost cap, and the runtime packer must use only production-computable nonnegative affinities—never gold required-evidence labels. LLM-training planning remains gated on the later deterministic benchmark and real-outcome milestones.
