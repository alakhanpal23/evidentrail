# Wire and product contract implementation plan

**Status:** G3 implementation decision; schemas not yet frozen  
**Date:** August 24, 2026  
**Depends on:** [`LOG_BRIEF_CONTRACT.md`](LOG_BRIEF_CONTRACT.md),
[`SOURCE_ADAPTER_CONTRACT.md`](SOURCE_ADAPTER_CONTRACT.md), and
[`adr/0004-encrypted-local-snapshot-store.md`](adr/0004-encrypted-local-snapshot-store.md)

## Decision

Keep constructor-validated semantic types in dependency-free `evidentrail-schema`.
Create a separate `evidentrail-wire` crate for Serde DTOs, strict version dispatch,
canonical JSON, JSON Schema artifacts, and checked domain-to-wire conversion.

The dependency direction is one way:

```text
evidentrail-schema <- evidentrail-core <- evidentrail-wire
                         ^
evidentrail-bench --------------+
```

`evidentrail-schema` and `evidentrail-core` never depend on `evidentrail-wire`. Deserialization
never constructs a ledger event, block, receipt, or brief by assigning private
fields. A DTO is untrusted until a checked constructor or a sealed-domain
export validates it.

The encrypted store's fixed binary headers and AAD are a separate internal
format. External canonical JSON is not reused as cryptographic framing.

## V1 scope

V1 is the smallest contract needed for one explicitly approved local-file or
replay result:

- a typed, bounded local query plan and source identity;
- sealed event, block, fetch-completion, acquisition-receipt, and
  presentation-receipt records;
- evidence references scoped to one random result;
- independent acquisition and selection status;
- one structured `LogBriefV1` and deterministic text rendering;
- bounded expansion request/response records; and
- public case, governed annotation, and run manifests for EvidentrailBench.

Cloud/provider plan variants are not speculative fields in the local-file
variant. A later source variant is admitted only with its source-conformance
tests and an explicit versioned schema change.

## Record set

### Identity and plan

`ResultId` is a distinct random 32-byte locator. It does not reuse
`RetrievalId`, derive from content, or act as an authentication secret. Random
generation belongs to the store; schema permits fixed bytes for deterministic
tests. Ordinary `Debug`/`Display` never reveal it. Only the user-facing result
boundary emits its canonical token.

`SourceIdentityV1` contains only typed adapter identity, approved binding
digest, target/source identity digest, and a typed identity-proof kind with
bounded observation/expiry times. It contains no credential or display path.

`LocalFileQueryPlanV1` contains:

- retrieval, plan, adapter, binding, policy, and source-identity references;
- the explicitly approved member identity and snapshot/high-water facts;
- source-byte, record-count, per-record-byte, and wall-time caps;
- requested ordering and the adapter's declared ordering capability;
- creation and execute-before times; and
- an optional sanitized display label that is excluded from plan identity.

The canonical plan material excludes its own IDs, digest, and display label.
Core verifies the declared `PlanDigest` against the canonical material before
execution. Query plans are never auto-migrated and executed under changed
semantics; they are replanned.

### Ledger and receipts

`TransformationReceiptRecordV1` exists only for `PostPolicy`. It records the
policy/version, ordered typed operations, input/output lengths, output content
hash, payload/terminator split, and resulting event. It never stores forbidden
original bytes. Its identity material excludes its own ID and the resulting
`EventId` to avoid an identity cycle.

`EventRecordV1` is exported only from a sealed ledger and carries every typed
provenance and exactness fact required for basis-exact expansion. Payload and
terminator are encoded separately. Native event ID and cursor remain separate.

`EventBlockRecordV1` contains ordered event references and lane sequences, not
duplicate payload bytes. Cross-record validation verifies same-lane contiguous
membership and the exact core `BlockId`.

Acquisition and presentation receipts have distinct typed identities.
Presentation receipt chunks contain at most 4,096 ledger-ordered assignments;
chunk indices, entry counts, event coverage, and a root commitment reconcile
against the exact sealed ledger. Policy omission never appears in a
presentation receipt.

### Product result

`EvidenceReferenceV1` is scoped to exactly one `ResultId`. It contains a
nonempty ordered target list, a sorted unique allowlist of expansion relations,
an expiry, and a result-bound identity. The server also verifies it against the
encrypted result manifest; possession is not authorization.

`ResultStatusV1` always has two independent fields:

```text
acquisition = Complete | Partial(reasons) | Unknown(reason)
selection   = Passthrough | Compiled | NeedsMore(reason)
```

Construction verifies that `Passthrough` shows every persisted authorized
event and that `Compiled` does not claim passthrough. Neither state upgrades or
rewrites acquisition completeness.

`LogBriefV1` follows the exact shape in
[`LOG_BRIEF_CONTRACT.md`](LOG_BRIEF_CONTRACT.md). It has no generated diagnosis,
root-cause paragraph, remediation command, hidden refresh, or log-authored tool
field. Evidence bytes are data, every signal cites evidence references, and
`untrusted_data` is always true.

`ExpansionRequestV1` accepts a result-scoped evidence-reference ID, one
allowlisted relation, and bounded event/byte/token/before/after limits. It does
not accept a raw source query, path, refresh flag, or unrestricted event ID.
`ExpansionResponseV1` reports exact returned packets, truncation and cost, and
updated presentation accounting without changing the original acquisition
receipt.

Expired, forged, cross-result, disallowed, missing-key, and tampered references
collapse to the same contentless public unavailable error. Expansion never
contacts the original source.

### EvidentrailBench

Keep three manifests separate:

1. `EvidentrailBenchCaseManifestV1` contains immutable source/case digests, question
   attachment, plan digest, split/leakage keys, budgets, expected acquisition
   state, and reader configuration.
2. `EvidentrailBenchAnnotationManifestV1` is governed/hidden. It contains weighted
   diagnostic requirements whose alternatives are jointly sufficient evidence
   sets, evidence roles, ambiguity, diagnosis/impact/fix/outcome attachments,
   and adjudication provenance.
3. `EvidentrailBenchRunManifestV1` pins code, lockfile, method/config, renderer,
   tokenizer, model/prompt if any, machine/runtime, seeds, budget vector,
   timings, and per-case artifact/score digests.

Hidden gold labels never enter the public case manifest or runtime candidate
packer. Weights are positive integer micros; wire contracts contain no floats.

## Structural bounds

Bounds are named constants in `evidentrail-schema` and are checked before allocation:

| Object | V1 maximum |
| --- | ---: |
| One wire object | 16 MiB |
| Query plan | 1 MiB |
| Expansion request | 64 KiB |
| Authorized event payload / one acquired record | 8 MiB |
| Event terminator | 64 bytes |
| Query members | 4,096 |
| Selectors or filters | 256 each |
| One opaque selector value | 8 KiB |
| Metadata | 256 fields / 256 KiB encoded |
| Transformation operations | 256 |
| Block members | 4,096 |
| Presentation receipt chunk | 4,096 entries |
| Brief evidence packets | 512 |
| Brief signals / next steps | 256 / 64 |
| Expansion | 512 events / 8 MiB / 131,072 tokens |
| Expansion before/after | 256 each |

JSON integer fields are at most `2^53 - 1`. Nanosecond timestamps use canonical
signed decimal strings. Nonempty collections use checked constructors; set-like
collections are sorted and duplicate-free while source/evidence order remains
semantic.

The product's default result TTL is 30 minutes and reads do not extend it. A
longer organization maximum is policy, not a hard-coded seven-day assumption.

## JSON and identity rules

Every object has an exact `contract` string and integer
`contract_version: 1`. Dispatch uses a streaming header visitor so duplicate
keys cannot disappear into a generic map. Private DTOs reject unknown and
duplicate fields recursively. Unknown contracts, versions, enum tags, and
fields fail closed; extension uses explicit typed versioned variants.

Binary values use exactly:

```json
{
  "encoding": "base64url-nopad",
  "data": "AAE",
  "byte_length": 2
}
```

Decoding rejects padding, the standard Base64 alphabet, length mismatch, and
any value that does not decode and re-encode identically. Hash-shaped IDs use
their exact prefix plus 64 lowercase hexadecimal characters. Uppercase,
wrong-prefix, wrong-length, and noncanonical spellings fail.

Persisted and digested JSON uses RFC 8785 canonicalization and must pass the
published canonicalization vectors before freeze. Artifact identity is SHA-256
over a length-framed domain and the canonical body with its derived digest/ID
field omitted. Existing core `EventId`, `BlockId`, `ContentHash`, and receipt
algorithms remain authoritative; wire encoding does not invent parallel IDs.

## Migration rules

- Migrations are explicit pure `Vn -> Vn+1` functions.
- Migration provenance retains the original canonical artifact digest.
- No field or unknown variant is silently dropped.
- Executable QueryPlans and ExpansionRequests are replanned/reissued, not
  auto-migrated.
- Historical result artifacts migrate only when exactness, references,
  receipts, and expansion semantics are preserved.
- Writers emit one current version. Readers either retain an explicitly tested
  old decoder or fail closed.

## Security formatting

Wire/domain records containing questions, payloads, metadata, source identity,
members, cursors, paths/scope, filters, timestamps, result/reference IDs,
provider details, or content-derived hashes never derive `Debug`.

Manual formatting exposes only record type/version, counts, presence booleans,
byte lengths, and stable enum/error codes. Parser errors never forward JSON
snippets, unknown field names, IDs, hashes, paths, or provider messages into
logs, telemetry, or public output.

## Golden gates

The contract does not freeze until golden tests cover:

- duplicate/unknown fields and versions, noncanonical IDs/Base64, oversized
  lengths/counts, and noncanonical persisted bytes;
- invalid UTF-8, NUL, CRLF, blanks, and duplicate events with exact round trip;
- source-exact, post-policy, and policy-omitted receipts without forbidden
  commitments;
- block reorder, omission, duplication, lane mismatch, and exact reconstruction;
- every pairing of partial/unknown acquisition with passthrough/compiled
  selection;
- `NeedsMore` at a mandatory-over-budget boundary;
- receipt chunk reorder, omission, duplication, and digest tampering;
- log-borne prompt-injection bytes unable to change structure, relation,
  policy, scope, or tool authority;
- expansion success, truncation, expiry, forged/cross-result/disallowed
  references, and proof of zero source I/O;
- public/hidden benchmark-label separation and split-family leakage rejection;
  and
- deterministic canonical bytes, IDs, rendering, and token counts on replay.

## Implementation order

1. Add schema bounds and typed IDs without changing current APIs.
2. Replace free-form pattern and receipt identities with typed IDs.
3. Add the minimal local `SourceIdentityV1` and `LocalFileQueryPlanV1`, then
   verify plan identity inside execution.
4. Add transformation-receipt domain records and exact core export views.
5. Scaffold `evidentrail-wire` canonical binary/ID codecs, strict dispatch, errors,
   and private DTOs.
6. Implement query, ledger/block, and chunked receipt V1 codecs.
7. Implement product status, evidence reference, Log Brief, and expansion V1.
8. Implement EvidentrailBench case, annotation, and run manifests.
9. Freeze JSON Schemas and golden fixtures; only then mark P0 closed.

The next code slice after typed IDs/bounds is deliberately the local-file plan,
not a universal provider schema. This keeps the customer path small while
preserving a clean versioned extension boundary.
