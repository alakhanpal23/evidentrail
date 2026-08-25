# ADR 0002: Authorized ledger and three loss boundaries

**Status:** Accepted  
**Date:** August 24, 2026

## Context

A source adapter sees exact source bytes before retention policy is applied. Some deployments permit local source-exact persistence, some require a deterministic transformation before persistence, and some prohibit retaining the record or any content-derived commitment. One EventId-based “coverage receipt” cannot represent all three cases honestly because a policy-omitted record has no retained payload and therefore no content-derived event.

Provider-side missing records are a different fact again: Evidentrail never received them and cannot enumerate what it did not observe.

## Decision

Use three non-interchangeable layers:

1. `FetchCompletion` states what the provider acquisition did and could prove, including `Complete`, `Partial`, or `Unknown` and acknowledged counts.
2. `AcquisitionReceipt<SourceRecordId>` assigns every acknowledged envelope exactly one authorization outcome: `SourceExact`, `PostPolicy`, or `OmittedByPolicy`.
3. `PresentationReceipt<EventId>` assigns every persisted event exactly one presentation outcome: `ShownVerbatim`, `PatternRepresented`, or `RetainedRaw`.

`SourceRecordId` derives from result/plan/member/sequence/cursor identity and never from payload content. `EventId` exists only for persisted authorized bytes. Every persisted event declares its exactness basis. Only `SourceExact` may claim source-byte expansion; `PostPolicy` expands exactly relative to its deterministic transformation receipt. `OmittedByPolicy` retains a policy digest but no content hash.

`RawEnvelope` is bounded in-memory transport whose sole consumer is the policy-aware sink. It contains no durable pre-policy content hash or encrypted snapshot locator. The sink acknowledges only after encrypted durability or explicit memory-only retention.

## Consequences

- Every distinct loss point is measurable without inventing IDs for missing content.
- Policy omission cannot be disguised as renderer omission or provider incompleteness.
- Exactness claims are narrower and testable.
- The former combined coverage receipt and public bulk `EventInput` migration path were removed before P0 contract lock.
- More types and reconciliation tests are required, but later parsing, ranking, and model work receive a coherent trust boundary.
