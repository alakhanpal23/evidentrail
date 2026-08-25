# Greenfield implementation status

**As of:** August 24, 2026  
**Truth rule:** passing tests show that an implemented slice satisfies its current tests; they do not close a product phase whose shared contracts or end-to-end gates remain open.

## Decision

The new product is an independent diagnostic evidence compiler. Old Evidentrail and `legacy-drain` are pinned external benchmark methods only. No product crate may link, vendor, copy, wrap, or invoke them.

The architecture and benchmark have completed adversarial review. That review invalidated four tempting shortcuts before Phase 2:

1. source bytes and post-policy bytes cannot share an unnamed “exact” claim;
2. one EventId-based receipt cannot represent content that policy prohibited retaining;
3. uncosted candidate recall can be made perfect by returning all input;
4. gold required-evidence labels, negative redundancy terms, and overlapping non-additive packet costs cannot appear in the v1 monotone runtime packer.

The corrected specifications are normative. Existing code that predates them is a migration source, not an API compatibility constraint.

## What is implemented and verified

| Slice | Implemented behavior | Status |
| --- | --- | --- |
| Acquisition schema | `RawEnvelopeV1`, typed identities/order/framing/metadata, checked `FetchCompletion`, authorization outcomes, `AcquisitionReceipt`, strict canonical local-file binding/plan material, and closed scoped provider attestations | Passing current contract tests; provider attestations affect only authorized persisted `EventId` material (never position-derived `SourceRecordId`), while public local-file execution remains frozen until governed host certification lands |
| Immutable ledger and result lifecycle | Sole policy-aware envelope consumer; source/post-policy exactness; arbitrary bytes; duplicate identity; typed lane provenance; domain-separated IDs; fixed-TTL memory retention; exact result-scoped expansion; transactional same-question resume after a retained compilation failure; and post-render migration into provider-generic authenticated process-local encrypted retention | Passing current contract tests; plaintext deletion occurs only after encrypted seal/publication, while a durable filesystem/Keychain backend and crash recovery remain Phase 1 |
| Presentation accounting | Separate exhaustive `PresentationReceipt<EventId>` over shown, pattern-represented, and retained-raw events | Passing current contract tests; policy omission exists only in acquisition accounting |
| Atomic blocks | Nonempty exhaustive partition, same-lane contiguous membership, protected blocks, exact expansion, and interleaved-stream coverage; a byte-only conservative framer reconstructs bounded Python, JVM/.NET, JavaScript, Rust, Go, compiler, assertion, and diff blocks | Passing current contract tests; opaque, fragmented, unknown-delimiter, over-cap, and uncertain records remain exact singletons |
| Exact passthrough and compiled Log Brief | Full authorized result is rendered with reversible single-line byte escaping, result-scoped short citations, exhaustive receipts, and one whole-render tokenizer call; one call now performs passthrough-first, budget-independent three-lane proposal preparation, certified selection/rendering, typed retained `needs_more`, or same-question resume without reacquisition | Focused contract and golden tests pass; compiled and budget-`needs_more` results expose the same redacted producer proposal audit, preparation-incomplete results expose only their bound input receipt, resume reuses the exact cached universe, and low-level caller-supplied compilation cannot synthesize this audit |
| Three evidence lanes and canonical compiler | Exact-byte lexical/validated-ID retrieval; complete failure/onset/raw-coverage annotations with exhaustive risk facts but at most five deterministic representatives per risk kind; narrowly scoped native/provider-attested correlations; exact block-universe validation; canonical facet union; renderer-derived packet certification; honest cap/budget `needs_more` | Focused candidate/compiler and governed corpus tests pass; the canonical producer receipt binds exhaustive metadata, exact positive-affinity proposal memberships and costs before budgeted selection. Opt-in instrumentation generates and validates the lanes once, then freezes Full and the three leave-one-lane-out universes without allowing an omitted lane to contribute facets, affinities, mandatory reasons, or proposal admission; Full remains receipt-identical to production. The six-case/24-mask join is frozen with exact lane-removal deltas and attribution. Broader system/fault-family outcome coverage and downstream reader/tool-loop validation remain open |
| Deterministic packer | Pairwise event-disjoint intact packets, canonical production-only facets, fixed-point monotone top-k facility coverage, mandatory evidence, certified composable cost bounds, deterministic density-greedy plus best-single, one-quarter source/service/time breadth weights, a dynamically classified one-eighth optional-token slice for pure breadth gain, and diagnostic-first semantic-role presentation of the frozen set | Provider-attested relations now take the two best affinities from distinct packets at half endpoint weight; all other facets remain top-one. Selector v2/provider v2/compiler v4 bind the closed cardinalities and weights. Exhaustive/property tests cover monotonicity, submodularity, mandatory baselines, third-endpoint zero gain, budget, permutations, and presentation marginals. A benchmark-only exact subset oracle (v2, at most 12 optional packets) binds the concrete production problem before annotations, evaluates all five feasible frozen Full cases exactly, and records zero integer objective regret; governed joining then confirms that each optimum preserves the same 3/3, 5/5, 7/7, 9/9, or 13/13 required-event outcome as production. The sixth case exactly matches production's fixed-overhead `needs_more`. A separate 13-case/seven-family perturbation corpus freezes eight exact-zero cases, two deterministic positive-regret witnesses (400,000 density/knapsack and 500,000 breadth admission-order), two typed `needs_more` cases, and one 13-packet oracle-cap ineligible case. An evaluation-only exact-12/order-aware-beam/production-fallback challenger fixes both positive-regret witnesses with no objective regression across the combined 19 cases, but at higher selected cost. A separate eight-case/seven-family stress corpus with 14–65 optional packets fixes selected cost and coverage charge to production: the challenger is objective- and governed-recall-better in three cases, equal in five, worse in none, and matches the structured exact DP optimum in all six eligible cases. Production remains unchanged because the evidence is synthetic and has no governed wall/RSS receipt. The hermetic 200-record CLI output remains 4,553 bytes and three heartbeat records while preserving the validated request ID and traceback; none of these facts is a population, approximation-factor, learned-ranking, or general outcome-superiority claim |
| Cheap baselines and EvidentrailBench | Whole-event raw truncation, deterministic exact/token grep plus head/tail, reserved-quota hybrid, checked five-dimensional resource envelopes, annotation-free public execution, governed-only hidden-label joins, a reversible canonical producer-universe renderer, exact self-asserted measurement binding, five-axis proposal caps, weighted-requirement recall, non-scalar paired Pareto relations, a two-stage preregistered configured-producer frontier, four exact leave-one-lane-out producer universes, a shell-free bounded external harness, governed reversible-representation bridges, and a provider-neutral bounded reader contract | The unchanged six-case/24-mask governed corpus freezes real Full/ablation selections, exact renders, oracle bounds, every non-perfect attribution, and matched cheap baselines at Full selected unique authorized-source-byte parity. The forced 200-event external case freezes 14 first-party proposals and an eight-group/200-occurrence Drain post-hoc upper bound under the same raw-stdin-to-captured-process-output scope and direct-process RSS observer. One actual pinned same-case deterministic-reader run uses identical reader configuration and produces the same 308-byte answer from 29,018 first-party versus 360,361 Drain prompt-byte units; first-party citations are 2 valid/0 invalid while Drain has no source-exact citation catalog. An evaluation-only compact structured agent view reduces the constrained first-party artifact from 13,936 to 10,612 bytes and the five rendered cases in the six-case corpus from 11,524 to 4,757 bytes while preserving the frozen deterministic answer and citation semantics. A strict hosted-reader JSONL contract is spec-only and has no network implementation. None of these results is VDS, hosted-Evidentrail behavior, a model-token/cold-start/child-tree-RSS claim, a scalar winner, or a general quality win; broader matched reader/tool-loop evaluation remains open |
| Live local-file authority, preflight, and streaming | Exact live binding version/revocation/repository joins, internal-root and active-inode exclusion under read leases, sealed wall-clock expiry, descriptor-relative no-follow opens, exact pre/post snapshot/source/filesystem revalidation, byte-exact retained-handle streaming, acknowledged-prefix accounting, and the source-specific planned-snapshot completeness proof | Passing macOS/APFS synthetic contract tests; production token issuance remains frozen closed until a governed Darwin certification matrix exists |
| In-memory-fixture ingestion | Deterministic replay has acknowledgement validation, cancellation, arbitrary-byte framing, strict bounds, and checked fixture-only completeness | Replay tests pass; the obsolete path-based local-file adapter and its file-only errors/tests have been removed |
| Explicit standard-input CLI and MCP | `evidentrail brief` accepts one bounded caller-owned byte stream plus an explicit question and token budget, preserves LF/CRLF/no-final-newline and arbitrary bytes, uses fresh random result identity material, and prints only the canonical passthrough/compiled brief. `evidentrail serve-mcp` implements bounded newline-delimited JSON-RPC, MCP 2026-07-28 discovery/per-request metadata and a 2025-11-25 initialize fallback, with `evidentrail_logs` over canonical Base64 caller bytes and exact result-scoped `evidentrail_expand` | Focused library/binary/black-box tests and strict Clippy pass, including arbitrary non-UTF-8 process-level compile/expand, duplicate-field and noncanonical-Base64 rejection, sequential JSON-RPC ID reuse, schema-shaped unsupported-version errors, exact expiry, collision preservation, oversized-frame recovery, focal-evidence retention, and a bounded irrelevant-heartbeat regression. Default MCP retains at most 32 successful results and 64 MiB of aggregate source bytes in memory for the fixed 30-minute TTL; it does not discover paths, inspect ambient logs, invoke a model, persist results, or retain expansion after process exit. A backend-neutral library seam can instead inject one explicitly authenticated recovered result and advertise only exact `evidentrail_expand` under modern or legacy MCP. Publish/drop/recover tests prove exact expansion after all session/product owners are gone, with forgery, expiry, tamper/quarantine, relation, and no-prefix cap checks. The default binary remains memory-only because production key authority, authenticated expected-context/result discovery, and configured startup wiring remain open |
| Memory walking skeleton | Synthetic interleaved stdout/stderr plus a 3-scenario, 21-record multi-runtime corpus run through replay acquisition, policy authorization, immutable ledger sealing, conservative framing, passthrough-first three-lane compilation, certified rendering, retained needs-more/resume, exact/same-lane expansion, and the process-resident two-tool MCP surface | Passing focused integration contracts across Python/JVM/.NET/JavaScript/Rust/Go/compiler/assertion/database/Kubernetes-shaped records; governed local-file certification, durable encrypted replay/recovery, matched outcome execution, and cross-process expansion remain open |
| Security hygiene | Contentless Debug/Error canaries across implemented types; hostile bytes cannot inject Log Brief structure; fixed-width XChaCha20-Poly1305 snapshot frames/manifest envelope, AAD, commitments, one zeroizing result DEK, nonce registry, domain-separated wrapping/seal keys, fixed-width AEAD key objects, canonical Creating/Sealed key records, a state-oriented bounded key-provider contract, untrusted fixed-width cleanup hints, segment catalogs, catalog-bound EventId expansion indexes, receipt-ordered source-outcome tables, a bounded self-restoring acquisition-completion record, a canonical ciphertext-only sealed-result bundle, a Unix ciphertext-only filesystem publication substrate, a provider-generic authenticated post-render retention adapter, and an encrypted displayed-alias manifest | The transactional repository and sealed bundle path authenticate provider seal, manifest, catalog, source-outcome/index bijection, frame chain, and complete event AEAD before returning zeroizing exact bytes. Filesystem publication uses a canonical 0700 root, ResultId-derived 0600 names, create-exclusive same-directory temporaries, bounded exact write, file sync, atomic no-replace rename, directory sync, strict readback, and create-only quarantine with symlink/hard-link/alias/race rejection. Product migration seals every ledger event before deleting the retained ledger, admits only store-issued capabilities, and publishes aliases only for displayed packets. The alias manifest binds exact `E<n>` ordinal, recomputable reference, result, expiry, and ordered EventIds. A fresh authenticated restart coordinator preflights independently supplied provider authority, fully imports/authenticates before visibility, quarantines invalid candidates, and returns only an exact-alias handle; whole-event cap failure returns no prefix. The already returned display remains caller-owned until dropped. Production Keychain/root-key authority, authenticated expected-context/result catalogs, configured startup, rollback prevention, cross-process locking, and sudden-power-loss durability remain open |

### Provider V2 admission freeze

The provider-objective correction was admitted on the exact existing fixtures,
questions, annotations, and budgets. These identities prevent a later method
from being reported as the same freeze:

| Bound item | Frozen value |
| --- | --- |
| Selection objective | `evidentrail/selection/top-k-facility-coverage` v2 |
| Provider candidate policy | `evidentrail/provider-attested-correlation` v2 |
| Proposal compiler | `evidentrail/three-lane-positive-affinity-proposal-compiler` v4 |
| Candidate config digest | `0f137cb719a47cee655752160753dcdb279cf1376531b6308a3daf259ac08596` |
| Compiler config digest | `abe61978cc5f4edc4f5c416e0ffc32dbcba4705ee211941ec5e2b5ed4eefb047` |
| Ablation method-family digest | `865526e9b3be94c590f065eb7d2519de9d5dc1c127a966dc7304592ec3d08539` |
| Golden proposal receipt | `7d8ef8e4f54e87d6a84968d15c93b7ce83e96ef94ecb4aa7dc8a08f8912270dd` |

The governed Full outcomes are:

| Case | Full decision/recall | Packets / events / selected source bytes / render-budget units | Raw / grep / quota recall at Full selected-source-byte parity |
| --- | --- | --- | --- |
| Validated identifier | selected, 3/3 | 4 / 4 / 127 / 1,831 | 3/3 / 3/3 / 0/3 |
| Failure and onset | selected, 5/5 | 7 / 7 / 155 / 2,790 | 5/5 / 5/5 / 0/5 |
| Provider relation | selected, 7/7 | 5 / 5 / 119 / 2,143 | 0/7 / 0/7 / 0/7 |
| Mixed lanes | selected, 9/9 | 8 / 8 / 227 / 3,248 | 0/9 / 0/9 / 0/9 |
| Deliberately tiny budget | `needs_more`, 0/11 | 0 / 0 / 0 / 0 | 0/11 / 0/11 / 0/11 |
| Arbitrary structural bytes | selected, 13/13 | 3 / 3 / 122 / 1,512 | 13/13 / 13/13 / 0/13 |

Baseline parity here means only the Full arm's selected unique authorized source
bytes. It is not total rendered-envelope, wall-time, RSS, or episode-cost
parity, and the table is not a scalar winner. Every non-perfect ablation is
attributed to the deliberately removed lane's candidate recall or to the
preregistered infeasible budget. No objective-saturation residual remains in a
Full arm.

The test count is intentionally reported from the next clean full-workspace gate rather than copied from earlier component checkpoints. Green component tests do not override the explicit release blockers above. Re-run the commands in the root README because the count changes as product slices land.

## P0 blockers in exact dependency order

### G0 — Shared acquisition and authorization schema — semantic core implemented

The dependency-free acquisition vocabulary now covers:

- retrieval/plan/adapter identity, `SourceIdentityDigest`, `SourceRecordId`, `RawEnvelopeV1`, and typed member/stream/cursor/timestamp/native metadata;
- `FetchCompletion` with counts, high-water marks, caps, outcomes, and deterministic projection to provider completeness;
- `ExactnessBasis`, `TransformationReceiptId`, and acquisition outcomes; and
- `AcquisitionReceipt<SourceRecordId>` plus a separate core-reconciled `PresentationReceipt<EventId>`.

The local-file `QueryPlan` and its `SourceIdentity` material now have strict
canonical JSON, duplicate/unknown-field rejection, golden fixtures, independent
ID recomputation, and adversarial mutation tests. Transformation-receipt and
the remaining product-facing records still require equivalent wire contracts.
Those gaps keep P0 open; one frozen plan type does not make the complete product
contract stable.

`SourceRecordId` is derived from retrieval/plan/member/sequence/cursor identity, not content. `EventId` is created only for a persisted authorized basis. No original-content hash survives when policy forbids a content-derived commitment.

### G1 — Streaming policy-aware ledger sink — implemented for memory-only retention

The bulk acquisition path has been replaced by discover/plan/execute into a bounded acknowledging sink:

```text
execute(plan, sink, cancellation) -> FetchCompletion
sink.accept(envelope) -> Persisted(event_id, exactness_basis) | OmittedByPolicy(policy_digest)
```

The current sink acknowledges explicit memory-only retention, applies backpressure one envelope at a time, and seals the immutable ledger and acquisition receipt without cloning the whole retrieval. The encrypted durable sink remains Phase 1 work. The local-file engine now consumes only facts owned by its descriptor-backed preflight token, revalidates retained descriptors before and after byte-exact streaming, and records acknowledged prefixes without read-ahead. Public admission remains frozen until a governed Darwin host-certification matrix exists. `ProviderCompleteness` is a deterministic projection of `FetchCompletion`, never its replacement.

### G2 — Typed core provenance and source-lane blocks — implemented

Preserve payload and terminator separately, source member, source stream, member-local sequence/cursor, global arrival sequence, fragment state, timestamps, and native ID in the event ledger. Never hide typed provenance inside opaque provider byte fields.

Block membership must be contiguous in one `(source_member, stream)` lane's sequence, while global arrival order remains separately addressable. Interleaved stdout cannot invalidate a valid multiline stderr block. The primary partition remains exhaustive over persisted events; ambiguous reconstruction retains conservative singleton/raw access.

### G3 — Remaining shared product schemas — partially implemented

The Rust contracts for `EvidenceReference`, `ResultStatus`, exact passthrough
`LogBrief`, bounded `ExpansionRequest`, and benchmark cases/annotations exist.
Freeze and serialize `EventRecord`, `EventBlock`, those product records, and
their version/migration rules. Until G0–G3 are complete, P0 is open.

The dependency direction, V1 scope, bounds, canonical JSON rules, strict
dispatch, migration policy, golden gates, and implementation order are fixed in
[`WIRE_CONTRACT_PLAN.md`](WIRE_CONTRACT_PLAN.md). The serialized schemas and
golden artifacts are not yet implemented.

## Phase sequence after P0

```text
P0 shared contracts
  -> streaming explicit-file/replay ingestion
  -> encrypted TTL snapshot + memory-only mode
  -> lossless framing + passthrough Log Brief [memory-only slice implemented]
  -> end-to-end replay and golden three-layer receipts
  -> local CLI/MCP walking skeleton
  -> costed three-lane candidate union [focused implementation complete]
  -> canonical certified compiler + monotone constrained packer [focused implementation complete]
  -> EvidentrailBench outcome proof
  -> separate LLM-training plan
```

Phase 2 does not start merely because component tests pass. Phase 1 must prove exact authorized expansion after source rotation/deletion, honest `Complete`/`Partial`/`Unknown`, zero unaccounted source records/events, ciphertext-only persistence, and a working one-file product loop.

## Phase 2 objective and evaluation guardrails

Candidate generation is implemented but not yet admitted by outcome. It is evaluated at a frozen vector cap over candidate count, unique underlying bytes, canonical tokens, wall time, and peak memory. Report the full requirement-recall/cost Pareto curve; returning all oversized input fails efficiency.

The runtime packer uses a pairwise event-disjoint atomic packet universe and only production-computable nonnegative affinities in a normalized monotone top-k facility-coverage objective. Provider-attested relations use two distinct-packet half-weight slots; all other facets use one. Required-evidence annotations are evaluation/training data only. Source/service/time breadth facets carry one-quarter weight; pure breadth marginal gain also shares a version-bound one-eighth optional-token slice, dynamically reclassified after each selection. Stronger evidence retains full weight and can use the full remainder. Final evidence recall is gated on oracle-feasible budgets; impossible cases must return `needs_more` rather than fabricate completeness.

No model work begins until deterministic residual analysis shows that learned ranking, rather than acquisition, framing, candidate generation, packing, presentation, or evaluation noise, is the bottleneck. The original Full corpus has no learned-ranker residual. The broader perturbation corpus's two positive-regret witnesses have deterministic counterexamples, and the bounded deterministic challenger fixes the three affected cases in the separate cost-matched >12 stress corpus without a recorded objective, recall, selected-cost, or coverage-charge regression. That challenger is still evaluation-only pending measured resources and non-synthetic evidence. The one pinned paired-reader case produces the same answer under both arms, while a compact deterministic view preserves its answer/citations with fewer bytes. Broader downstream-reader residual evidence is therefore still required before hosted or learned ranking is justified, and custom-model training remains last.
