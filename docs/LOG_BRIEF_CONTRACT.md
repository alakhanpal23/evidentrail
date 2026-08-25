# Log Brief v1 product contract

**Status:** Deterministic passthrough/compiled core, bounded stdin CLI, process-resident MCP expansion, and an injectable authenticated recovered exact-expansion backend implemented; production startup/key authority pending  
**Goal:** The smallest polished output that lets a coding agent act on evidence without mistaking selection for diagnosis or partial acquisition for completeness.

## Product surface

```text
evidentrail setup
evidentrail_logs(question, approved_scope, time_range, budget)
evidentrail_expand(result_id, reference, relation, limit)
```

`evidentrail_logs` returns one structured `LogBriefV1` plus a deterministic text rendering of the same object. `evidentrail_expand` reads only the unexpired result ledger. It never widens scope or requeries a source; refresh/widening is a new `evidentrail_logs` request.

The current Rust core implements exact passthrough, a certified compiled brief,
typed retained `needs_more`, and result-scoped expansion. The memory-only
`evidentrail brief` command accepts one explicit bounded stdin stream and emits the
canonical artifact. `evidentrail serve-mcp` exposes `evidentrail_logs` and `evidentrail_expand`
over bounded newline-delimited JSON-RPC using MCP 2026-07-28 with a 2025-11-25
initialize fallback. `evidentrail_logs` accepts canonical Base64 for caller-supplied
bytes only; successful results remain in at most 32 process-resident sessions
and 64 MiB of aggregate source bytes until the fixed 30-minute expiry, while
`needs_more` retains nothing. The MCP process neither discovers a source nor
preserves expansion after exit.
An opt-in library path can migrate a rendered session into authenticated
ciphertext retention, publish its exact displayed-alias manifest, drop the
original session/product owners, and inject one freshly recovered read-only
backend that advertises only exact `evidentrail_expand`. This path requires the caller
to provide the opened ciphertext root, independently retained provider, and
full expected authority. The default binary remains memory-only because no
production Keychain provider, authenticated expected-context/result catalog, or
configured startup selection exists yet.
`evidentrail setup`, approved-source binding, and the durable service path above
remain intended public surfaces rather than shipped entry points. Optional
signals, contrasts, pattern-census material, and richer next steps remain
contract surface and must not be inferred from the smaller current renderer.

## Two independent states

A single `complete` flag is misleading. The brief exposes:

```text
acquisition_state = Complete | Partial(reasons) | Unknown(reason)
selection_state   = Passthrough | Compiled | NeedsMore(reason)
```

`Passthrough` means every persisted authorized event fits and is shown; it does not upgrade a partial/unknown acquisition. `Compiled` means a budgeted evidence subset is shown with all persisted events still addressable. `NeedsMore` means mandatory evidence/overhead cannot fit, candidate confidence is below the supported envelope, or the requested question/scope cannot be answered honestly from this result.

## Structured shape

```text
LogBriefV1
  contract_version
  result_id
  query_plan_digest
  question_digest                 # question text remains C3 and need not be echoed
  untrusted_data = true
  acquisition_state
  selection_state
  scope
    source kinds and approved logical scope
    exact time/high-water bounds where known
    records and authorized bytes acknowledged
  budget
    requested evidence tokens
    fixed overhead tokens
    selected evidence tokens
    total rendered tokens
    tokenizer and renderer digests
  evidence[]
    packet_reference
    ordered event/block references
    role[]                         # symptom | precursor | change | control | sentinel
    exactness_basis
    exact display bytes/view
    source/stream/time display provenance
    production reason codes[]
    facet affinities and marginal gain
    rendered token cost
    expansion relations[]
  signals[]                        # deterministic facts, never a generated diagnosis
    onset/change facts
    supported incident/reference contrasts
    counts and typed shifts
    cited packet references
    confidence and eligibility reason
  pattern_census_summary           # optional/collapsed unless it adds evidence
  coverage
    FetchCompletion summary/digest
    AcquisitionReceipt counts/digest
    PresentationReceipt counts/digest
    unparsed/fragment/low-confidence counts
    provider and policy warnings
  next_steps[]                     # bounded read-only expansion proposals only
```

No field contains a model-authored paraphrase presented as evidence. Every signal cites retained event/block IDs. Every evidence field carries machine-readable untrusted-data provenance so a host agent cannot treat log text as policy or instruction.

## Deterministic text rendering

The default rendering is intentionally short and stable:

```text
STATUS
  acquisition: PARTIAL — source_byte_cap
  selection:   COMPILED — 1,842 / 2,000 evidence tokens

SCOPE
  local-file · approved member 1/1 · byte high-water known
  acknowledged 18,442 records; persisted 18,442; policy-omitted 0

EVIDENCE
  [E1] precursor · exact typed-ID match · first occurrence
       <exact authorized bytes>
       source … · stream stderr · event evt_… · expand before_after

  [E2] symptom · failure block · correlated with E1
       <complete protected block>
       source … · events evt_… · expand same_lane | same_trace

SIGNALS
  [S1] event family behind E1 begins after deployment boundary [E3]
  [S2] incident/control delta shown with support and denominator [E4]

COVERAGE
  shown 37 · pattern-represented 8,201 · retained raw 10,204
  unparsed 12 · fragments 1 · exactness source=18,442 post-policy=0

NEXT
  expand E1 same_lane ±20 · expand E2 same_trace · new query required to exceed source cap
```

The real renderer uses opaque/sanitized source labels according to policy; the example is structural. Evidence bytes are fenced/escaped as data and cannot alter section structure. IDs may be shortened only with a result-bound collision check; the structured form always carries the full ID.

## Ordering and inclusion rules

1. Render status, scope, and reserved coverage overhead regardless of evidence budget.
2. If the complete authorized result fits, render exact passthrough in source order.
3. Otherwise render mandatory capped typed-ID packets, then the already-selected optional set in deterministic role order: diagnostic/query/change/provider evidence, reconstruction-risk evidence, then pure breadth coverage. Preserve selector acceptance order inside each role class and lane/source order inside each packet.
4. Keep every protected block intact. Never splice lines from different blocks into an apparently contiguous excerpt.
5. Recompute displayed marginal gains against that presentation order and verify their exact sum equals the selected-set objective. Presentation may reorder the chosen set but cannot add, remove, split, or rescore a packet into eligibility.
6. Include a contrast only when reference eligibility, exposure denominator, support, placebo, and completeness rules pass.
7. Keep the pattern census collapsed unless it explains material repetition or selection accounting.
8. End with warnings and bounded expansion proposals, never an autonomous fix command.

Each packet renders canonical closed semantic role codes such as `failure_role`, `provider_attested_graph_relation`, or `time_coverage_stratum`; a raw affinity count is retained only in structured audit data because it is not a useful reading cue.

## Budget accounting

The canonical renderer computes cost with a pinned tokenizer. Scope, status, receipt summaries, references, escaping, and section labels count against total artifact budget. The evidence budget is the remainder after fixed overhead and the bounded mandatory set.

Before returning, Evidentrail performs an exact render → tokenize → verify pass. If formatting crosses budget, it repacks deterministically; it never slices an evidence packet. Byte count is always reported beside token count because tokenizer changes must not erase the physical cost surface.

## Expansion relations in v1

- `exact`: the cited packet exactly;
- `same_lane_before_after`: bounded neighbors in source-member/stream lane order;
- `global_before_after`: bounded acquisition-order neighbors, explicitly labeled;
- `pattern_members`: bounded exact members of one derived group;
- `same_attested_trace`: bounded provider-attested trace/request members;
- `around_onset`: bounded same-source window around a cited onset.

Payload-parsed attacker-controlled correlation IDs may support a nonmandatory search proposal but cannot masquerade as `same_attested_trace`. Every expansion returns its own byte/token cost and updated presentation accounting while preserving the original acquisition receipt.

## Non-goals

- no root-cause paragraph generated by Evidentrail;
- no remediation command;
- no confidence theater such as an unexplained “92% likely” label;
- no implicit refresh, provider call, or scope widening;
- no raw query/path/provider value in ordinary diagnostics;
- no claim that pattern representation is exact evidence expansion;
- no source-exact claim for post-policy content.

## Acceptance cases

The v1 renderer is not complete until golden tests cover:

- fitting exact passthrough with invalid UTF-8, NUL, CRLF, blanks, and duplicates;
- partial acquisition that remains visibly partial in passthrough and compiled modes;
- policy-omitted source record with no EventId but reconciled acquisition receipt;
- complete protected multiline block at the exact budget edge;
- interleaved stdout/stderr with lane-correct block and both neighborhood relations;
- mandatory set over budget returning `NeedsMore` without sliced evidence;
- unsupported reference contrast suppressed under `Partial`/`Unknown`;
- prompt-injection text unable to alter rendering, relations, policy, or tool fields;
- exact deterministic render/token identity on replay;
- expired and forged expansion references failing contentlessly.
