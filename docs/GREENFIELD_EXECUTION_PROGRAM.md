# Greenfield Evidentrail evidence-product execution program

**Date:** August 24, 2026
**Status:** Canonical engineering program for the deterministic product phase
**Boundary:** The old Evidentrail implementation and `legacy-drain` are external benchmark arms only. The new product has no runtime or architectural dependency on them.

## The engineering decision

We are not rebuilding a better template compressor. We are building a **diagnostic evidence compiler**.

It is not log-template compression, a generic observability backend, a log replay system, autonomous RCA/remediation, or a wrapper around the old Evidentrail. Those boundaries are architectural, not positioning language.

It accepts a bounded log acquisition plus a debugging question and compiles a compact trustworthy evidence set that lets a coding agent reach a verified diagnosis. It preserves exact source bytes when authorized, accounts for every acknowledged record even when policy omits its content, exposes uncertainty, and supports basis-exact expansion of retained evidence. Compression is a consequence of evidence selection, not the objective.

The optimization target is:

```text
maximize verified diagnosis success at total episode budget

subject to:
  exact evidence identity
  complete accounting of received and not-received records
  bounded read-only acquisition
  intact diagnostic blocks
  deterministic expansion
  explicit uncertainty
  no tool authority for log-derived content
```

The customer-facing surface stays deliberately small:

```text
evidentrail setup
evidentrail_logs(question, scope, time_range, budget)
evidentrail_expand(result_id, reference, relation)
```

The default output is one versioned Log Brief containing scope, basis-exact evidence, transparent onset/change facts, the three-layer coverage bundle, and expansion handles. Reference contrasts, pattern census, anomaly scores, embeddings, and model-written diagnosis are absent unless an evaluation-only challenger is explicitly enabled; they are never implied by an ordinary v1 result.

## The polished v1 we actually ship

The research space is broad; the first product is not. V1 has one linear customer experience and three active evidence lanes:

```text
bounded read-only capture
  -> policy-aware authorization + immutable authorized-basis ledger
  -> conservative source-lane blocks
  -> union of:
       1. lexical + validated typed identifiers
       2. complete failures + onset/change + raw coverage sentinels
       3. provider-attested bounded correlations
  -> disjoint monotone evidence packing
  -> one deterministic Log Brief + exact expansion
```

Exact structured event keys and conservative token-shape fingerprints may annotate those packets. Drain/n-gram proposals, reference-window contrasts, learned anomalies, embeddings, and an LLM ranker remain feature-gated experiments until each passes the applicable admission gate in the canonical matrix. The default product does not expose parser knobs, algorithms, or model prompts.

## Why this is a different, testable bet than current Evidentrail

The current public Evidentrail must not be reduced to a template parser. As documented in [`EVIDENTRAIL_COMPETITIVE_TEARDOWN.md`](EVIDENTRAIL_COMPETITIVE_TEARDOWN.md), the public surface now advertises action-aware reduction across tool outputs, local encrypted retrieval of omitted content, analytics, and workspace policy. Separately, the public `legacy-drain` repository exposes deterministic Drain-style grouping and rendering. Those are related but non-equivalent benchmark targets: the hosted service and pinned open engine must never be reported as one arm.

The public `legacy-drain` agent-serving evaluation is also directionally important: its reported reducer lost to raw at a 300-line scale and beat the truncated raw arm at 3,000 lines under that study's model, cap, and private cases. That does not establish a general quality curve or current hosted-service performance, but it falsifies an unconditional “compression is always better” rule. V1 therefore bypasses reduction whenever the complete authorized result fits and tests reduction only where context is genuinely constrained.

| Public Evidentrail/legacy-drain baseline | Greenfield evidence compiler |
| --- | --- |
| Hosted product advertises broad action-aware tool-output reduction, analytics, local encrypted retrieval, and policy | Deliberately narrow read-only diagnostic evidence compilation for bounded logs |
| Open `legacy-drain` is line/template oriented; public parser results attribute default grouping to Drain3 and gains to rendering | Authorized retained event and intact source-aware evidence block are the units; no runtime Drain dependency |
| Reduction remains available at small inputs | Exact passthrough is mandatory whenever the complete authorized result fits |
| Token reduction and compact agent-readable output are prominent | Verified diagnosis at total episode budget is the objective |
| Ranked patterns, samples, and context shape large-window output | Exactly three deterministic evidence lanes feed a costed disjoint monotone packer |
| Public materials describe local encrypted retrieval and policy surfaces | Fetch, authorization, and presentation receipts separately account for not-received, policy-omitted, retained, shown, and unshown records |
| Current hosted behavior and the open engine are not proven identical | Each is pinned and evaluated as a separate arm, with terms/data-policy constraints recorded |
| Gateway policy is an advertised direction | Evidence bytes have no scope, policy, command, query, egress, or tool authority |
| Public parser and private single-reader studies provide useful hypotheses | Public, hermetic, hidden-consented, interactive, safety, exactness, and human tracks determine our claims |

## Research synthesis turned into one method

No single published method solves the product objective. The source-by-source evidence, limitations, and decisions are recorded in [`RESEARCH_LEDGER.md`](RESEARCH_LEDGER.md), which is a systematic relevant-source ledger rather than a claim of literally exhaustive paper coverage. The implementation combines only the parts that survive the product-level evidence test:

- Drain, Spell, Logram, PIPLUP, and learned parsers demonstrate alternative ways to propose structural groups; Loghub-2.0 and corrected ground truths show scale, rare-template, and label-instability risk. Therefore v1 permits only exact provider event keys and conservative token-shape annotations. Parser-derived candidate lanes are evaluation-only challengers.
- LogReducer, LogBlock, Denum, LogShrink, DeLog, and LogPrism demonstrate storage redundancy, not diagnosis-preserving omission. Therefore specialized codecs are rejected from the v1 evidence path; validated types and provider-attested correlations are used directly, without adopting a compression objective.
- DeepLog, LogAnomaly, LogBERT, LogFormer, BARO, and Onion show that sequence, change, and contrast signals can surface candidates but do not establish cause. Therefore only transparent bounded onset/change facts ship inside the failure/raw-coverage lane. Learned anomaly, sequence-surprise, and reference-window lanes remain challengers.
- RECOMP, LLMLingua-2, and budgeted submodular summarization show the value of downstream-utility training and set selection. Therefore Evidentrail selects intact evidence blocks for marginal diagnostic utility rather than deleting tokens.
- LogDx-CI and LogSieve show that simple bounded reducers remain serious CI baselines and that reduction must be evaluated downstream. Their public scope is too small and concentrated to set product truth, so total episode cost includes every expansion and requery and hidden-family evaluation remains mandatory.
- Log-Insight supports symbolic-before-neural evidence preparation, but its small single-organization incident study and unavailable production artifact do not justify shipping its sampling, fixed thresholds, or reference-skew lane. V1 keeps the pipeline shape and evaluates its extra mechanisms as challengers.
- Evidence-grounding studies show that answer quality can appear stable while citations degrade sharply. Therefore source identity, grounding, and expansion are separate release gates.
- LogJack supplies early, preprint evidence that log text can carry indirect prompt injection. The empirical evidence is not broad enough for universal attack-rate claims, but the low-regret architectural response is clear: every retained log byte is untrusted data and no evidence-stage component can invoke tools.

## Canonical method-admission matrix

This matrix is the implementation boundary. “Evaluation-only challenger” means code may exist only behind a non-default benchmark feature, cannot affect ordinary v1 output, and has no compatibility promise. “Rejected” means excluded from the diagnostic evidence compiler; an external baseline adapter or a later, independently justified storage project does not change that status.

Admission gates use the following exact rules:

- **T — trust gate:** zero receipt/accounting violations, zero unmarked mutation, basis-exact expansion for every retained event, complete protected blocks, zero Evidentrail-owned log-derived authority, and deterministic recomputation for deterministic methods.
- **U — incremental-utility gate:** on preregistered family-held-out splits at frozen cap `K`, hierarchical paired-bootstrap 95% lower confidence bounds for both lane-unique required-evidence yield and leave-one-lane-out `R_macro(K)` loss are greater than zero; final evidence recall and Verified Diagnosis Success meet preregistered non-inferiority floors; the challenger gives a statistically supported Pareto improvement in at least one preregistered operating region; no protected slice falls below its frozen floor; and p95/p99 resource caps pass.
- **G — grouping gate:** `T + U`, plus zero known incompatible overmerges in the adversarial suite, full member accounting, windowed pattern versions, and no selection credit from proposer agreement alone.
- **R — reference gate:** `T + U`, plus pre-content reference eligibility, preregistered placebo and multi-control sensitivity bounds, stable sign/rank under eligible controls, and no missing-event claim when acquisition is `Partial` or `Unknown`.
- **M — learned-method gate:** the applicable gate above, plus project/organization/time/provider/fault-family isolation, frozen training data and labels, pinned weights/tokenizer/prompt, calibration and repeated-run variance reporting, privacy/licensing/deletion approval, and LogJack-style adaptive-injection tests. A learned method remains additive and ID-emitting only.

For challenger `m`, all gold use is offline. `R_macro` is required-evidence-alternative recall macro-averaged across held-out fault families. At the same frozen candidate-cost vector `K`, define `Y_m(K)` as the family-macro fraction of required-evidence alternatives contributed by `m` that are absent from frozen v1 candidates, and define `Delta_m(K) = R_macro(C_v1_union_m(K)) - R_macro(C_v1(K))`. The `U` gate resamples families first and paired cases within family; its 95% lower confidence bounds must be greater than zero for both `Y_m(K)` and `Delta_m(K)`, not just their means. The full candidate-count/unique-byte/canonical-token/wall-time/peak-memory Pareto curve is still reported; a favorable scalar at one hidden-tuned cap cannot admit a method.

`X1` is the challenger phase after the deterministic Wave 2 baseline freezes; challengers are measured in Wave 4 and cannot enter the default path before admission. `X2` begins only after the separate LLM-training boundary is satisfied. `P1` is a post-MVP project with its own charter.

| Method family | Status | Why | Exact admission gate | Code phase |
| --- | --- | --- | --- | --- |
| Policy sink, authorized ledger, exactness bases, three receipts | **Active v1** | Establishes what Evidentrail received, was allowed to retain, transformed, omitted, and can expand | `T`; all receipt equations reconcile under crash/cancel/partial cases | W0–W1 |
| Source-aware atomic block reconstruction | **Active v1** | Prevents stack traces, assertion diffs, and compiler failures from being split | `T`; golden framing fixtures pass; ambiguous cases keep conservative alternatives; caps cannot absorb adjacent events | W1–W2 |
| Reversible deterministic preprocessing for active-lane features | **Active v1** | Typed extraction and bounded normalization help retrieval without mutating evidence | `T`; every feature maps to retained-basis offsets; mask/unmask metamorphic tests pass; opaque fallback and intact protected blocks are preserved; no new lane is created | W1–W2 |
| Exact provider event keys and conservative token-shape annotations only | **Active v1** | Useful deterministic metadata without granting grouping omission power | `T`; annotation failure cannot change candidate membership, mandatory status, or retained bytes | W2 |
| Evidence lane 1 — lexical relevance + syntactically validated typed identifiers | **Active v1** | Cheap, question-directed retrieval with explicit caps | `T`; active-v1 `R_macro(K) >= R0`; typed-ID false-mandatory and protected-slice floors pass | W2 |
| Evidence lane 2 — complete failures + transparent onset/change + raw-coverage sentinels | **Active v1** | Preserves complete failure blocks and blind-spot coverage without learned causality | `T`; active-v1 `R_macro(K) >= R0`; complete-block, onset-boundary, strata-coverage, and partial-acquisition tests pass | W2 |
| Evidence lane 3 — provider-attested bounded correlations | **Active v1** | Connects symptoms and precursors using provenance-bearing relations | `T`; namespace/hop/degree/cost caps pass; payload IDs never create mandatory edges; clock-order tests pass | W2 |
| Feasible small-window exact passthrough | **Active v1** | The complete authorized result dominates reduction when it already fits | `T`; passthrough is always selected when the complete authorized bounded result fits and matches the complete-authorized-input task outcome | W1–W2 |
| Disjoint monotone top-k facility packer, deterministic brief, exact expansion | **Active v1** | Selects complementary intact evidence under an auditable budget; provider relations retain two endpoints and all other facets one | `T`; normalization/monotonicity/diminishing-return/property tests pass; exact-small-instance regret reported; no approximation claim beyond implemented algorithm | W2 |
| Structural taint/authority separation and read-only expansion | **Active v1** | LogJack/CaMeL motivate an enforceable boundary stronger than prompt filtering | `T`; encoded/fragmented/multiline/cross-event injection suite has zero Evidentrail-owned authority path | W0–W3 |
| Evaluation infrastructure — Loghub-2.0/corrections, LogDx-CI, RCAEval, AIOpsLab tracks | **Active v1** | Separates parsing, CI, injected RCA, interactive, and hidden-real evidence instead of using one proxy score | Pinned versions/checksums; project/family/system splits; gold unavailable at runtime; per-track/worst-slice reports; no pooled release score | W1–W4 |
| Evaluation infrastructure — ALCE/RAGChecker grounding, Lost-in-the-Middle position tests, LogJack attacks | **Active v1** | Tests citation, utilization, position, and hostile-input failures independently | Stable evidence IDs; citation correctness/completeness; order/distractor sweeps; adaptive-injection intervals; deterministic labels remain primary | W1–W4 |
| Separate benchmark arms — pinned current Evidentrail hosted service and pinned `legacy-drain` | **Active v1** | Public hosted claims are broader than the open grouper and cannot be inferred from it | Separate version/commit/config/model/budget/provenance; matched inputs and costs; hosted arm only when terms/data policy permit; never pool or substitute the arms | W1–W4 |
| Drain, Spell, Logram, PIPLUP, and other non-neural groupers | **Evaluation-only challenger** | Parsing metrics do not prove diagnostic evidence utility and overmerge is destructive | `G` independently for each proposer; agreement between proposers gives no validation credit | X1/W4 |
| LILAC, DivLog, LogBatcher, LibreLog, UNLEASH, LUNAR, MicLog | **Evaluation-only challenger** | Potential grouping gains carry model, cache, privacy, drift, and reproducibility costs | `G + M` independently for each pinned implementation | X2/W4 |
| Onion/Log-Insight-style reference and group-skew selection | **Evaluation-only challenger** | Contrast may add unique evidence, but reference choice and current production evidence are weak | `R`; Log-Insight-like fixed thresholds and destructive sampling are not inherited | X1/W4 |
| DeepLog, LogAnomaly, LogBERT, LogFormer, BARO ranker | **Evaluation-only challenger** | Novelty/change can propose evidence but is not causality; public/injected scope is limited | `U`; `M` for learned methods; BARO's transparent primitive may be studied separately from its ranker | X1 or X2/W4 |
| LoFI, LogSieve classifier, RECOMP-style extractive ranker | **Evaluation-only challenger** | Task-aware selection is promising, but current labels/domains do not prove complete incident evidence | `U + M`; selected units remain intact blocks and the ranker emits only IDs, scores, roles, uncertainty | X2/W4 |
| Trusted-evidence mutation — LLMLingua token deletion, RECOMP abstraction, uncited neural summaries | **Rejected** | Can mutate machine evidence and break exact expansion; useful only as external baselines or cited convenience text | No admission path for protected/trusted blocks; a synopsis must be secondary, cited, and unable to alter selection | W1/W4 baseline adapter only |
| V1 evidence-path use of LogReducer, LogBlock, Denum, LogShrink, DeLog, LogPrism archive codecs | **Rejected** | Compression ratio is not diagnostic sufficiency and newer artifacts have reproducibility gaps | No evidence-lane admission from compression results; any `P1` archive project requires basis-exact round trip, corruption isolation, version compatibility, and random-access proof | P1 only |
| Old Evidentrail and `legacy-drain` runtime reuse | **Rejected** | Would make the product a wrapper around the prior implementation or open grouping engine | No runtime admission; subprocess baseline only, with no shared parsing/grouping code | W1/W4 baseline adapter only |
| Generic observability backend, continuous log store, dashboard, replay system | **Rejected** | Expands scope without improving the bounded evidence contract | No admission under this program; requires a separate product charter | Never |
| Autonomous RCA/remediation or log-derived tool execution | **Rejected** | Conflates evidence with diagnosis/authority and violates the security boundary | No admission; Evidentrail remains read-only evidence infrastructure | Never |
| Prompt filtering as the security boundary | **Rejected** | Filters are bypassable and cannot confer authority safety | No admission as a boundary; only structural taint/capability separation can satisfy `T` | Never |

### Evidence-strength boundary

- Parsing papers mostly optimize template metrics; corrected labels and Loghub-2.0 demonstrate that those metrics are unstable and incomplete proxies for diagnosis.
- Storage papers establish lossless compression behavior, not safe evidence omission. DeLog and LogPrism remain preprint-level evidence, and LogPrism lacks a verified usable artifact in the ledger.
- Public diagnosis/reduction evidence remains narrow: LogDx-CI currently documents 35 cases, LogSieve focuses on open-source Android CI, and Log-Insight reports 11 incidents from one organization. These motivate challengers and benchmarks, not default architecture.
- Anomaly/RCA studies frequently use a small number of public systems or injected faults. Their scores are proposals, not causal labels or proof of production generalization.
- The submodular guarantee applies only to the cited objective and algorithm. V1's `Greedy+Max` is an inspectable baseline and receives no `1-1/e` claim unless the proven algorithm and assumptions are actually implemented.
- LogJack is a useful adversarial suite, not a complete threat model or proven defense. Evidentrail's no-authority invariant is architectural; downstream-host safety remains version-scoped empirical evidence.

## The greenfield algorithm: Evidence Compilation Pipeline

### Stage 1 — Bounded source capture

Turn the question and an approved repository-to-service binding into a read-only acquisition plan. The plan contains exact source identity, environment, service/resource, time interval, safe provider filters, row/byte/time/token caps, pagination state, and expected completeness.

Only exact scope filters may be pushed down unconditionally. V1 evaluates lexical/error terms only after the bounded acquisition reaches the policy sink; anomaly and semantic provider queries are disabled challengers. If a future admitted method issues a parallel candidate query, that query is separately receipted and can never replace the complete bounded acquisition path. This prevents a routine deployment event, a successful control request, or a missing expected event from disappearing before evaluation.

At acquisition time, an adapter emits the exact bounded source bytes and provenance as `RawEnvelope` values in bounded process memory. A policy-aware ledger sink is their sole downstream consumer. For every acknowledged envelope, the sink atomically records exactly one outcome:

- `SourceExact`: persist payload and terminator byte-for-byte;
- `PostPolicy`: persist the output of a versioned deterministic transformation plus its `TransformationReceipt`; or
- `OmittedByPolicy`: persist the policy identity and accounting fact, but no payload.

No parser, grouper, ranker, renderer, diagnostic logger, or model may observe an envelope before this decision. Each envelope has a result-local `SourceRecordId` derived from acquisition identity and source position, never from payload content. An envelope is acknowledged only after its chosen outcome is durable, or retained in explicitly selected memory-only mode. Provider credentials and transport authorization are out-of-band and never enter an envelope; credential-looking bytes returned inside a log record are content and follow the same explicit policy decision. Expansion must not depend on a file still existing, a container still running, or provider retention still containing the event.

### Stage 2 — Immutable authorized-basis ledger

The resulting **authorized ledger** is immutable. Every persisted event receives:

- deterministic result-local event ID;
- authorized content hash over the retained exactness basis, computed only after the policy decision;
- source/provider identity and cursor or file position;
- source and ingestion timestamps where available;
- stream identity such as stdout/stderr;
- service, resource, environment, severity, logger, event name;
- trace, span, request, session, deployment, and host/container identifiers;
- structured fields in their original typed representation;
- parse/redaction status and confidence;
- `exactness_basis = SourceExact | PostPolicy { policy_digest, transformation_receipt_id }`.

IDs and content hashes commit only to the authorized persisted basis. If policy forbids retaining source content or even a content-derived commitment, Evidentrail retains neither the original bytes nor their hash. “Exact expansion” always means exact relative to the declared basis; only `SourceExact` may claim source-byte expansion. Normalized text, display views, parsed fields, templates, embeddings, and model features are derived objects referencing ledger IDs. Invalid UTF-8 remains valid evidence. Duplicate authorized payloads remain distinct events while sharing the same content hash.

The policy sink produces an `AcquisitionReceipt` over `SourceRecordId`:

```text
envelopes_acknowledged = source_exact + post_policy + omitted_by_policy
```

`SourceExact` and `PostPolicy` entries point to persisted `EventId` values and exactness bases. `OmittedByPolicy` entries point only to a policy identity because no content-derived event is retained. A separate `PresentationReceipt` assigns every persisted event exactly one of `ShownVerbatim`, `PatternRepresented`, or `RetainedRaw`; `PatternRepresented` remains zero in ordinary v1 until a grouping method is admitted. Provider-side records that were never received appear only in `FetchCompletion`. These three layers must never be collapsed into one receipt.

### Stage 3 — Atomic block reconstruction

Construct evidence blocks before ranking:

- provider-native structured events remain atomic;
- stack traces, exception chains, compiler failures, assertion diffs, and test failures are reconstructed with bounded state machines;
- a block records every member line/event ID and reconstruction confidence;
- membership is contiguous in one `(source_member, stream)` lane's sequence, while global acquisition order remains a separate ordering view; interleaved stdout cannot split a valid stderr stack;
- ambiguous input keeps both the conservative line view and the proposed block view;
- maximum lines, bytes, and inter-line time prevent a malformed event from absorbing a window.

The packer may never split a protected block. This matters more than saving a few tokens.

### Stage 4 — Exactly three active evidence lanes

The active views operate over the same immutable IDs and are not a serial implementation order. The default execution DAG is:

```text
authorized ledger
  -> atomic blocks + typed extraction
  |    -> exact structured-key/token-shape annotations
  |    -> complete failure/onset/raw-coverage candidates
  -> lexical + validated typed-ID candidates
  -> provider-attested bounded-correlation candidates
  -> deduplicated costed candidate union
```

No active lane depends on a parser group, reference window, embedding, learned anomaly score, or LLM. A failure in one lane cannot delete an event from another. Exact keys and token-shape fingerprints are annotations only: they cannot create mandatory status, suppress a candidate, or alter retained content.

1. **Lexical and validated typed-identifier lane**
   - exact IDs, error strings, paths, endpoints, codes, symbols, and alert text;
   - BM25-style lexical relevance over blocks and structured fields;
   - only syntactically validated typed identifiers are mandatory, under explicit count and token caps; free-text or full-query matches are high-priority affinities, never unbounded must-keeps.

2. **Complete-failure, onset/change, and raw-coverage lane**
   - complete ERROR/FATAL/crash/assertion/compiler/exception blocks;
   - first and last occurrence, count, affected service/resource, and correlated IDs;
   - severity is useful but never sufficient by itself.
   - first bounded occurrence, last available pre-onset evidence, bursts, deploys, migrations, restarts, configuration and feature-flag events;
   - transparent count/rate and validated typed-value changes only; no learned sequence score, reference contrast, or causal label;
   - bounded head/tail plus time/source/service strata, unparsed and low-reconstruction-confidence blocks, and provider-native hits as raw-coverage sentinels;
   - missing-expected-event claims are not emitted.

3. **Provider-attested bounded-correlation lane**
   - distinguish provider-attested correlation IDs from payload-parsed attacker-controlled IDs, and namespace every node by retrieval, tenant, and source;
   - create typed edges for trace/request/session IDs, host/container/deployment identity, provider-attested parent/child ordering, and tight temporal adjacency;
   - cap hub degree, hops, and emitted members; payload-parsed IDs cannot create mandatory edges;
   - expand from a visible symptom toward precursors with a bounded graph walk;
   - never treat temporal proximity alone as causality or order events across unsynchronized clocks without an attested ordering fact.

Candidate generation takes the union of these three lanes. Each lane emits intact candidate packets whose costs include all unique underlying member bytes and canonical rendered tokens. The preregistered cap is a vector over candidate count, unique member bytes, canonical candidate tokens, wall time, and peak memory. Candidate recall is measured as a recall-versus-cost Pareto curve before scoring, so a good ranker cannot hide destructive retrieval and an “all events in one block” candidate cannot game the gate.

Grouping, reference-window contrast, sequence/anomaly, embedding, and learned-ranker implementations live only in the challenger harness described by the admission matrix. They do not run, allocate resources, change the brief, or contribute facets in ordinary v1.

### Stage 5 — Annotation-only structure and grouping challengers

Do not import the old Evidentrail grouping path. Implement only the annotation routes needed by v1:

- exact structured event keys when the provider supplies them;
- conservative token-shape fingerprints with typed variable boundaries.

These annotations can aid display, debugging, and challenger measurement, but cannot affect candidate membership, mandatory status, or packer facets. An online prefix/tree proposal inspired by Drain, an n-gram/anchor proposal inspired by Logram, and other grouping methods remain disabled experiments until each passes `G` in the canonical admission matrix. Agreement between two proposers is not validation.

Structured records with explicit event names use a separate exact-key path. Proposals are accepted only after a compatibility validator passes:

- same source/service/resource partition;
- compatible severity class;
- same logger or explicit event type when present;
- same exception class and normalized stack signature;
- no structured-event/free-text cross-merge;
- sufficient static-anchor coverage;
- consistent variable boundaries and value types;
- opaque identifiers never summarized as numeric measurements;
- no member violates the derived exact template.

When a challenger proposal disagrees or confidence is low, split. Fragmentation costs tokens; incompatible overmerge destroys evidence. Pattern versions are windowed so drift creates a new version instead of silently rewriting historical meaning.

Every challenger group retains full member IDs, exact counts, first/last timestamps, typed summaries, representatives, and a grouping explanation. Patterns are derived evaluation objects, never a substitute for the ledger or an active-v1 selection feature.

### Stage 6 — Deterministic block scoring

Before a proprietary model exists, compute inspectable features:

- exact/lexical question relevance;
- bounded validated-identifier mandatory status;
- failure-block and visible precursor-context priority;
- onset/change-boundary strength;
- provider-attested graph distance to query/alert entities;
- raw-coverage source/time/service strata;
- source and reconstruction confidence;
- nonnegative affinity to production-computable evidence facets;
- rendered token cost.

Use calibrated deterministic rules and small linear combinations selected on training folds, never hidden-test tuning. No learned model runs in v1. A later admitted model must produce only the same semantic outputs—required-evidence probability, precursor/symptom role, relevance, and uncertainty—without changing the ledger, candidate contracts, packer, or authority boundary.

### Stage 7 — Constrained evidence-set optimization

Do not return an unbudgeted fixed-count top-k packet list. Gold required-evidence labels exist only in training and evaluation; they are forbidden from the runtime objective. Reserve the fixed scope/receipt space and deterministic mandatory packet set `M` first. If `cost(M) > B`, return `needs_more`.

V1 canonicalizes all three-lane reasons onto a pairwise event-disjoint universe of intact primary atomic packets. Packet `i` has additive rendered cost `c_i`; no event can be charged twice. Let `U` contain only production-computable active-lane facets: validated query identifiers and terms, failure/onset roles, source/service/time raw-coverage strata, validated typed changes, provider-attested bounded graph relations, and reconstruction-risk coverage. Group, reference, anomaly, embedding, and model-derived facets are forbidden until their method family is admitted. Packet affinity `a[i,u]` is in `[0,1]`, and all facet weights are nonnegative. Let `k(u)=2` only for a provider-attested graph relation and `k(u)=1` for every other facet. `C_u(A)` is the sum of the `k(u)` largest affinities for facet `u` from distinct packets in `A`, with missing slots equal to zero. Select the remainder with the normalized gain:

```text
G(S) = sum(u in U) w_u * (C_u(M union S) - C_u(M))

subject to:
  all w_u are nonnegative
  sum(i in S) c_i <= B - cost(M)
  sum(i accepted with coverage-only marginal gain) c_i
    <= floor((B - cost(M)) / 8)
  protected blocks are not split
  candidate packets are pairwise event-disjoint
```

`G(empty) = 0`; the top-k facility-coverage objective is monotone and submodular, and repeated evidence has little marginal gain without negative pairwise penalties or endlessly additive “quality” rewards. Provider-relation endpoints each carry one half of the former full facet weight, so two unit-affinity endpoints preserve its prior maximum while a third has zero gain. One packet cannot occupy both slots. Encode quality as capped facets. Source/service/time breadth facets carry one quarter of the full diagnostic/reconstruction facet weight, so three independent breadth dimensions cannot by themselves outrank one full-weight diagnostic dimension. At each deterministic greedy step, a packet is “coverage-only” only when every positive marginal contribution remaining after the current selection is a source, service, or time stratum. Such packets share one eighth of the optional packet budget; validated identifiers, query/failure/onset, typed change, provider-attested, and reconstruction-risk marginal gain retain access to the full remainder. The best-single challenger is checked against the same slice from the mandatory baseline, so it cannot bypass the constraint. Both the slice limit and actual charged cost remain in structured accounting. The versioned candidate/compiler config digests bind the saturation cardinalities, provider endpoint weight, breadth weight, and budget denominators. See [`ADR 0005`](adr/0005-provider-relation-top-two-coverage.md).

A complementary graph chain must be resolved into a disjoint protected superpacket before selection or handled as a hard preselection rule; do not add a chain-completion bonus. Compare deterministic density-greedy with the best single fitting packet (`Greedy+Max`) using stable ties. Lazy evaluation remains enabled only while property tests verify monotonicity and diminishing returns. Local swaps may run only when exact `G` strictly improves. If a future version permits overlapping packets or exact union-render costs, it must use an optimizer valid for that cost function and make no `Greedy+Max` approximation claim. After the set is frozen, present mandatory packets first and optional packets by diagnostic/change/provider, reconstruction-risk, then breadth role, retaining selection order inside a role tier. Recompute per-packet marginal gains in presentation order and require their sum to equal exact `G(S)`. Render the closed canonical role codes rather than an opaque affinity count. Report affinity, presentation-consistent marginal gain, cost, forcing constraint, and coverage-only budget accounting for every selected plan.

If the complete authorized bounded result fits, bypass the optimizer and return exact passthrough. If mandatory evidence cannot fit or coverage uncertainty is high, return `needs_more` with a bounded expansion proposal; widening acquisition is a separate policy-checked query and is never implicit.

### Stage 8 — Deterministic Log Brief and exact expansion

Render according to [`LOG_BRIEF_CONTRACT.md`](LOG_BRIEF_CONTRACT.md): status and scope first, then strongest evidence, transparent onset/change facts, raw-coverage sentinels, provider-attested correlations, and the `FetchCompletion`/`AcquisitionReceipt`/`PresentationReceipt` coverage bundle. Reference contrasts, anomaly scores, pattern census, and neural summaries are absent from the default brief. Every displayed claim maps to event IDs. Expansion operates on the local snapshot and can return:

- an exact block;
- before/after neighbors;
- same trace/request/session;
- same service around onset;
- the retained payload at its declared exactness basis and provenance.

An explicitly enabled challenger may attach a separately labeled evaluation annex, but it cannot rewrite the default evidence section, receipts, status, or expansion targets.

Evidentrail supplies evidence. The coding agent performs diagnosis using code, configuration, git, tests, and other tools.

## Local and internal logs are a first-class product path

Local logs are not one adapter. They are the fastest product-development loop and the most privacy-sensitive surface.

### Supported local acquisition order

1. exact file snapshots and explicit globs;
2. stdin and child process stdout/stderr with separate stream provenance;
3. JSONL/NDJSON and free-form text;
4. rotated files; compressed sources stay disabled until a versioned derived-exact transformation chain is specified and tested;
5. Docker and Docker Compose;
6. CI artifact directories;
7. later: journald and macOS unified-log presets.

### Local-source rules

- Never crawl a home directory or auto-enroll discovered logs.
- Discovery is metadata-only: path, size, format guess, recency, rotation, and permission status.
- The user explicitly approves every root, glob, command, container, or OS preset.
- Resolve symlinks and enforce the approved root after canonicalization.
- Snapshot the bounded window before parsing; record file identity, offsets, modification time, and rotation state.
- Preserve stdout/stderr and arrival ordering separately.
- Mark truncated reads, decompression failures, racing writes, and permission gaps as partial.
- Store authorized retained result snapshots locally with restrictive permissions, short TTL, authenticated encryption, crash-safe cleanup, and an OS-keychain-managed key. `OmittedByPolicy` records retain only their allowed accounting facts.
- Evidentrail's own operational logs contain only query-plan metadata, counts, timings, versions, receipt hashes, and errors—never customer log bytes.
- Product telemetry consent, raw-content retention consent, and training consent are separate controls.

### How local logs enter development and evaluation

Use four distinct tiers:

1. **Synthetic contract fixtures:** committed, deterministic cases for exactness, multiline, overmerge, rotation, invalid UTF-8, prompt injection, secrets, and caps.
2. **Hermetic incident lab:** Docker/Compose services with controlled faults, known impact, exact root cause, and verified fixes. This produces realistic multi-service local logs without customer data.
3. **Public datasets:** versioned external corpora for parsing, CI diagnosis, RCA, drift, and scale.
4. **Opt-in dogfood/partner incidents:** local-only by default; benchmark or training use requires separate explicit consent and redaction review.

Personal application logs, Codex conversation/history databases, IDE logs, and arbitrary machine logs must never silently become benchmark or training data.

## Greenfield repository shape

Keep the architecture small enough to finish:

```text
evidentrail/
  crates/
    evidentrail-schema/     versioned query, event, receipt, brief, expansion, bench types
    evidentrail-core/       immutable ledger, blocks, receipt validation, expansion
    evidentrail-ingest/     lossless framing, local adapters, query/cap semantics
    evidentrail-evidence/   blocks, three active lanes, scorer, packer, brief; challengers feature-gated
    evidentrail-store/      encrypted TTL result snapshots and policy boundary
    evidentrail-cli/        setup, bindings, local commands, MCP tools
    evidentrail-bench/      cases, annotations, baselines, runners, metrics
  fixtures/
    contract/         safe committed golden cases
    incident-lab/     hermetic known-fault scenarios
  docs/
```

Do not split further until profiling or ownership requires it. Provider adapters implement one trait inside `evidentrail-ingest` at first; move them only if the crate becomes unwieldy.

## Dependency-aware parallel execution

### Wave 0 — Freeze contracts

One short serial decision sets the interfaces all parallel work uses:

- event and block IDs;
- exact raw/post-policy payload boundary;
- query/acquisition plan and completeness reasons;
- source adapter trait;
- block membership and the schema for optional challenger pattern membership;
- source-record authorization and persisted-event presentation receipts;
- Log Brief schema;
- benchmark case and annotation schema.

**Exit:** golden serialization tests and a written versioning rule.

### Wave 1 — Four parallel foundations

**Workstream A: ledger and trust contract**

- immutable authorized-basis ledger, hashes, event/block references;
- exact expansion and passthrough;
- acquisition and presentation dispositions with separately reconciled receipts;
- partial/not-retrieved reasons.

**Workstream B: local ingestion**

- file/stdin/child process input;
- multiline reconstruction and unparsed records;
- caps, cancellation, and rotation handling;
- source conformance tests.

**Workstream C: benchmark foundation**

- case/annotation manifests and split keys;
- exact passthrough, whole-event raw truncation, grep-plus-tail, quota-hybrid, and pinned Drain3 baselines;
- pinned `legacy-drain` subprocess and a separately pinned current hosted-Evidentrail arm when terms and data policy permit; never infer one from the other;
- integrity, accounting, security, and local-log fixtures;
- case-level bootstrap and machine-readable result schema.

**Workstream D: local store and policy**

- encrypted TTL snapshot store;
- keychain/key abstraction, permissions, deletion and crash recovery;
- separate telemetry/content/training consent;
- no-content operational audit events.

**Wave 1 exit:** every persisted event expands exactly relative to its declared authorization basis from a local snapshot; every acknowledged envelope reconciles to `SourceExact`, `PostPolicy`, or `OmittedByPolicy`; all presentation and fetch categories reconcile; baselines run on committed fixtures.

### Wave 2 — Four parallel evidence-engine workstreams

**Workstream E: blocks and annotation-only structure**

- atomic block state machines;
- validated typed extraction, exact provider event keys, and token-shape annotations;
- grouping challenger interface and overmerge suite, with all challengers disabled by default.

**Workstream F: active evidence lanes 1 and 2**

- lexical index and validated typed query entities;
- complete failure blocks, transparent bounded onset/change facts, and raw-coverage sentinels;
- no learned model.

**Workstream G: active evidence lane 3**

- provider-attested, namespaced correlation entities and edges;
- bounded neighborhood expansion and chain-closure candidates;
- adversarial high-cardinality and payload-ID non-authority tests.

**Workstream H: packer and renderer**

- mandatory evidence policy;
- deterministic monotone top-k facility-coverage selection using `Greedy+Max`, with optional swaps only on strict exact-objective improvement;
- disjoint-member budget accounting, deterministic default Log Brief, passthrough and uncertainty states;
- no group/reference/anomaly/embedding/model facet in the v1 objective.

**Wave 2 exit:** the three active lanes pass costed candidate-recall and leave-one-lane-out tests; oracle-feasible final-recall, determinism, protected-block, trust, and exact budget-accounting gates pass. Challenger interfaces are inert in the default build and cannot alter golden briefs.

### Wave 3 — Product loop and production sources

Parallel workstreams can implement:

- `evidentrail setup`, repository bindings, and policy UX;
- two MCP tools and versioned schema;
- Docker/Compose and CI artifacts;
- Kubernetes and CloudWatch adapters behind the same conformance tests;
- the hermetic incident lab and tool-using evaluation runner.

**Exit:** a developer connects one local or production source, asks one ordinary question, receives a trustworthy Log Brief, expands any reference, and completes a debugging episode without provider syntax.

### Wave 4 — Real outcome proof

- freeze EvidentrailBench v1 before tuning claims;
- independently annotate consented real incidents;
- run single-shot, tool-loop, adversarial, and blinded human comparisons;
- report the Pareto frontier against exact passthrough, raw truncation, grep/tail, quota-hybrid, provider-native retrieval, BM25, dense retrieval, pinned Drain3, pinned `legacy-drain`, the separately pinned hosted Evidentrail arm when permitted, generic summaries, prompt compression, and oracle evidence;
- fix worst-slice failures instead of averaging them away.

**Exit:** statistically supported improvement in Verified Diagnosis Success at Total Episode Budget, with no trust or security regression.

### Challenger phases — earn complexity after the baseline freezes

**X1, after Wave 2 exit:** non-learned grouping, reference, and deterministic anomaly/change challengers may be implemented only behind benchmark-only features. Each runs independently against the frozen three-lane v1 and is eligible for Wave 4 admission testing under `G`, `R`, or `U`.

**X2, after the LLM-training boundary:** learned parsers, anomaly models, selectors, embeddings, and rankers may enter the same harness under `M`. They remain shadow/evaluation-only until admitted; no model changes source authorization, block boundaries, mandatory evidence, tool authority, or exact expansion.

**P1, separate post-MVP charter:** specialized lossless archive codecs may be studied behind the ledger API. Compression ratio alone can never admit a codec into evidence selection.

## Engineering gates

### Contract gates

- zero unmarked evidence mutation;
- basis-exact authorized retained expansion, including invalid UTF-8; only `SourceExact` may claim source-byte expansion;
- zero unaccounted acknowledged source records and zero unaccounted persisted events;
- provider filters/caps/timeouts/permissions are separate from local dispositions;
- deterministic IDs, references, receipts, and render order for fixed inputs;
- exact passthrough is selected whenever the complete authorized bounded input fits; the reducer is bypassed and no reduction-induced task regression is permitted.

### Evidence gates

- candidate recall is evaluated only at a frozen vector cap `K`, charges unique underlying members, and reports its full recall-cost Pareto curve;
- the family-macro bootstrap lower confidence bound at `K` meets a preregistered `R0`, fixed after a powered pilot and before the hidden run, with hard p95/p99 resource caps and no protected-slice collapse;
- final required-evidence recall meets its preregistered threshold on oracle-feasible cases at the declared total artifact budget; infeasible cases must correctly return `needs_more`;
- zero known incompatible overmerges in the adversarial release suite;
- complete protected blocks;
- report rare/unparsed/low-confidence slices separately.

These gates qualify the active v1 system; they do not silently admit new lanes. Every challenger additionally satisfies its named `U`, `G`, `R`, or `M` gate from the canonical matrix against the frozen active baseline. A challenger that merely correlates with an active proposer, raises a parser metric, or improves compression ratio remains evaluation-only.

### Product-outcome gates

- the paired family-macro lower confidence bound exceeds a preregistered minimally important improvement over raw chronological truncation at the frozen large-window budget; freeze that margin after a powered pilot and before the hidden run;
- statistically supported Pareto improvement over bounded grep plus tail and provider-native retrieval in at least one valuable operating region;
- at every feasible small-window operating point, exact passthrough is selected and matches the complete-authorized-input task outcome; compact rendering cannot replace it merely to save tokens;
- the broad-refetch rate caused by omitted required evidence stays below a preregistered operational ceiling, frozen after the pilot and before the hidden run;
- Evidentrail itself performs zero log-derived command/tool execution, scope widening, policy mutation, content egress, or implicit requery;
- each supported host-agent integration reports a version-scoped adaptive-injection attack-success interval and benign-task/overblock rate; zero observed attacks is not described as a universal guarantee.

## What not to build yet

- no dashboard;
- no new log store or continuous ingestion platform;
- no generic observability backend or replay system;
- no wrapper, fork, or runtime adapter around old Evidentrail or `legacy-drain`;
- no autonomous RCA or diagnosis engine;
- no automatic remediation;
- no broad connector catalog;
- no remote per-line model calls;
- no generic tool-output compression;
- no large proprietary model;
- no training on personal/local/customer logs by default.

These are product exclusions, not a backlog implied by this plan. Generic observability, replay, autonomous RCA/remediation, and old-Evidentrail reuse require separate charters; they are not future stages of the diagnostic evidence compiler.

## Boundary before LLM-training planning begins

Do not let model work shape the evidence contract prematurely. Start the separate LLM-training program only when all of these are true:

1. schema and event/block IDs are versioned and stable;
2. exact expansion and receipt gates pass;
3. deterministic and cheap retrieval baselines are implemented, and candidate retrieval passes a preregistered costed-recall gate;
4. EvidentrailBench has frozen public, hermetic, adversarial, and hidden-real tracks;
5. deterministic error analysis identifies ranking failures a model can plausibly fix;
6. consented labels include required evidence, precursor/symptom roles, omissions, expansions, verified diagnosis, and fix outcome;
7. train/validation/test splits hold out projects, organizations, time periods, providers, and fault families;
8. privacy, deletion, licensing, and customer-owned training paths are explicit.

At that point, the model plan can optimize a real marginal-utility target and be judged by whether it moves the whole debugging Pareto frontier. Until then, a proprietary LLM is an expensive source of ambiguity rather than an edge.

## The product sentence

> **The greenfield Evidentrail compiles bounded local, CI, and production logs into a compact auditable evidence set that preserves the correct debugging outcome—then exposes every loss boundary and expands each retained event exactly relative to its declared authorization basis.**
