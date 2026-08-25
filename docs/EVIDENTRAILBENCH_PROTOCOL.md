# EvidentrailBench protocol for the greenfield evidence compiler

**Status:** Normative evaluation protocol  
**Version:** 0.1 design freeze  
**Date:** August 24, 2026

## Purpose

EvidentrailBench determines whether an implementation helps a coding agent reach a verified debugging outcome under a bounded total episode budget without weakening evidence integrity, privacy, or security.

It is not a compression-ratio leaderboard. Parser quality, evidence selection, single-shot diagnosis, tool-loop behavior, and human debugging are different surfaces and remain separately visible.

## Primary hypothesis

At a preregistered large-window budget, greenfield Evidentrail improves **Verified Diagnosis Success at Total Episode Budget** (`VDS@B`) over raw chronological truncation, bounded grep plus head/tail, provider-native retrieval, and the old Evidentrail method, while all evidence-contract and security gates remain satisfied.

Automatic passthrough must prevent a small-window regression.

## Evaluation unit

The unit is one incident episode, not one line or one template. A case contains:

- immutable source artifacts and source-query provenance;
- the authentic or deliberately authored debugging question;
- approved scope and expected completeness;
- incident and optional reference windows;
- diagnostic requirements expressed as one or more acceptable jointly sufficient event/block alternatives, plus supporting, precursor, symptom, duplicate, distractor, and unsafe-instruction IDs;
- hierarchical root cause, verified impact, verified fix or executable outcome check;
- ambiguity and forbidden/unjustified claims;
- project, organization, provider, format, time, fault, generator, and near-duplicate family keys;
- one immutable split assignment;
- token/time/call budgets and applicable reader configurations;
- consent, retention, redaction, and revocation lineage.

Rows or messages from the same incident are never treated as independent samples.

## Benchmark tracks

### Track A — Contract and adversarial conformance

Committed synthetic cases exercise:

- exact bytes, invalid UTF-8, embedded NULs and empty records;
- multiline stacks, nested causes, compiler/assertion blocks and ambiguous framing;
- malformed JSON/NDJSON/logfmt, mixed streams and schema drift;
- duplicate events, timestamp ties, out-of-order events and rotation;
- severity/service/event-type/stack-signature overmerge challenges;
- high-cardinality identifiers and numeric-looking opaque IDs;
- provider caps, pagination, timeout, cancellation, retention and permissions;
- secrets, declared redactions, PII policy and transformation receipts;
- log-borne prompt injection and tool-shaped content;
- token-budget boundaries, passthrough and exact expansion;
- diagnostic-log no-content canaries.

This track is release blocking and has no probabilistic tolerance for integrity failures.

### Track B — Public reproducible systems

Use pinned, licensed versions with acquisition scripts and checksums:

- LogHub-2.0 for scale, rare-template parsing, drift and runtime;
- LogDx-CI for CI evidence selection and bounded grep-plus-tail comparison;
- RCAEval for repeatable RCA tasks;
- AIOpsLab for live workloads, faults, telemetry and agent interaction;
- realistic dynamic RCA cases for hierarchical cause and resistance to trivial rules.

Each source keeps its own metric surface. Results are not pooled into a misleading universal parser or diagnosis score.

### Track C — Hermetic incident lab

Run controlled local services under reproducible workloads. Each scenario produces:

- healthy reference traffic;
- one or more controlled faults;
- multi-service logs and correlation identifiers;
- distractor errors and background drift;
- known deployment/configuration boundary;
- verified user-facing impact;
- a deterministic fix or rollback validation.

Fault families include deploy regression, configuration, feature flag, schema/migration, dependency failure, resource exhaustion, timeout/latency, retry storm, permissions, rate limit, third-party outage, partial rollout, stale cache and intentionally ambiguous evidence.

Variants from one generator family remain in the same split.

### Track D — Hidden consented incidents

Use independently adjudicated real CI and production incidents stored outside ordinary source control and CI. Before a real-world superiority claim, target at least 50 incidents across five organizations; the stronger product benchmark grows to at least 100 CI and 100 production incidents.

Two annotators label evidence and cause roles, followed by adjudication. Disagreement and legitimate ambiguity remain encoded. Implementation owners should not access hidden labels where practical.

### Track E — Blinded developer study

Use a balanced crossover study comparing provider/raw workflows with Evidentrail. Measure time to first correct hypothesis, time to verified diagnosis, incorrect pivots, expansion/requery behavior, confidence calibration, unsupported claims and trust in the three-layer coverage bundle. Determine sample size by power analysis from a pilot, not an arbitrary participant count.

## Splits and leakage prevention

Split only after exact and near-duplicate grouping. Hold out entire:

- organizations and projects;
- services and repositories;
- provider and format families;
- versions and time buckets;
- fault and generator families;
- incident/trace lineages;
- normalized pattern/template families when relevant.

No line, template variant, generator seed sibling, or lightly modified incident may cross a family boundary. Record all split keys in `corpus_manifest_v1` and fail materialization when related artifacts disagree.

## Release-core and scheduled methods

Every release comparison includes the methods that define the practical product boundary:

1. exact passthrough when fitting;
2. raw chronological truncation;
3. a pinned bounded hybrid that reserves independent quotas for validated-ID/lexical retrieval, head, tail, and coverage sentinels before filling remaining budget;
4. provider-native query/MCP output;
5. BM25F over raw blocks plus typed fields;
6. greenfield deterministic Evidentrail;
7. oracle required-evidence packet as an upper bound.

Every public freeze and every competitive claim also includes pinned Drain3,
`legacy-drain`, and—when its terms and the case data policy permit—the current
hosted Evidentrail product. The hosted arm is pinned by observed API/CLI version,
contract digest, workspace policy, reducer decision, response, latency, and
price schedule because Evidentrail's public product now extends beyond the open
Drain implementation. If a hosted version cannot be pinned or replayed, report
it as a dated observed-service arm rather than implying reproducibility.

Scheduled extended runs add dense retrieval using a pinned off-the-shelf
encoder, a Drain pattern inventory, a generic LLM summary, LLMLingua-style
prompt compression, and a Log-Insight-like neuro-symbolic selector. These
expensive research arms run on every public freeze and preregistered private
claim, but need not consume every routine private regression run.

No Evidentrail competitor implementation is linked into the product. The benchmark
captures each executable/container/API digest, configuration, raw output, and
adapter normalization. Selection-only comparisons share one frozen
acquisition; end-to-end comparisons report acquisition differences separately
so provider pushdown cannot masquerade as selector quality. The detailed
competitor evidence and falsification conditions live in
[`EVIDENTRAIL_COMPETITIVE_TEARDOWN.md`](EVIDENTRAIL_COMPETITIVE_TEARDOWN.md).

## Four evaluation surfaces

### 1. Contract and component surface

Measure:

- exact mutation count and expansion identity;
- provider completion, source-record authorization, and persisted-event presentation reconciliation;
- multiline/block integrity;
- incompatible overmerge and harmless fragmentation;
- template-level macro metrics and rare-event recall;
- candidate required-evidence recall before ranking at frozen vector caps over candidate count, unique member bytes, canonical candidate tokens, wall time, and peak memory;
- final required-evidence recall at each budget;
- redundancy, lane/source/time coverage and selected token cost;
- deterministic replay;
- latency, peak memory and throughput at 10K, 100K and 1M records.

Every measured artifact pins the canonical renderer, tokenizer, renderer/tokenizer/config digests, fixed receipt/reference overhead, and exact byte/token accounting. Development, public test, and hidden test report separate OOD axes for organization/project, provider/format, time/version, and fault/generator family rather than one pooled “unseen” label. Hidden cases and access credentials rotate under rate limits; public leaderboards cannot query private labels or receive per-case optimization feedback.

### Costed requirement coverage

One flat list of “required IDs” is insufficient when multiple evidence packets can establish the same fact. For diagnostic requirement `r`, annotations provide one or more acceptable jointly sufficient alternatives `A[r,j]`, each a set of event/block IDs. With `members(C)` expanding candidate blocks to their unique raw members:

```text
cover(r, C) = 1 iff there exists j such that A[r,j] is a subset of members(C)
R_case(C)   = sum(r) w_r * cover(r, C) / sum(r) w_r
R_macro(K)  = mean_family(mean_case(R_case(C_K)))
```

Candidate set `C_K` must satisfy the preregistered vector cap `K = (candidate_count, unique_member_bytes, canonical_candidate_tokens, wall_time, peak_memory)`. Wrapping all input in one candidate therefore still pays for every unique underlying member. Any non-passthrough method returning all over-cap input fails candidate efficiency regardless of recall. Report the entire `R_macro(K)` Pareto curve, lane-unique yield, and leave-one-lane-out recall loss.

For final-artifact budget `B`, a case is oracle-feasible only if at least one alternative for every mandatory requirement plus fixed brief, receipt, and reference overhead fits under the pinned renderer and tokenizer. Evidence recall at `B` is reported on feasible cases. An infeasible case must return `needs_more` and is evaluated on calibrated uncertainty and useful bounded expansion, not forced into an impossible recall target. The complete tool-loop episode is still charged on the outcome surface.

### 2. Fixed single-shot surface

Give each frozen reader the same question, code/change context and one method's artifact at the same declared budget. Measure verified diagnosis, cause granularity, evidence citations, grounding, unsupported claims, abstention calibration, input/output tokens, latency and cost.

### 3. Tool-loop episode surface

Allow exact expansion and other approved debugging tools. Count the full episode:

- initial artifact;
- every expansion/requery and returned byte/token count;
- agent input/output tokens attributable to the episode;
- provider/tool calls;
- wall-clock latency and compute cost;
- final diagnosis/fix outcome;
- whether an omitted clue caused a wrong path.

An agent recovering after multiple broad reads does not make the initial artifact free or successful.

### 4. Human surface

Use the blinded study described above. Human trust never replaces integrity tests, and automated metrics never replace verified task outcomes.

## North-star outcome

`VDS@B = 1` only when all applicable requirements hold:

1. the diagnosis identifies the verified cause at the useful benchmark granularity;
2. the answer cites supporting source evidence correctly;
3. no disqualifying unsupported causal claim is present;
4. an executable known-fix check passes when the case provides one;
5. the episode remains within the preregistered total budget `B`.

`B` is a vector reported transparently: total context tokens, output tokens, calls, latency, compute cost and optional human time. Do not hide tradeoffs behind one weighted cost scalar.

Use multiple frozen readers/agents and multiple budgets. Report a Pareto frontier over:

- verified diagnosis success;
- total tokens/calls/time/cost;
- required-evidence recall and citation grounding;
- confident-wrong, privacy and security failures.

## Statistical protocol

- Preregister datasets, splits, methods, configurations, budgets, readers, primary hypotheses and exclusion rules before the final hidden run.
- Use paired case-level comparisons because every method runs the same cases.
- Report case-level bootstrap 95% confidence intervals, stratified by benchmark source where appropriate.
- For binary paired success, also report the paired difference and a paired exact/permutation or McNemar-style test as preregistered.
- Correct secondary multiple comparisons or label them exploratory.
- Report macro results by case/family plus every important worst slice; do not rely on line-weighted micro averages.
- Publish effect sizes and raw case-level public-track results, not only p-values.
- Never tune thresholds, prompts or budgets on the private test set.
- Treat LLM judges as analysis aids only. Executable outcomes or blinded experts determine release claims.

## Release gates

### Absolute trust gates

- zero unmarked evidence mutations;
- exact authorized expansion for every valid reference;
- zero unaccounted acknowledged source records and zero unaccounted persisted events;
- correct `Complete`, `Partial`, and `Unknown` acquisition states;
- zero known incompatible overmerges in the adversarial suite;
- complete protected blocks;
- zero raw/query/path/provider canary leakage through diagnostics, telemetry, reports or ordinary CI;
- zero Evidentrail-owned log-derived command/tool execution, binding or policy mutation, provider-scope widening, executable/argv/environment/path construction, content egress, or implicit requery.

### Evidence gates

- at the frozen candidate cap `K`, the case/family bootstrap 95% lower confidence bound for `R_macro(K)` meets preregistered `R0`; `R0`, protected-slice floors, and hard p95/p99 resource caps are fixed after a powered pilot and before the hidden run;
- final required-evidence recall meets its preregistered lower-confidence-bound threshold on oracle-feasible cases at each supported budget;
- oracle-infeasible cases return `needs_more` with calibrated uncertainty and a bounded expansion route;
- exact passthrough with no task regression when the bounded input fits;
- rare, unparsed, low-confidence and cross-provider slices reported separately.

### Outcome gates

- the paired, family-macro `VDS@B` improvement over raw chronological truncation exceeds a preregistered minimally important absolute effect at the large-window budget; derive and freeze that effect from product economics plus a powered pilot before the hidden run, and require its family-stratified 95% lower confidence bound to remain above zero;
- a statistically supported Pareto improvement over bounded grep plus tail and provider-native retrieval in at least one valuable operating region, with no safety regression;
- the fraction of supported episodes requiring another broad fetch because Evidentrail omitted required evidence remains below a preregistered operational ceiling fixed from the same pilot before the hidden run;
- no hidden-test or worst-slice collapse that invalidates the supported-product claim.

These thresholds define a supported operating envelope; they do not claim that unknowable provider-side missing records can be recovered.

### Safety claim boundary

The Evidentrail-owned invariant above is absolute and release-blocking: evidence bytes never gain authority inside Evidentrail, the ranker emits only result-local IDs, bounded scores, typed roles, and uncertainty, and expansion is read-only and result-scoped.

Downstream agent behavior is an empirical, version-scoped integration result. Every evidence field carries machine-readable untrusted-data provenance. For each supported pinned agent, prompt, tool set, and authorization policy, report adaptive-injection attack success with a confidence interval, benign-task success/overblock, and read-only expansion success. Destructive or privileged actions require confirmation or corroboration independent of log text. Untested hosts receive no “safe agent” claim, and zero observed attacks is reported only as a suite result.

## Run provenance

Every run persists content-appropriate provenance:

- benchmark and manifest revisions;
- public artifact checksums or opaque governed private-case IDs;
- code revision and dirty-state hash;
- build profile, target and dependency lock digest;
- method configuration and random seeds;
- reader/model identifier, version, decoding configuration and prompt hash;
- machine/OS/runtime information;
- per-case timing, output identity and score;
- consent and redaction-policy versions where applicable.

Private content, questions, citations, labels and outputs remain in the governed result store. Ordinary reports use opaque case IDs and aggregates.

## Gate before model evaluation begins

The future proprietary ranker cannot enter EvidentrailBench until deterministic candidate generation reaches the candidate-recall gate and residual analysis shows ranking is the bottleneck. Its only acceptable product claim is movement of the hidden `VDS@B` Pareto frontier without an integrity, safety, latency or worst-slice regression. Ranking NDCG, anomaly F1 or compression ratio alone cannot release a model.
