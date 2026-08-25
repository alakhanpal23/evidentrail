# Evidentrail competitive teardown and greenfield response

**Observed:** August 24, 2026  
**Purpose:** Freeze the public competitor surface that this workspace must beat without copying or depending on it.  
**Evidence rule:** Public claims are benchmark hypotheses, not accepted facts. Every tested arm is pinned to a release, commit, configuration, prompt, model, and budget.

## What Evidentrail publicly is now

Evidentrail's current documentation says it was last synchronized on August 16,
2026, with a product-status basis of August 12, 2026. The May 2026 launch post
now carries an August editor's note labeling its log-only commands, quotas, and
pricing as historical. Current claims below therefore use the current product,
privacy, CLI, SDK, and OpenAPI pages rather than treating the launch post as the
hosted product contract.

Evidentrail is no longer presented only as Drain-based log templating. Its current public surfaces describe two related products:

1. A log-focused product that turns large line-oriented windows into compact text containing ranked templates, counts, raw line references, and nearby context.
2. A broader action-aware gateway that reduces search, test, build, log, file-tree, and API tool results, records contentless cost/usage metrics, retains omitted data encrypted on the user's machine, and exposes workspace policy.

The strongest public materials are:

- [Evidentrail product site](https://evidentrail.ai/) — action-aware reduction across logs, tests/build/lint, search, file trees, document reads, and other eligible large tool results; local exact retrieval; analytics; and fail-open behavior.
- [Current Evidentrail documentation](https://evidentrail.ai/docs) and [privacy/data-flow page](https://evidentrail.ai/docs/privacy-data-flow) — local proxy and retrieval behavior, transient hosted processing claims, supported action classes, and the seven-day/1-GiB local omitted-content policy.
- [YC company and launch page](https://www.ycombinator.com/companies/evidentrail) — action-aware reduction plus analytics and intended policy/control expansion.
- [legacy-drain repository](https://github.com/evidentrail-megalith/legacy-drain) — deterministic Drain-style grouping, bounded samples, slot summaries, and its reproducible parser benchmark.
- [legacy-drain public parser benchmark](https://github.com/evidentrail-megalith/legacy-drain/blob/master/docs/PUBLIC_BENCHMARKS.md) — 14 Loghub-2.0 systems and explicit grouping/compression/timing results.
- [legacy-drain agent-serving evaluation](https://github.com/evidentrail-megalith/legacy-drain/blob/master/docs/AGENT_SERVING_EVAL.md) — 80 private incidents at 300- and 3,000-line scales, one reader model, and a blind-judge design.
- [Evidentrail SDK repository](https://github.com/evidentrail-megalith/evidentrail-sdk) and [public OpenAPI file](https://github.com/evidentrail-megalith/evidentrail-sdk/blob/main/openapi/evidentrail-v1.openapi.json) — hosted API, action envelopes, bounded retrieval selectors, and the metrics/policy surface.

The currently published OpenAPI document identifies itself as API `0.2.0`.
Its closed action-kind list is `unknown`, `log`, `test_build_lint`, `search`,
`file_list`, `document_read`, `agent_handoff`, `query`, and `verbatim`. A
successful response is either `passthrough` or `reduced`, may contain compact
content, and can return at most 64 bounded `lines`, `json_path`, or `group`
selectors. It also reports reducer byte/token/cost/time usage. These are useful
benchmark-contract facts, not proof that the hosted reducer preserves the
evidence needed by any particular incident.

The current product page separately claims that unknown and ineligible tool
types pass through, errors and quota failures fail open to original bytes,
and omitted content remains encrypted locally for seven days under a 1 GiB
cap. It also says source code, diffs, configuration, and exact structured data
pass through unchanged. Those claims narrow the fair comparison: our exact
passthrough rule, local retention, and failure behavior must be tested against
the same action class and size, not presented as unique based on older Evidentrail
materials.

The current privacy page makes a second boundary explicit: model-provider
traffic stays between the local proxy and the user's provider, but eligible
tool output plus minimum task context is sent to Evidentrail-controlled inference
endpoints for transient reduction. The public API permits the full tool result
up to 32 MiB and optional task/intent/session context. The site says this
content is not retained. That is a public architecture claim, not an
independent audit; it also means an entirely local, no-content-egress product
path is a materially different benchmark/privacy mode and must be labeled as
such rather than silently compared with a hosted run.

The website, SDK README, older OpenAPI contract, and pricing page do not describe exactly the same product or limits. We therefore do not benchmark a timeless brand name. We benchmark immutable artifacts and record the observed surface separately.

The supplied planning spreadsheet contains no direct Evidentrail or log-compression
proposal in its active Ideas tab. Its relevant transferable bets are
`ContextPack` (an auditable minimum evidence bundle), `RepoRetrievalBench`
(local, task-specific retrieval proof), and incident/replay-adjacent competitor
maps. We adopt the first two principles as evidence-linked output and
organization-local evaluation. We do not turn this product into the sheet's
generic context, replay, observability, or autonomous-RCA ideas.

## What is proven publicly, and what is not

| Public evidence | Supported conclusion | Unsupported leap |
| --- | --- | --- |
| `legacy-drain` source and tests | The open engine performs deterministic Drain-style grouping and renders counts, samples, and slot summaries. | It does not prove the behavior of the current hosted action reducer. |
| Loghub-2.0 parser report | The default open grouper matches its Drain3 control on grouping in the reported setup and improves rendered-template accuracy. | Parser accuracy or compression ratio does not prove retained diagnostic sufficiency. |
| 80-case private agent-serving report | At 3,000 scaled lines under its chosen raw cap, `legacy-drain` beat the raw and Drain3 arms for the reported model/judge; at 300 lines it lost to raw. | It does not establish cross-family, cross-organization, cross-model, interactive, or current-hosted-product superiority. |
| Current product/YC pages | Evidentrail claims broader action-aware reduction, local encrypted omitted-data retrieval, analytics, and policy. | The pages alone do not prove completeness, exactness, no-loss accounting, security isolation, or diagnosis outcomes. |
| SDK/OpenAPI `0.2.0` | There is a public action-aware integration with nine action kinds, bounded line/JSON/group selectors, reducer usage accounting, and fail-open guidance. | A changing or mismatched contract is not evidence of stable semantics, selector exactness, or diagnostic sufficiency for every advertised reducer. |
| Current privacy/data-flow docs | Evidentrail says eligible tool output and minimum task context are processed transiently on Evidentrail-controlled endpoints, while omitted exact content remains encrypted locally for bounded selector retrieval. | The page is not an independent confidentiality, deletion, cryptographic, selector-completeness, or no-retention audit. |

The competitor's own published result is especially useful: template compression can outperform a truncated raw prefix when logs are large, yet underperform raw evidence when the window is small enough to fit. That is evidence for a conditional selector and exact passthrough path, not for maximizing compression.

## The method we must build better

Our product is a diagnostic evidence compiler. It wins only if it improves the debugging outcome, not because it emits fewer tokens or has more controls around the same reducer.

| Decision surface | Evidentrail public baseline | Greenfield method |
| --- | --- | --- |
| Primary unit | Public API and open engine are line/template oriented. | Source-defined record plus conservative source-lane atomic block. |
| Objective | Token reduction and compact agent-readable output. | Verified diagnostic requirement coverage and diagnosis success at total episode cost. |
| Small inputs | Public material now documents conservative passthrough for unknown/ineligible actions and failures; its exact size/utility decision boundary is not public. | Exact passthrough whenever the complete authorized result fits, tested as a semantic invariant rather than inferred from an action label. |
| Large inputs | Ranked patterns, samples, and context. | High-recall union of three independent evidence lanes, followed by deterministic constrained set selection. |
| Query conditioning | Public log examples emphasize generic signal ranking. | The debugging question, validated typed identifiers, complete failures, onset/change facts, and trusted provider correlations are first-class facets. |
| Multiline evidence | Not established by the public line-record contract. | Stack traces, compiler failures, exception chains, and assertion diffs are protected before ranking. |
| Omission accounting | Public materials describe seven-day, 1 GiB encrypted local retrieval through line/JSON/group selectors. | `FetchCompletion`, `AcquisitionReceipt`, and `PresentationReceipt` prove three separate loss boundaries, while expansion remains basis-exact and result-scoped. |
| Content path | Current hosted reduction receives eligible tool output plus bounded task context; the local proxy keeps model-provider traffic and omitted exact retrieval local. | The default greenfield path performs authorization, framing, selection, and expansion locally and has no model/network client in the trusted data plane; any future remote reader is separately consented and benchmarked. |
| Exactness | Public line citations and local retrieval. | Every persisted event declares `SourceExact` or `PostPolicy`; policy-omitted content receives no content-derived commitment. |
| Completeness | Not established by a line reference. | Provider/source completeness is explicit `Complete`, nonempty `Partial`, or typed `Unknown`. |
| Selection transparency | Ranked signal is product logic. | Every selected packet exposes reason, production-computable affinity, marginal gain, cost, and forcing constraint. |
| Safety | Gateway policy is an advertised product direction. | Log bytes are structurally untrusted data and can never mutate scope, policy, tools, commands, or query authority. |
| Evaluation | Parser metrics plus a small private single-model diagnosis study. | Public, hermetic, hidden consented, interactive, safety, exactness, and blinded-human tracks with family-held-out splits. |

## Deliberate product boundary

V1 stays narrower than Evidentrail's advertised general tool gateway. It does not attempt generic shell-output rewriting, spend dashboards, agent permissions, autonomous root-cause prose, or fix execution. Those are separate products and would blur the proof obligation.

The shipped loop is:

```text
approved bounded capture
  -> policy-aware authorized ledger
  -> source-lane atomic blocks
  -> three active deterministic evidence lanes
  -> costed disjoint candidate union
  -> monotone constrained evidence packer
  -> deterministic evidence-linked Log Brief
  -> basis-exact local expansion
```

The three active lanes are:

1. lexical relevance plus bounded validated typed identifiers;
2. complete failures plus transparent onset/change facts and raw coverage sentinels;
3. bounded provider-attested correlations.

Drain/n-gram grouping, reference windows, learned anomalies, embeddings, and an LLM ranker are challengers, not dependencies. Each enters only after held-out unique-yield, recall-cost, protected-slice, and incompatible-overmerge gates.

## Mandatory head-to-head benchmark

Every release candidate must compare:

- exact raw passthrough where feasible;
- whole-event raw truncation;
- literal grep plus head/tail;
- quota-hybrid lexical/head/tail/coverage;
- pinned Drain3;
- pinned `legacy-drain` at commit `5a84fb050e074b15474fdb264c9e97faaa66c9f5`;
- a pinned current Evidentrail hosted response when terms and data policy permit it;
- the deterministic greenfield product;
- admitted learned challengers only after deterministic results are frozen.

The comparison sweeps input scale, output budget, evidence position, duplication, invalid encoding, multiline fragmentation, incident family, source family, provider completeness, and adversarial log content. It reports:

- required-evidence recall with jointly sufficient alternatives;
- protected-block recall and incompatible-overmerge rate;
- candidate recall versus count/byte/token/time/memory cost;
- final recall only on oracle-feasible budgets;
- citation correctness and basis-exact expansion;
- provider, authorization, and presentation accounting;
- single-shot diagnosis, complete tool-loop diagnosis, expansions, latency, tokens, and dollars;
- abstention/`needs_more`, unsupported claims, and unauthorized-action attempts;
- macro-family estimates, bootstrap intervals, and paired tests.

No win is declared from compression ratio, parser score, pooled micro-average, one model judge, or one serving cap.

## Falsification conditions

The greenfield method is not better if any of the following remains true after matched evaluation:

- it cannot beat exact passthrough on feasible small windows;
- it cannot beat grep/head/tail or quota-hybrid on family-held-out large windows;
- it improves a component metric without improving diagnosis or total episode cost;
- it loses protected evidence through framing, overmerge, policy handling, or packing;
- its receipts cannot explain every acknowledged and persisted record;
- its advantage disappears when the current Evidentrail hosted arm receives the same input, output, tool-loop, and cost budget;
- gains require gold labels or a hidden model at runtime.

These conditions are intentional. The moat is the measured evidence-outcome system and trust substrate, not the word "compression."
