# ADR 0003: Disjoint atomic packets and a normalized monotone packer

**Status:** Accepted  
**Date:** August 24, 2026

## Context

Top-k ranking wastes budget on duplicates. A negative redundancy penalty can make a set objective non-monotone, gold required-evidence labels are unavailable at inference, complementary graph-chain bonuses violate submodularity, and overlapping packets make union-render cost non-additive. Those details invalidate the usual lazy-greedy/knapsack argument and make behavior harder to test.

Unbounded exact-query “must keeps” are also unsafe: broad or adversarial text can consume the entire mandatory budget.

## Decision

V1 selects from pairwise event-disjoint primary atomic packets. All view reasons and affinities are attached to those canonical packet IDs. A protected superpacket may replace its members only if the resulting universe remains a partition. Only syntactically validated typed identifiers may enter the mandatory set, under explicit count and cost caps; ordinary text matches are high-priority affinities.

After reserving fixed brief overhead and mandatory set `M`, optimize:

```text
k(u) = 2 for provider-attested graph relations; 1 otherwise
C_u(S) = sum of the k(u) largest a[i,u] values from distinct packets

G(S) = sum(u) w_u * (C_u(M union S) - C_u(M))
```

All `w_u` and affinities are nonnegative. Packet costs are canonical rendered costs and additive because packets are disjoint. Quality is encoded as capped facets, not an endlessly additive per-packet reward. `G(empty) = 0`; repeated coverage has diminishing marginal gain.

ADR 0005 refines the original top-one rule for provider-attested relations.
Each of their two endpoint slots carries one half of the former full facet
weight; every other facet remains top-one. The closed top-k form preserves
monotonicity and submodularity while preventing one endpoint from erasing the
complementary endpoint's value.

Source/service/time breadth facets carry one quarter of the full diagnostic/reconstruction facet weight. This prevents three breadth coordinates alone from outranking one full-weight diagnostic coordinate while retaining positive monotone coverage gain. After fixed overhead and mandatory cost are reserved, at most one eighth of the optional packet budget may be charged to packets whose positive marginal support at their deterministic acceptance step consists only of those breadth strata. Classification is recomputed after every accepted packet. Any positive validated-identifier, query, failure, onset, typed-change, provider-attested, or reconstruction-risk marginal contribution keeps the packet in the primary optional budget. The best-single challenger uses the same coverage-only limit against the mandatory baseline. The selection and compiled-cost accounting expose both the limit and actual charge; the candidate/compiler config digests bind both denominators.

Use deterministic density greedy compared with the best single fitting packet (`Greedy+Max`) and stable tie-breaking. Lazy evaluation runs only while property tests verify monotonicity and diminishing returns. Any local swap must strictly improve exact `G`. If mandatory content exceeds budget, return `needs_more`.

Selection acceptance order is an optimizer detail, not the reading order. Once the chosen set is frozen, present mandatory packets first and optional packets in three deterministic tiers: diagnostic/query/change/provider, reconstruction risk, then breadth coverage. Preserve acceptance order inside each tier. Recompute packet marginal gains against this presentation order and fail closed unless their checked sum is exactly the selected-set objective. Structured and text output carry canonical unique facet-family roles; text does not substitute an opaque affinity count for those roles.

## Consequences

- Runtime selection uses no evaluation labels.
- Redundancy is controlled by diminishing facet coverage without a negative term.
- Breadth facets remain useful but cannot numerically outrank a full diagnostic facet by dimensionality alone.
- Low-value breadth coverage cannot consume the entire diagnostic budget.
- The chosen set is unchanged by presentation ordering, while diagnostic evidence is read before sentinels and displayed marginal gains remain algebraically exact.
- Budget accounting matches the actual cost model; no unimplemented approximation guarantee is claimed.
- V1 gives up some overlapping bundle flexibility. A future overlapping-packet optimizer must charge exact union-render cost and make no Greedy+Max claim unless its own assumptions are proved.
