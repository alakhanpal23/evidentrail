# ADR 0005: Two-endpoint coverage for provider-attested relations

**Status:** Accepted  
**Date:** August 24, 2026

## Context

ADR 0003 used ordinary top-one facility coverage for every production facet.
That suppresses duplicate evidence, but a provider-attested relation is not
established by one endpoint alone. On the frozen six-case governed corpus, the
provider-only and mixed incidents contained every required endpoint in the
proposal universe and each oracle evidence set fit the unchanged render budget.
Nevertheless, selecting one endpoint saturated the shared relation facet and
gave the complementary endpoint exactly zero marginal gain. Both misses were
therefore attributable to the production objective, not acquisition, framing,
candidate recall, rendering, or budget infeasibility.

Adding a complementary pair bonus would make the objective non-submodular and
would weaken the deterministic Greedy+Max contract. Giving each endpoint a
separate unrelated facet would also lose the fact that they attest the same
provider relation.

## Decision

Use closed top-k facility coverage by facet family:

```text
k(u) = 2  when u is a provider-attested graph relation
       1  otherwise

C_u(S) = sum of the k(u) largest affinities a[i,u]
         from distinct packets i in M union S

G(S) = sum(u) w_u * (C_u(S) - C_u(M))
```

Missing slots contribute zero. One packet can occupy at most one slot for a
facet. Provider-relation endpoint weight is exactly one half of the former
full facet weight, so two unit-affinity endpoints retain the prior maximum
total contribution. All other production facet families remain top-one.

The saturation cardinality is a closed property of
`ProductionFacetKindV1`; callers cannot choose it. The candidate, selector,
compiler, benchmark, and external-run identities bind the cardinality,
endpoint weight, and policy versions. Mandatory baselines, marginal scoring,
coverage-only classification, density greedy, best-single, arbitrary-set
evaluation, objective bounds, and diagnostic-first presentation all use the
same cardinality-aware arithmetic.

Admission requires:

- exhaustive monotonicity and diminishing-return checks on small set systems;
- distinct-packet, mandatory-plus-complement, third-endpoint-zero, exact-budget,
  permutation, and presentation-marginal contracts;
- no fixture, label, or budget changes in the governed corpus;
- recovery of both formerly saturated endpoints; and
- no regression in the fixed 200-record product-output contract.

## Consequences

- Provider relations can retain both evidentiary endpoints without a
  non-monotone pair bonus.
- Repeated third and later packets for the same relation still have zero gain
  once the two best slots are occupied.
- The normalized objective remains monotone and submodular because a weighted
  sum of top-k nonnegative modular contributions has diminishing returns.
- The unchanged provider and mixed cases now recover all required evidence;
  this is a corpus result, not a general quality or competitor-win claim.
- Policy-v3 benchmark receipts remain historical pre-fix evidence. Post-fix
  runs must carry a distinct typed policy identity and may not overwrite them.

## Revisit condition

Increase cardinality or add another relation family only when a frozen residual
shows an oracle-feasible miss caused by the current closed objective. Do not
tune cardinality on output size, a single anecdote, or hidden benchmark labels.
Learned ranking remains downstream of this deterministic contract.
