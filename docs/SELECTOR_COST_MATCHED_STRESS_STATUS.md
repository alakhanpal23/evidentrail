# Cost-matched selector stress status

Status: evaluation-only. This synthetic conformance corpus does not change the
production selector and does not support a population, approximation-factor,
latency, peak-RSS, or general-quality claim.

## Frozen protocol

The public stage contains eight hand-authored problems across seven structural
families. Every problem has more than 12 optional packets. It freezes the
production selection before accepting any hidden requirement, then restricts
the order-aware beam and exact oracle to:

- no more than the production plan's selected packet cost; and
- no more than the production plan's actual coverage-only token charge.

The beam retains its closed width 64, depth 64, 131,072-transition, and
129-state-slot bounds. The structured exact oracle admits only additive
saturation-safe problems and uses dual-resource dynamic programming with a
48-optional-packet, 65,536-state, and 1,000,000-transition cap. Non-additive or
oversized problems produce typed ineligible outcomes.

Type staging keeps annotations out of public generation, but is not external
temporal/process attestation.

## Frozen observations

| Case | Optional packets | Exact DP | Production → challenger gain | Selected cost | Coverage charge | Governed recall |
|---|---:|---|---:|---:|---:|---:|
| Primary density trap | 15 | exact | 850,000 → 1,200,000 | 10 = 10 | 0 = 0 | 0/1 → 1/1 |
| Primary balanced | 16 | exact | 3,440,000 = 3,440,000 | 8 = 8 | 0 = 0 | 1/1 = 1/1 |
| Coverage density trap | 15 | exact | 850,000 → 1,200,000 | 10 = 10 | 10 = 10 | 0/1 → 1/1 |
| Mixed dual resource | 16 | exact | 1,400,000 → 1,880,000 | 18 = 18 | 2 = 2 | 0/1 → 1/1 |
| Provider pairs | 14 | exact | 3,500,000,000,000 = 3,500,000,000,000 | 7 = 7 | 0 = 0 | 1/1 = 1/1 |
| Mandatory baseline | 14 | exact | 2,590,000 = 2,590,000 | 8 = 8 | 0 = 0 | 1/1 = 1/1 |
| Provider third endpoint | 15 | non-additive saturation | 1,000,000,000,000 = 1,000,000,000,000 | 2 = 2 | 0 = 0 | 1/1 = 1/1 |
| Exact packet cap | 65 | optional-packet cap | 3,975,000 = 3,975,000 | 10 = 10 | 0 = 0 | 1/1 = 1/1 |

Across this frozen corpus, the challenger is objective-better in three cases
and equal in five, with identical selected cost and coverage-only charge in all
eight. Governed recall is better in the same three cases, equal in five, and
worse in none. In every one of the six eligible cases, the beam result matches
the structured exact optimum's objective, selected cost, and governed recall
under the frozen resource envelope. No beam work cap was reached.

This is weak dominance only on the recorded deterministic axes for these eight
synthetic cases. Production admission remains blocked pending governed
large/unstructured evidence plus separately measured wall-time and peak-RSS
receipts under an exact executable/environment binding.
