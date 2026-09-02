# Selective hosted ranking release plan

**Status:** implemented behind explicit opt-in; not admitted for production  
**Default:** deterministic, local, no hosted egress  
**Current pinned candidate:** disqualified on latency

## Product decision

Evidentrail will not ask a model whether logs are ambiguous and will not expose
model confidence as evidence. The deterministic compiler owns the escalation
decision. Hosted ranking is useful only when an intact optional block visible
to the model was excluded by deterministic budget packing.

The V1 selective policy is therefore `selection_contended`:

1. Attempt exact passthrough.
2. Prepare the complete deterministic proposal universe.
3. Return every deterministic `needs_more` decision without egress.
4. Produce the deterministic selection.
5. Build the bounded model-visible optional candidate set.
6. Skip egress if fewer than two candidates exist or if every visible
   candidate is already selected.
7. Otherwise make at most one hosted ranking call.
8. Validate one complete ID permutation and apply only the bounded-fourth-
   affinity consumer.
9. Fall back byte-identically on every failure.

This is an opportunity gate, not a correctness or root-cause confidence claim.

### Preferred later refinement

After the stronger bounded deterministic challenger receives real wall/RSS and
quality admission, add a `selector_disagreement` policy: run both deterministic
selectors locally and contact the model only when their selected optional sets
differ. That is a stronger ambiguity signal than budget contention and should
further reduce egress. It is not wired today because the challenger remains
benchmark-only and must not gain production authority indirectly.

## Shipped interfaces

- CLI default: no egress.
- CLI unconditional evaluation: `--llm-rank`.
- CLI selective escalation: `--llm-rank-if-contended`.
- MCP default: `ranking_mode: "deterministic"`.
- MCP unconditional evaluation: `ranking_mode: "hosted"`.
- MCP selective escalation: `ranking_mode: "hosted_if_contended"`.
- Hosted modes remain memory-only and require explicit request-level opt-in.
- Shadow mode always publishes the deterministic bytes.

## Frozen admission work

### 1. Gate conformance

- Prove no call for passthrough, `needs_more`, fewer than two candidates, a
  non-contended visible set, an oversized request, or disabled operation.
- Prove a call is made for a contended visible set.
- Property-test that the gate cannot change mandatory evidence, source bytes,
  citations, expansion targets, budget accounting, or deterministic fallback.
- Keep all gate diagnostics contentless.

### 2. Benchmark arms

On identical randomized cases and the same single model response, compare:

1. deterministic Evidentrail;
2. always-hosted model order;
3. always-hosted reciprocal-rank fusion;
4. always-hosted bounded-fourth affinity;
5. selective-hosted versions of all three consumers.

Add these contentless measurements:

- selective eligibility and actual call rates;
- avoided-call rate versus always-hosted;
- proposal-change rate;
- conditional and overall required-evidence recall delta;
- cases where always-hosted improves recall but selective mode did not call;
- valid-response, fallback, latency, token, and cost distributions;
- verified diagnosis/fix success and protected-slice deltas.

### 3. Selective-policy gates

- 100% byte, citation, ID, budget, expansion, and mandatory-evidence integrity.
- Zero cases where always-hosted improves required-evidence membership but the
  selective gate did not call.
- Overall required-evidence recall non-inferior to always-hosted within one
  percentage point.
- Paired 95% lower confidence bound above zero versus deterministic ranking.
- No protected-slice or verified-diagnosis regression beyond one percentage
  point.
- At least 99% structurally valid responses.
- p95 assisted end-to-end latency below one second under the unchanged 800 ms
  provider deadline and no retry.
- p95 assisted-request cost at or below $0.01.
- Prompt-injection, malformed-byte, duplicate-ID, and foreign-ID tests pass.

### 4. Model and operational qualification

- Replace the current latency-disqualified candidate only through the frozen
  multi-provider bakeoff.
- Freeze model revision, region, prompt, schema, timeout, prices, adapter
  commit, corpus, hardware, and network location before scoring.
- Run the untouched synthetic test set once after the non-scoring pilot passes.
- Re-run the complete freeze before changing any bound item.

### 5. Rollout

1. Internal synthetic shadow mode.
2. Separately approved realistic, non-customer shadow traffic.
3. Explicit opt-in beta only after every gate passes.
4. Keep deterministic operation as the permanent default and fallback.
5. Automatically disable the pinned revision on latency, validity, cost,
   privacy, recall, diagnosis, or protected-slice regression.

## Current blockers

- The current hosted candidate completed valid responses in 1.501–2.236
  seconds, so it fails the production latency requirement.
- No hosted-ranking accuracy improvement has been established.
- The selective arm is not yet included in the frozen live benchmark report.
- No multi-provider winner exists.
- Real/customer/production log egress is not authorized.
- Broad blinded real-incident and downstream agent tool-loop evidence remains
  incomplete.

No production enablement, deadline increase, or scored run is justified until
these blockers are closed.
