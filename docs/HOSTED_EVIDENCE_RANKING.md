# Hosted evidence ranking beta

Hosted evidence ranking is an explicit, default-off application-layer option.
The deterministic compiler remains the source of framing, candidates,
mandatory evidence, budget accounting, citations, exact rendering, receipts,
and expansion targets.

## Request boundary

The product first attempts exact passthrough and computes the complete
deterministic selection. A passthrough result or any `needs_more` decision
returns without calling a ranker. For an eligible compiled result, the request
contains the escaped question and at most 32 intact optional blocks. Each field
is labeled as `ascii_byte_escape_v1` and untrusted data. The combined escaped
question and block payload is capped at 40 KiB before the ranker is called;
larger eligible compilations use the deterministic result without egress.

The model receives no tools or conversation history. The OpenAI beta adapter
uses the Responses API, strict JSON Schema, `reasoning.effort: none`,
`store: false`, a 512-token output cap, and an 800 ms request deadline. The
model and endpoint are compile-time constants. The only credential source is
`OPENAI_API_KEY`; no provider or model override is public.

The provider envelope is capped at 64 KiB and must report `completed` with
exactly one `output_text`, no refusal, error, or incomplete details. HTTP 408
and 504 are timeouts; all status and parsing failures use closed contentless
failure codes. The configuration digest binds the actual prompt, model,
endpoint, limits, request settings, and frozen pricing inputs so configuration
drift is observable. Estimated cost is operational telemetry, not provider
billing authority, and pricing must be re-frozen before an admission run.

## Accepted response

Exactly this schema is accepted:

```json
{"schema_version":1,"ranked_block_ids":["B7","B2","B9"]}
```

The list must be a complete permutation of the submitted aliases. Unknown,
duplicate, missing, malformed, oversized, or foreign IDs invalidate the whole
proposal. Model text never becomes evidence, a citation, policy, or a
completeness decision.

## Selection and fallback

The current beta consumes the model order as a bounded fourth optional signal.
It can break close candidate comparisons but adds no more than 1% to a
candidate's existing positive marginal gain. It cannot make a zero-gain packet
eligible, prioritize a mandatory packet, alter the breadth quota, split a
packet, exceed the budget, or change bytes and expansion targets. Model-order
The frozen benchmark additionally evaluates direct model-order budget packing
and reciprocal-rank-fusion budget packing. Those two evaluation-only consumers
preserve mandatory membership, positive marginal-gain eligibility, the
coverage-only diversity quota, packet indivisibility, certified costs, exact
bytes, and expansion targets. The public CLI/MCP beta continues to use only the
bounded-fourth-affinity consumer.

There is no retry. Disabled operation, missing credentials, timeouts, rate
limits, policy denials, provider failures, invalid output, and assisted-selector
failure immediately return the already computed deterministic result.

### Deterministic selective escalation

`hosted_if_contended` is the preferred explicit opt-in policy. It is evaluated
only after exact passthrough, complete proposal preparation, deterministic
budget feasibility, and deterministic selection. The model is contacted only
when the at-most-32 model-visible optional candidates include at least one
packet excluded from the deterministic selection. This is the smallest honest
condition under which reordering could improve optional evidence membership.

The gate does not call logs “nondeterministic,” estimate correctness, infer a
root cause, or interpret model confidence. If fewer than two optional
candidates exist, or every model-visible optional candidate is already
selected, the product emits a contentless `not_sent` diagnostic with
`insufficient_optional_candidates` or `selection_not_contended`. Explicit
egress consent is still required on every request; this mode is never an
automatic default.

Diagnostics contain only provider/configuration digests, elapsed time, token
counts, estimated cost, validation/fallback codes, and a digest of accepted
block IDs. Prompts, responses, credentials, provider request IDs, raw IDs, and
source bytes are not retained or logged. The CLI emits this allowlisted record
to stderr; MCP includes it as an optional `hosted_ranking` output object.

## Surfaces and release status

- CLI: `evidentrail brief ... --llm-rank` (memory retention only)
- CLI selective escalation: `--llm-rank-if-contended` (preferred beta mode)
- MCP memory mode: `evidentrail_logs` with `ranking_mode: "hosted"` or
  `"hosted_if_contended"`; omitted means `deterministic`
  (authenticated/durable retention remains deterministic)
- Kill switch: `EVIDENTRAIL_HOSTED_RANKING_DISABLED=1`
- Internal shadow switch: `EVIDENTRAIL_HOSTED_RANKING_SHADOW=1` together with
  explicit hosted opt-in; the call and validation run, but deterministic bytes
  are always published and diagnostics report whether the proposal differed

The checked-in OpenAI model is a beta candidate, not a benchmark winner. The
project owner has approved only the synthetic/non-sensitive OpenAI test scope
recorded in
[`HOSTED_RANKING_TEST_AUTHORIZATION.md`](HOSTED_RANKING_TEST_AUTHORIZATION.md).
The multi-vendor frozen benchmark, approval for every other provider or data
class, organizational privacy review, shadow run, and every
quality/latency/validity/cost gate remain required before any production
admission or model/configuration change.

The current model/configuration is not eligible for rollout: the approved
synthetic pilot timed out on all 18 calls at 800 ms, while the separate
three-call measurement-only characterization returned valid rankings at
1.501–2.236 seconds end-to-end. Selective escalation reduces unnecessary
egress; it does not repair that latency failure or establish an accuracy gain.
The repeated `live-ranking-measure` stage removes that censoring from the
evaluation: it uses a 15-second safety ceiling across the complete 18-call
pilot and reports the legacy one-second SLO as an observation, never as a
condition for collecting quality evidence or as production admission.

Before beta admission, the frozen benchmark must add the selective-escalation
arm and report its eligible-call rate, avoided-call rate, false-negative
opportunities, conditional and overall required-evidence recall deltas,
proposal-change rate, downstream verified diagnosis, latency, and cost. A
qualified pinned model, untouched synthetic results, approved realistic shadow
traffic, and separately authorized real-log egress remain mandatory.

## Frozen synthetic live qualification

`evidentrail-hosted-ranking-bench` is an evaluation-only staged runner. It owns
one persistent ranking HTTP client for the complete process. Each frozen case
is compiled deterministically and with hosted assistance from identical bytes,
candidate order is deterministically randomized on every repetition, and the
one validated response is replayed in memory to all three consumers. Neither
requests, responses, questions, logs, rendered evidence, nor raw block IDs are
serialized. Output contains only digests, codes, counts, timing/token/cost
measurements, integrity booleans, and aggregate outcomes.

The `pilot` phase makes 18 ranking calls (six cases, three repeats), is
non-scoring, and never starts the scored corpus. `qualify` runs that same pilot
first and stops immediately unless integrity, adversarial, validity, latency,
and cost gates pass. Only then does it open the untouched lineage-separated
24-case scored corpus (72 ranking calls). Scored diagnosis evaluation uses a
separate persistent single-shot hosted reader for the deterministic arm and
the three assisted arms; these reader calls are evaluation overhead and are
reported separately from assisted-request latency and cost.

The freeze is:

| Bound item | Frozen value |
| --- | --- |
| Ranking and reader model | `gpt-5.6-luna` |
| Provider API | OpenAI Responses, `store:false`, no tools/history, reasoning `none`, strict JSON Schema |
| Ranking deadline | 800 ms; no retries |
| Outcome-reader deadline | 5 seconds; no retries; evaluation only |
| Ranking price inputs | $0.20/M input tokens; $1.20/M output tokens |
| Corpus | generated synthetic-only pilot 6 and scored 24; lineage-separated |
| Repetitions | 3 per case with a different deterministic candidate permutation |
| Evidence budget | 4,000 compiled render units per arm |
| Structural validity | at least 99% |
| Assisted end-to-end latency | p95 strictly below 1 second |
| Assisted request cost | p95 at or below $0.01 |
| Recall | paired 95% bootstrap lower bound strictly above zero |
| Protected slice and verified diagnosis | no regression beyond one percentage point |
| Phase spend guards | $1 pilot; $10 scored; current worst-case guards are $0.18 and $3.60 |

### Non-qualifying latency characterization

When the 800 ms pilot returns only timeouts, `characterize` makes exactly three
calls against one approved synthetic case through one persistent client. It
uses the same pinned model, request schema, prompt, candidate randomization,
three ranking consumers, shadow comparison, and contentless report contract,
but a five-second measurement-only request timeout. Its configuration digest
is deliberately distinct. The report always sets `qualification_eligible` and
`qualification_passed` to `false`, so it cannot weaken or replace the production
deadline. The guarded maximum is $0.03 (three calls at $0.01 each).

```sh
target/release/evidentrail-hosted-ranking-bench characterize > /tmp/evidentrail-hosted-characterization.json
```

This answers only whether successful responses arrive below 800 ms, between
800 ms and one second, between one and two seconds, between two and five
seconds, or still fail at five seconds. Exit status `0` means all three calls
returned structurally valid rankings; it is not a qualification pass.

### Repeated ranking measurement

The measurement-only v2 path exercises all six pilot families, three candidate
permutations per case, and all three deterministic consumers through one
persistent client. Its 15-second request ceiling prevents hung calls; it is not
a latency target. The command exits successfully only when validity, integrity,
adversarial, and cost checks pass. The report still records whether the legacy
one-second SLO would have passed, while `qualification_passed` remains false.

```sh
scripts/production-qualification.sh live-ranking-measure
```

Use its p50/p95/p99 distribution to declare an interactive or asynchronous
product SLO before changing the production adapter. Do not infer a production
timeout from one best-case request.

Every scored arm must pass byte, citation/expansion, ID, mandatory-evidence,
and budget integrity. Malformed response, duplicate ID, foreign ID,
prompt-injection, duplicate-record, and malformed-byte challenges are frozen in
the preflight/corpus. A consumer is eligible only if its recall, protected
slice, evidence-sufficiency, and verified-diagnosis gates all pass. The report
then selects the eligible consumer with the strongest worst-family recall,
followed by diagnosis success and overall recall; a tie favors the bounded
consumer. No eligible consumer means no hosted admission.

Run from a shell that already has `OPENAI_API_KEY` set:

```sh
cargo build --release -p evidentrail-bench-harness --bin evidentrail-hosted-ranking-bench
export EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK=1
export EVIDENTRAIL_HOSTED_RANKING_SHADOW=1
target/release/evidentrail-hosted-ranking-bench pilot > /tmp/evidentrail-hosted-pilot.json
```

Only after reviewing a passing pilot, run the staged scored qualification:

```sh
target/release/evidentrail-hosted-ranking-bench qualify > /tmp/evidentrail-hosted-qualification.json
```

Exit status `0` means the applicable gates passed; `2` means a gate failed or
the scored phase was skipped. The runner never changes the 800 ms deadline to
make a result pass. A live result remains a synthetic conformance result, not
a real-incident or population-quality claim, and production remains default-off
shadow until separately authorized realistic usage repeats the gates.
