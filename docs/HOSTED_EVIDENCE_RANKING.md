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
and reciprocal-rank-fusion consumers are also exposed for the frozen benchmark.

There is no retry. Disabled operation, missing credentials, timeouts, rate
limits, policy denials, provider failures, invalid output, and assisted-selector
failure immediately return the already computed deterministic result.

Diagnostics contain only provider/configuration digests, elapsed time, token
counts, estimated cost, validation/fallback codes, and a digest of accepted
block IDs. Prompts, responses, credentials, provider request IDs, raw IDs, and
source bytes are not retained or logged. The CLI emits this allowlisted record
to stderr; MCP includes it as an optional `hosted_ranking` output object.

## Surfaces and release status

- CLI: `evidentrail brief ... --llm-rank` (memory retention only)
- MCP memory mode: `evidentrail_logs` with `ranking_mode: "hosted"`; omitted
  means `deterministic` (authenticated/durable retention remains deterministic)
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
