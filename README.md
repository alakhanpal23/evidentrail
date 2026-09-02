# Evidentrail

Evidentrail turns large diagnostic logs into a compact, auditable evidence
brief for coding agents.

Instead of sending an entire log file to a model, Evidentrail keeps the exact
source bytes, finds the events most relevant to a question, and returns a
smaller brief with expandable evidence references.

## What it does

- Preserves raw log bytes, record boundaries, duplicate events, invalid UTF-8,
  and multiline failures such as stack traces.
- Returns the complete input unchanged when it already fits the output budget.
- Otherwise selects evidence using identifiers, failure context, raw coverage,
  and explicitly supplied provider correlations.
- Produces deterministic output: the same authorized input, question, policy,
  and budget produce the same brief.
- Exposes exact `E<n>` references so a caller can retrieve the original source
  events behind a claim.
- Returns `needs_more` when the budget cannot hold enough evidence instead of
  inventing a confident summary.
- Supports in-memory retention and an opt-in encrypted packed repository for
  restartable exact expansion.
- Runs locally and does not invoke an AI model by default. Hosted evidence
  ranking is a separate explicit opt-in with deterministic fallback.

## Why it is useful

Large logs are expensive to place in an agent context, while ordinary summaries
can lose the line that proves what happened. Evidentrail reduces the context
size without disconnecting the result from its source evidence.

It is intended for CI failures, compiler output, service incidents, Kubernetes
logs, and other debugging workflows where an agent needs concise context plus
the ability to inspect the exact underlying bytes.

## CLI

Compile logs supplied on standard input:

```sh
cargo run -p evidentrail-cli --bin evidentrail -- brief \
  --question "why did request REQ-7 fail?" \
  --token-budget 20000 < app.log
```

Opt into one hosted evidence-ranking call (memory retention only):

```sh
OPENAI_API_KEY=... cargo run -p evidentrail-cli --bin evidentrail -- brief \
  --question "why did request REQ-7 fail?" \
  --token-budget 20000 --llm-rank < app.log
```

The model can reorder at most 32 intact optional blocks. It cannot rewrite
evidence, add citations, remove mandatory evidence, or decide completeness.
Missing credentials, the kill switch (`EVIDENTRAIL_HOSTED_RANKING_DISABLED=1`),
timeouts, provider errors, and invalid responses all use the deterministic
result without retrying. Hosted payloads have a separate 40-KiB escaped-input
cap. Internal rollout can set `EVIDENTRAIL_HOSTED_RANKING_SHADOW=1` with the
explicit opt-in to exercise ranking while always publishing deterministic
bytes. See [hosted evidence ranking](docs/HOSTED_EVIDENCE_RANKING.md) for the
trust boundary and release status.

Run the process-resident MCP service:

```sh
cargo run -p evidentrail-cli --bin evidentrail -- serve-mcp
```

The MCP surface provides `evidentrail_logs` for compiling caller-supplied bytes
and `evidentrail_expand` for exact expansion of result-scoped references.

## Current status

The deterministic memory product is the default. Streaming V3 supports up to
1,000,000 records or 1 GiB of explicit input and is gated behind
`EVIDENTRAIL_STREAMING_V3=1`. Durable macOS retention requires authorized
Keychain access and fails closed when that authority is unavailable.

Engineering design, format, benchmark, and qualification details are kept in
[`docs/`](docs/).

### Optional LLM compression evaluation

The benchmark harness includes a provider-neutral hosted-reader JSONL contract
for checking a compact view against the full view with the same pinned model.
The check passes only when the compact method artifact and provider-reported
prompt are both smaller, while the structured diagnosis, claims, and citation
semantics are exactly preserved. Responses are strictly parsed, identity-bound,
resource-capped, and fail closed.

This evaluation and the hosted-ranking beta are opt-in: CI uses offline
fixtures, credentials stay in the CLI adapter rather than the compiler/product
contract, an LLM never rewrites trusted evidence, and a passing receipt is not
production-admission authority.
See the [hosted LLM compression check](docs/HOSTED_LLM_COMPRESSION_CHECK.md)
for the adapter flow and response contract.

## License

Licensed under either of the following, at your option:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)
