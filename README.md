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
- Runs locally and does not invoke an AI model.

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
