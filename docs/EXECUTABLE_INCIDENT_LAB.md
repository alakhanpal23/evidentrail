# Executable incident lab

**Status:** benchmark-only V1 conformance slice
**Date:** August 29, 2026

## Purpose

The executable incident lab measures whether a diagnostic artifact helps a
coding agent produce a verified repair. It does not treat hand-authored evidence
recall as a product outcome and it does not activate local-file or durable-store
release authority.

The V1 episode is:

```text
bounded executable incident producer
  -> two byte-identical captured runs
  -> exact captured log artifact
  -> budget-matched Evidentrail / grep-head-tail / raw-prefix arms
  -> strict external agent subprocess
  -> proposed patch bytes
  -> independent executable verifier
  -> governed cause, citation, claim, repair, and VDS join
```

Every subprocess uses an explicit executable plus argv, a cleared and
allowlisted environment, an explicit working directory, bounded stdin/stdout/
stderr, a wall deadline, pre/post executable path hashing, unconditional child
reaping, and no shell. The selected stdout or stderr stream is retained exactly;
V1 never fabricates an inter-stream order by concatenating independently
captured streams.

## Public and governed separation

`ExecutableIncidentCaseV1` contains only the executable recipe, question,
context, selected stream, expected exit, and resource caps. The incident is run
twice before any hidden truth is accepted. A freeze fails if the selected bytes,
either stream digest/count, or exit category differs.

`GovernedIncidentTruthV1` is constructed separately and binds one frozen public
case to accepted cause codes and forbidden claim codes. The agent and verifier
APIs cannot accept it. `evaluate_governed_incident_v1` rejects cross-case,
cross-log, cross-method, cross-agent, and cross-patch joins.

The agent protocol is one canonical JSON response with:

- a typed abstention shape;
- a bounded lowercase cause code;
- an arbitrary-byte patch encoded as lowercase hexadecimal;
- sorted unique positive Evidentrail aliases;
- sorted unique bounded claim codes; and
- fixed-point uncertainty micros.

Unknown fields, noncanonical JSON, malformed patch bytes, and content-bearing
diagnostics fail closed.

## Current executable corpus

The initial corpus runs three deterministic faults inside the compiled benchmark
helper:

| Family | Executed failure | Verified repair invariant |
| --- | --- | --- |
| Database pool configuration | zero-capacity pool produces request failure and Rust-shaped panic block | `pool_size` is an unpadded integer from 1 through 1024 |
| Migration drift | worker expects schema 43 while deployment remains at 42 | the repair advances migrations/schema to 43 |
| Upstream timeout | gateway uses a 5 ms timeout with aggressive retries | timeout becomes 100–60,000 ms |

Each log contains 183 records and more than 20 KiB of exact captured bytes, with
the causal configuration after enough healthy noise to fall outside a 7,000-byte
raw prefix. The observed local artifact sizes were:

| Family | Exact raw bytes | Canonical Evidentrail brief bytes | Arm budget |
| --- | ---: | ---: | ---: |
| Database pool | 20,640 | 3,575 | 7,000 |
| Migration drift | 20,662 | 3,396 | 7,000 |
| Upstream timeout | 20,625 | 3,225 | 7,000 |

These are deterministic synthetic executable fixtures, not population-quality,
latency, model-token, or non-synthetic claims.

## Current gates

`tests/executable_incident_lab.rs` proves:

- two exact executions per family freeze to the same logs and exit;
- all three method artifacts are deterministic and stay within budget;
- the raw whole-record prefix omits the causal database-pool precursor;
- the actual Evidentrail product path exposes source-exact aliases and the causal
  precursor under budget;
- a deterministic protocol-conformance agent diagnoses and repairs all three
  Evidentrail arms, and each repair passes its executable invariant;
- the raw-prefix agent abstains when the precursor is absent;
- grep/head/tail can repair the database-pool fixture but cannot claim Evidentrail's
  source-exact citation VDS capability; and
- governed binding mutations and diagnostics fail closed.

One exploratory local run used `codex-cli 0.151.0`, its configured
`gpt-5.6-sol` model, an ephemeral read-only empty working directory, and only
the canonical Evidentrail brief on stdin. Across the three cases it identified the
intended cause, cited visible `E<n>` aliases, and proposed patches satisfying
the fixture invariants. This run was not executed through a preregistered hosted
adapter, did not freeze model-message/usage receipts for every case, and is not
a comparative quality or release claim.

## Next admission steps

1. Replace the conformance agent with a provider-neutral, version-pinned coding
   agent adapter that retains exact prompt, response, usage, model, tokenizer,
   and tool-call receipts.
2. Run each arm with the same repository snapshot, prompt, tools, context and
   total episode caps; alternate arm order and repeat trials.
3. Move from patch-byte verifiers to isolated repository copies where the agent
   edits files and the known reproduction/test command is executed afterward.
4. Add family-safe executable applications across runtime, provider/format,
   scale, partial-acquisition, and adversarial-instruction slices.
5. Power a pilot, freeze thresholds and exclusions, then run a preregistered
   hidden evaluation. Real consented incidents enter only after governance and
   release gates permit them.
