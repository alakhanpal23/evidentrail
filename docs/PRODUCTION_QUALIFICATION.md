# Production qualification program

This program combines the repository's contract, scale, security, live hosted
ranking, downstream diagnosis, and repeated production-path tests. It is
staged deliberately: a failed low-volume gate prevents a larger paid run.

It does not claim that every possible production environment has been tested.
The signed macOS Keychain restart test still requires a provisioned rebootable
host, and governed incident quality requires independently labeled incident
files supplied outside the repository.

## Test stages

| Stage | Provider calls | Maximum cost guard | What it establishes |
| --- | ---: | ---: | --- |
| `preflight` | 0 | $0 | Formatting, Clippy, all workspace targets/features, Rustdoc, wire schemas, feature partitions, RustSec audit, deterministic production shadow, 10K/100K memory probes, 10K/100K/1M repository probes, and the ignored one-million-record evidence gate |
| `live-pilot` | 21 | $0.21 | 18 frozen ranking calls over six fault families plus three calls through the public production selector |
| `live-qualify` | Up to 381 | $3.81 | The pilot, then 72 randomized ranking calls on 24 untouched cases, replay through all three consumers, and up to 288 hosted diagnosis calls, plus the production selector smoke |
| `live-soak` | 100 | $1.00 | Repeated production bounded-affinity selection through one persistent client |
| `all` | Up to 481 | $4.81 | Preflight, full live qualification, then soak only if qualification passes |

The guards use the existing conservative ceiling of $0.01 per hosted call.
They are authorization ceilings, not provider billing statements. Reports
include the token-derived cost observed in successful responses. The current
pinned price inputs are $0.20 per million input tokens and $1.20 per million
output tokens.

## Safety behavior

- The mode argument is mandatory; running the script without one cannot spend.
- Every live stage requires the API key, an exact approval sentinel, and an
  integer micro-USD ceiling sufficient for that stage.
- The OpenAI key is read only from the environment and never written to a
  report, command argument, or log.
- Reports are created with private permissions outside the repository.
- No prompt, response, question, log, evidence bytes, or provider request ID is
  serialized by the live benchmark reports.
- Calls are sequential through persistent clients. There is no retry.
- `all` never starts the 100-call soak unless the scored qualification passes.
- The model deadline remains 800 ms. A timeout is a failure, not a reason to
  silently loosen the gate.

## Run the no-cost preflight

```sh
cd /Users/arjun/.superset/projects/evidentrail
scripts/production-qualification.sh preflight
```

The command prints a protected `REPORT_DIR`. Preflight includes the expensive
one-million-record test and may take several minutes.

## Run the complete live program

Use the shell in which `OPENAI_API_KEY` is already set:

```sh
cd /Users/arjun/.superset/projects/evidentrail

export EVIDENTRAIL_LIVE_TEST_APPROVAL=I_APPROVE_OPENAI_RESPONSES_CHARGES_AND_SYNTHETIC_EGRESS
export EVIDENTRAIL_LIVE_TEST_BUDGET_MICROUSD=4810000

scripts/production-qualification.sh all
```

The `$4.81` value is the program's conservative authorization guard, not a
prediction that the run will cost that amount. To limit the first paid step to
21 calls, use `live-pilot` with a `210000` micro-USD ceiling instead.

## Interpret the outcome

Exit `0` means every applicable gate in the selected stage passed. Exit `2`
means a gate failed or a required authorization was absent. Expected report
files include:

- `preflight-summary.json`;
- `hosted-ranking-pilot.json` or `hosted-ranking-qualification.json`;
- `hosted-production-smoke.json`;
- `hosted-production-soak.json` when the soak was admitted;
- contentless command logs and exit codes.

A complete hosted qualification still requires 100% integrity, at least 99%
valid ranking responses, p95 assisted latency below one second, p95 ranking
cost at or below $0.01, a positive paired recall lower confidence bound, no
protected-slice regression beyond one percentage point, and non-inferior
verified diagnosis. If the operational pilot repeats the previously observed
800 ms timeouts, the program stops before the scored and soak stages.

## Remaining environment-specific gates

After synthetic qualification passes:

1. Run the governed incident manifest described in
   [`PRODUCTION_SHADOW_PILOT.md`](PRODUCTION_SHADOW_PILOT.md) on 10–20 approved,
   independently labeled incidents.
2. Run the ignored Keychain contract on a provisioned, signed, rebootable Mac.
3. Exercise a read-only CI and Kubernetes/CloudWatch adapter shadow in the
   target deployment environment; current adapters are transport-injected
   contracts rather than configured customer connections.
4. Observe the same latency, validity, cost, privacy, recall, and diagnosis
   gates under shadow traffic before beta admission.
