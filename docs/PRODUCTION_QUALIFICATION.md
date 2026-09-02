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
| `value` | 0 | $0 | Frozen eight-incident matched-budget evidence recall against raw, grep/head-tail, quota hybrid, BM25F, and the exact oracle; plus three executable incidents through a deterministic fixture agent and independent repair verifier |
| `preflight` | 0 | $0 | Formatting, Clippy, all workspace targets/features, Rustdoc, wire schemas, feature partitions, RustSec audit, deterministic production shadow, 10K/100K memory probes, 10K/100K/1M repository probes, and the ignored one-million-record evidence gate |
| `live-latency-challenge` | 3 | $0.03 | Non-qualifying go/no-go latency screen of dated `gpt-5.4-nano-2026-03-17` at the unchanged 800 ms deadline; this cannot repin or admit a model |
| `live-demo` | 180 | $1.80 | Three executable synthetic incidents × three matched 7,000-byte arms × 20 repetitions through one persistent GPT-5.4 nano reader, using a balanced randomized crossover schedule and paired outcome bounds |
| `live-pilot` | 21 | $0.21 | 18 frozen ranking calls over six fault families plus three calls through the public production selector |
| `live-qualify` | Up to 381 | $3.81 | The pilot, then 72 randomized ranking calls on 24 untouched cases, replay through all three consumers, and up to 288 hosted diagnosis calls, plus the production selector smoke |
| `live-soak` | 100 | $1.00 | Repeated production bounded-affinity selection through one persistent client |
| `live-campaign` | Up to 664 | $6.64 | Preflight, latency challenger, 180-call product demo, full ranker qualification, and a 100-call soak only if qualification passes |
| `all` | Up to 481 | $4.81 | Preflight, full live qualification, then soak only if qualification passes |

The guards use the existing conservative ceiling of $0.01 per hosted call.
They are authorization ceilings, not provider billing statements. Reports
include the token-derived cost observed in successful responses. The current
pinned price inputs are $0.20 per million input tokens and $1.20 per million
output tokens.

The latency challenger uses the frozen standard prices for its dated model
snapshot: $0.20 per million input tokens and $1.25 per million output tokens.
It does not use account-dependent Fast/Priority processing.

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
- `live-demo` randomizes arm order with a balanced crossover schedule and keeps
  the same incident, question, artifact ceiling, reader, and decoding contract
  across all three arms.
- `all` never starts the 100-call soak unless the scored qualification passes.
- `live-campaign` also skips its soak when ranker qualification fails; a demo
  result cannot override an admission failure.
- The model deadline remains 800 ms. A timeout is a failure, not a reason to
  silently loosen the gate.

## Run the no-cost preflight

For the fast, decision-oriented value comparison only:

```sh
cd /Users/arjun/.superset/projects/evidentrail
scripts/production-qualification.sh value
```

This produces three private reports: `product-value.json` for matched-budget
required-evidence recall, `executable-value.json` for verified repair and
citation outcomes, and `value-decision.json` for the bounded interpretation.
No provider credential is read and no network call is made.

For the complete offline safety, scale, and value preflight:

```sh
cd /Users/arjun/.superset/projects/evidentrail
scripts/production-qualification.sh preflight
```

The command prints a protected `REPORT_DIR`. Preflight includes the expensive
one-million-record test and may take several minutes.

## Run the live product-value demonstration

This is the most direct answer to “does the compressed evidence help a real
LLM diagnose the incident?” It compares Evidentrail, grep/head-tail, and raw
prefix artifacts under the same 7,000-byte ceiling. It makes exactly 180 reader
attempts and writes only aggregate metrics and contentless attempt diagnostics:

```sh
cd /Users/arjun/.superset/projects/evidentrail
export EVIDENTRAIL_LIVE_TEST_APPROVAL=I_APPROVE_OPENAI_RESPONSES_CHARGES_AND_SYNTHETIC_EGRESS
export EVIDENTRAIL_LIVE_TEST_BUDGET_MICROUSD=1800000
scripts/production-qualification.sh live-demo
```

The conservative authorization guard is $1.80. The report uses the frozen
`gpt-5.4-nano-2026-03-17` snapshot with strict structured output, no tools, no
retention, no retry, and a five-second evaluation deadline. It is deliberately
separate from the 800 ms hosted-ranker production deadline.

For the maximum staged campaign:

```sh
export EVIDENTRAIL_LIVE_TEST_BUDGET_MICROUSD=6640000
scripts/production-qualification.sh live-campaign
```

This permits at most 664 calls under a $6.64 guard. It still stops weak paths:
the ranker qualification stops after its pilot, and the 100-call soak starts
only after the full scored qualification passes.

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

Because the current pinned candidate previously missed 800 ms on every pilot
call, the cost-efficient next experiment is the three-call latency challenger:

```sh
export EVIDENTRAIL_LIVE_TEST_APPROVAL=I_APPROVE_OPENAI_RESPONSES_CHARGES_AND_SYNTHETIC_EGRESS
export EVIDENTRAIL_LIVE_TEST_BUDGET_MICROUSD=30000
scripts/production-qualification.sh live-latency-challenge
```

Even a passing result is non-qualifying. It only authorizes engineering work on
a frozen full challenger bakeoff; it never changes the production model.

## Interpret the outcome

Exit `0` means every applicable gate in the selected stage passed. Exit `2`
means a gate failed or a required authorization was absent. Expected report
files include:

- `preflight-summary.json`;
- `product-value.json`, `executable-value.json`, and `value-decision.json`;
- `hosted-ranking-pilot.json` or `hosted-ranking-qualification.json`;
- `hosted-latency-challenger.json` and `latency-challenger-decision.json` for
  the optional three-call screen;
- `live-product-demo.json` and `live-demo-decision.json` for the 180-call paired
  live-reader comparison;
- `live-campaign-decision.json` for the combined staged campaign;
- `hosted-production-smoke.json`;
- `live-decision.json` for a single fail-closed admission verdict;
- `hosted-production-soak.json` when the soak was admitted;
- contentless command logs and exit codes.

A complete hosted qualification still requires 100% integrity, at least 99%
valid ranking responses, p95 assisted latency below one second, p95 ranking
cost at or below $0.01, a positive paired recall lower confidence bound, no
protected-slice regression beyond one percentage point, and non-inferior
verified diagnosis. If the operational pilot repeats the previously observed
800 ms timeouts, the program stops before the scored and soak stages.

The deterministic and hosted claims are deliberately separate. Passing the
value stage establishes only synthetic matched-budget evidence and executable
outcome conformance for the deterministic product. `live-decision.json` marks
hosted incremental value true only when the untouched scored set passes the
positive paired-recall bound, downstream diagnosis, validity, latency, cost,
and integrity gates. Real-incident external validity remains false until an
independently labeled governed shadow corpus is supplied and passes.

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
