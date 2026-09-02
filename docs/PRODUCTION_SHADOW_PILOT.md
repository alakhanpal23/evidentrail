# Production shadow pilot

**Status:** explicit hosted historical-incident pilot; never production qualification

**Data path:** memory-only; deterministic by default; OpenAI only when explicitly authorized

**Telemetry:** contentless JSON written only where the operator directs stdout

## Purpose

`evidentrail-production-shadow` evaluates approved historical incidents without
publishing a Log Brief or retained source bytes. In hosted mode it owns one
persistent production OpenAI client for the process and runs the real hosted V1
bounded-affinity product path at least three times per case. It generates a
fresh result identity for every attempt, expands every selected alias, and
checks exact required evidence supplied by an incident reviewer. Provider
failure still uses the product's deterministic fallback.

The report contains only allowlisted hosted diagnostic records plus modes,
counts, booleans, budgets, and timings. It never serializes paths, questions,
log bytes, evidence bytes, result IDs, provider request IDs, credentials, or
free-form error text. Accepted opaque block IDs are represented only by the
existing one-way digest in the hosted diagnostic contract.

This is the first production-testing stage. Hosted mode makes real OpenAI API
calls and can exercise model-influenced selection, but it does not alter a CI
result, execute a fix, establish downstream diagnosis success, or qualify the
product for release. The applicable case-scoped authorization is recorded in
[`HOSTED_PRODUCTION_SHADOW_AUTHORIZATION.md`](HOSTED_PRODUCTION_SHADOW_AUTHORIZATION.md).

## Build and synthetic smoke test

```sh
cd /Users/arjun/.superset/projects/evidentrail

cargo build --release -p evidentrail-cli \
  --bin evidentrail-production-shadow

target/release/evidentrail-production-shadow \
  "$PWD/fixtures/production-shadow-example" \
  manifest.json | jq .
```

The command exits `0` only when every synthetic requirement is selected and
every expansion/integrity check passes. A completed pilot that misses a quality
gate still emits its contentless report and exits `2`. Invalid authorization,
paths, permissions, files, or manifests fail with one contentless error code.

To exercise the real hosted production path on the checked-in non-sensitive
fixture, run the following from a shell with billing enabled for the OpenAI
project. This makes three eligible API requests through one persistent client:

```sh
read -rs 'OPENAI_API_KEY?Paste OpenAI API key: '; export OPENAI_API_KEY; echo
unset EVIDENTRAIL_HOSTED_RANKING_DISABLED

target/release/evidentrail-production-shadow \
  "$PWD/fixtures/production-shadow-example" \
  hosted-manifest.json > /tmp/evidentrail-hosted-production-smoke.json

SMOKE_EXIT=$?
echo "SMOKE_EXIT=$SMOKE_EXIT"
jq '{hosted_provider_call_count,hosted_accepted_response_count,hosted_fallback_count,p50_hosted_provider_nanos,p95_hosted_provider_nanos,hosted_cost_microusd,required_evidence_recall_micros,all_integrity_checks_passed,hosted_execution_gate_passed,pilot_passed}' \
  /tmp/evidentrail-hosted-production-smoke.json
```

The production deadline remains 800 ms. A timeout is a legitimate failed
production gate and is never converted into a pass by silently increasing the
deadline.

## Prepare a governed local corpus

Keep all real material outside the repository and ordinary CI. On macOS:

```sh
PILOT_ROOT=/Users/arjun/evidentrail-private-pilot
install -d -m 700 "$PILOT_ROOT/case-001"
```

Place these files inside each case directory:

- `incident.log`: the approved historical log, at most 16 MiB;
- `question.txt`: the question an operator actually needed answered;
- one or more `required-*.bin` files: exact, nonempty byte fragments from the
  log that an independent reviewer says a useful evidence brief must select.

The required fragments may contain arbitrary bytes. A fragment must occur in
the supplied log and may span adjacent records inside one selected evidence
block. Do not use a root-cause description as a requirement unless those exact
bytes occur in the log.

Restrict all governed files before running:

```sh
chmod -R go-rwx "$PILOT_ROOT"
```

Create `$PILOT_ROOT/manifest.json`:

```json
{
  "schema_version": 2,
  "data_classification": "governed_evaluation_c4",
  "local_processing_only": false,
  "ranking_mode": "hosted",
  "hosted_egress": true,
  "hosted_egress_authorization": "operator_approved_openai_responses_v1",
  "content_telemetry": false,
  "retention": "memory_only",
  "repetitions": 3,
  "cases": [
    {
      "log_file": "case-001/incident.log",
      "question_file": "case-001/question.txt",
      "required_evidence_files": [
        "case-001/required-cause.bin",
        "case-001/required-precursor.bin"
      ],
      "token_budget": 20000,
      "protected_slice": false,
      "hosted_egress_approved": true
    }
  ]
}
```

Paths must be relative, remain under the canonical corpus root, name regular
non-symlink files, and remain unchanged while read. Governed roots and files
must have no group or world permission bits. A manifest must contain 1–100
cases, 3–10 repetitions, and 1–64 evidence requirements per case. Hosted mode
is rejected unless the manifest authorizes the pinned OpenAI Responses adapter
and every case separately sets `hosted_egress_approved` to `true`.

## Run the governed pilot

The production adapter reads its credential only from `OPENAI_API_KEY`. It uses
the pinned model, `store:false`, no tools or conversation history, strict
structured output, no retry, and the unchanged 800 ms deadline. Do not place a
credential in the manifest or report.

```sh
unset EVIDENTRAIL_HOSTED_RANKING_DISABLED
[[ -n ${OPENAI_API_KEY:-} ]] || { echo "OPENAI_API_KEY is not set"; exit 1; }

PILOT_ROOT=/Users/arjun/evidentrail-private-pilot
REPORT_PATH=/Users/arjun/evidentrail-private-pilot/report.json

target/release/evidentrail-production-shadow \
  "$PILOT_ROOT" manifest.json > "$REPORT_PATH"

PILOT_EXIT=$?
echo "PILOT_EXIT=$PILOT_EXIT"
jq '{ranking_mode,case_count,attempt_count,hosted_provider_call_count,hosted_accepted_response_count,hosted_fallback_count,hosted_input_tokens,hosted_output_tokens,hosted_cost_microusd,p50_hosted_provider_nanos,p95_hosted_provider_nanos,rendered_attempt_count,needs_more_attempt_count,product_failure_count,required_evidence_recall_micros,all_integrity_checks_passed,hosted_execution_gate_passed,quality_gate_passed,pilot_passed}' \
  "$REPORT_PATH"
```

The report belongs inside the same protected corpus root even though its schema
is contentless. Exact sizes and timings can still reveal operational scale.

## Pilot gates

The runner's initial gate requires:

- every attempt renders rather than failing or returning `needs_more`;
- every advertised alias expands successfully with the exact relation;
- every expanded event is source-exact and every expansion is untruncated;
- returned expansion byte accounting reconciles exactly;
- every independently supplied required fragment is selected in every repeat;
- hosted mode makes at least one provider call, accepts every returned ranking,
  and observes no fallback;
- only the closed hosted diagnostic schema is emitted; prompt, response, and
  evidence content remain absent.

`qualification_eligible` is always `false`. Passing this gate proves only that
the selected deterministic or hosted product path behaved correctly on the
supplied sample.

## What follows a passing pilot

1. Grow from 10–20 internal resolved CI incidents to an independently
   adjudicated, lineage-separated corpus. Keep it outside source control.
2. Add a downstream blinded reader/human comparison against raw logs at the
   same total context budget. Measure verified diagnosis and fix success.
3. Re-run the current V4 10K/100K/1M resource point screen on a designated
   release host; historical V3 numbers do not carry forward.
4. Add a read-only CI shadow integration that never changes job status and
   emits this same contentless schema.
5. Qualify signed-Keychain restart behavior on a provisioned rebootable Mac
   before enabling durable production retention.
6. Keep hosted ranking explicit and shadow-only until latency, response
   validity, recall, downstream diagnosis, protected-slice, and cost gates pass.

For an external superiority claim, the benchmark protocol requires at least 50
independently adjudicated incidents across five organizations. A product canary
should begin only after integrity is perfect and required-evidence plus
diagnosis/fix results meet the frozen non-inferiority gates.
