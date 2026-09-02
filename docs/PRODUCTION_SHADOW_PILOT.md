# Production shadow pilot

**Status:** local historical-incident pilot; never production qualification

**Data path:** deterministic, memory-only, no hosted egress

**Telemetry:** contentless JSON written only where the operator directs stdout

## Purpose

`evidentrail-production-shadow` evaluates approved historical incidents without
publishing a Log Brief or retained source bytes. It runs the real deterministic
V1 product path at least three times per case, generates a fresh result identity
for every attempt, expands every selected alias, and checks exact required
evidence supplied by an incident reviewer.

The report contains only low-cardinality modes plus counts, booleans, budgets,
and timings. It never serializes paths, questions, log bytes, evidence bytes,
result IDs, free-form error text, or content-derived hashes.

This is the first production-testing stage. It does not connect to a live
provider, alter a CI result, execute a fix, call a model, establish downstream
diagnosis success, or qualify the product for release.

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
  "schema_version": 1,
  "data_classification": "governed_evaluation_c4",
  "local_processing_only": true,
  "hosted_egress": false,
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
      "protected_slice": false
    }
  ]
}
```

Paths must be relative, remain under the canonical corpus root, name regular
non-symlink files, and remain unchanged while read. Governed roots and files
must have no group or world permission bits. A manifest must contain 1–100
cases, 3–10 repetitions, and 1–64 evidence requirements per case.

## Run the governed pilot

Hosted environment variables are irrelevant to this binary because it has no
ranker path. Clearing them makes the operator intent explicit:

```sh
unset OPENAI_API_KEY EVIDENTRAIL_HOSTED_RANKING_SHADOW
export EVIDENTRAIL_HOSTED_RANKING_DISABLED=1

PILOT_ROOT=/Users/arjun/evidentrail-private-pilot
REPORT_PATH=/Users/arjun/evidentrail-private-pilot/report.json

target/release/evidentrail-production-shadow \
  "$PILOT_ROOT" manifest.json > "$REPORT_PATH"

PILOT_EXIT=$?
echo "PILOT_EXIT=$PILOT_EXIT"
jq '{case_count,attempt_count,rendered_attempt_count,needs_more_attempt_count,product_failure_count,required_evidence_recall_micros,p50_end_to_end_nanos,p95_end_to_end_nanos,all_integrity_checks_passed,quality_gate_passed,pilot_passed}' \
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
- no hosted path or content-reporting path exists in the binary.

`qualification_eligible` is always `false`. Passing this gate proves only that
the deterministic product behaved correctly on the supplied local sample.

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
6. Authorize and qualify hosted ranking separately, if ever desired. Current
   authorization excludes every real/private incident.

For an external superiority claim, the benchmark protocol requires at least 50
independently adjudicated incidents across five organizations. A product canary
should begin only after integrity is perfect and required-evidence plus
diagnosis/fix results meet the frozen non-inferiority gates.
