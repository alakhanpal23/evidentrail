#!/usr/bin/env bash
set -euo pipefail

readonly APPROVAL_SENTINEL="I_APPROVE_OPENAI_RESPONSES_CHARGES_AND_SYNTHETIC_EGRESS"
readonly LATENCY_CHALLENGE_GUARD_MICROUSD=30000
readonly PILOT_GUARD_MICROUSD=210000
readonly QUALIFY_GUARD_MICROUSD=3810000
readonly SOAK_GUARD_MICROUSD=1000000
readonly ALL_GUARD_MICROUSD=4810000

usage() {
  cat >&2 <<'EOF'
usage: scripts/production-qualification.sh <value|preflight|live-latency-challenge|live-pilot|live-qualify|live-soak|all>

value          no-cost matched-budget product-value report
preflight      offline product, contract, security, scale, and release checks
live-latency-challenge  3-call dated model screen at the unchanged 800 ms deadline
live-pilot     18-call benchmark pilot plus 3-call production-path smoke
live-qualify   gated pilot, then up to 72 ranking and 288 diagnosis calls, plus smoke
live-soak      100 production-path ranking attempts through one persistent client
all            preflight, live-qualify, then soak only if qualification passes

Every live mode requires OPENAI_API_KEY plus:
  EVIDENTRAIL_LIVE_TEST_APPROVAL=I_APPROVE_OPENAI_RESPONSES_CHARGES_AND_SYNTHETIC_EGRESS
  EVIDENTRAIL_LIVE_TEST_BUDGET_MICROUSD=<integer ceiling>
EOF
  exit 2
}

[[ $# -eq 1 ]] || usage
readonly MODE="$1"
case "$MODE" in
  value|preflight|live-latency-challenge|live-pilot|live-qualify|live-soak|all) ;;
  *) usage ;;
esac

for command_name in cargo git jq; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "EVIDENTRAIL_QUALIFICATION_MISSING_COMMAND=$command_name" >&2
    exit 2
  }
done

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

readonly REPORT_BASE="${EVIDENTRAIL_QUALIFICATION_REPORT_ROOT:-/Users/arjun/evidentrail-production-reports}"
[[ "$REPORT_BASE" = /* ]] || {
  echo "EVIDENTRAIL_QUALIFICATION_REPORT_ROOT_MUST_BE_ABSOLUTE" >&2
  exit 2
}
[[ ! -L "$REPORT_BASE" ]] || {
  echo "EVIDENTRAIL_QUALIFICATION_REPORT_ROOT_MUST_NOT_BE_SYMLINK" >&2
  exit 2
}
umask 077
mkdir -p "$REPORT_BASE"
chmod 700 "$REPORT_BASE"
readonly REPORT_BASE_CANONICAL="$(cd "$REPORT_BASE" && pwd -P)"
case "$REPORT_BASE_CANONICAL/" in
  "$REPO_ROOT/"*)
    echo "EVIDENTRAIL_QUALIFICATION_REPORT_ROOT_MUST_BE_OUTSIDE_REPOSITORY" >&2
    exit 2
    ;;
esac
readonly RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly RUN_DIR="$REPORT_BASE_CANONICAL/$RUN_ID"
mkdir -m 700 "$RUN_DIR"

printf '%s\n' "REPORT_DIR=$RUN_DIR"

write_run_metadata() {
  jq -n \
    --arg mode "$MODE" \
    --arg commit "$(git rev-parse HEAD)" \
    --arg started_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{schema_version:1,mode:$mode,commit:$commit,started_at:$started_at,contentless:true}' \
    > "$RUN_DIR/run.json"
}

record_exit() {
  local stage="$1"
  local status="$2"
  printf '%s=%s\n' "$stage" "$status" >> "$RUN_DIR/exit-codes.txt"
}

require_clean_checkout() {
  git diff --quiet
  git diff --cached --quiet
  [[ -z "$(git status --short)" ]]
}

require_live_authorization() {
  local required_budget="$1"
  [[ -n "${OPENAI_API_KEY:-}" ]] || {
    echo "EVIDENTRAIL_QUALIFICATION_OPENAI_API_KEY_MISSING" >&2
    exit 2
  }
  [[ "${EVIDENTRAIL_LIVE_TEST_APPROVAL:-}" == "$APPROVAL_SENTINEL" ]] || {
    echo "EVIDENTRAIL_QUALIFICATION_LIVE_APPROVAL_MISSING" >&2
    exit 2
  }
  local budget="${EVIDENTRAIL_LIVE_TEST_BUDGET_MICROUSD:-}"
  [[ "$budget" =~ ^[0-9]+$ ]] || {
    echo "EVIDENTRAIL_QUALIFICATION_BUDGET_INVALID" >&2
    exit 2
  }
  (( budget >= required_budget )) || {
    echo "EVIDENTRAIL_QUALIFICATION_BUDGET_BELOW_STAGE_GUARD" >&2
    exit 2
  }
}

build_live_binaries() {
  cargo build --release -p evidentrail-cli --bin evidentrail-production-shadow \
    > "$RUN_DIR/build-production-shadow.log" 2>&1
  cargo build --release -p evidentrail-bench-harness --bin evidentrail-hosted-ranking-bench \
    > "$RUN_DIR/build-hosted-benchmark.log" 2>&1
  build_value_binaries
}

build_value_binaries() {
  cargo build --release -p evidentrail-bench-harness \
    --bin evidentrail-product-value-bench \
    --bin evidentrail-executable-value-bench \
    --bin evidentrail-bench-harness-helper \
    > "$RUN_DIR/build-product-value.log" 2>&1
}

run_product_value_reports() {
  target/release/evidentrail-product-value-bench > "$RUN_DIR/product-value.json"
  target/release/evidentrail-executable-value-bench > "$RUN_DIR/executable-value.json"
  jq empty "$RUN_DIR/product-value.json"
  jq empty "$RUN_DIR/executable-value.json"
  jq -n \
    --slurpfile selection "$RUN_DIR/product-value.json" \
    --slurpfile outcome "$RUN_DIR/executable-value.json" \
    '{schema_version:1,scope:"synthetic_product_value_v1",deterministic_selection_value_passed:($selection[0].gates.all_arms_use_full_selected_source_byte_budget and $selection[0].gates.deterministic_matches_exact_oracle_recall and $selection[0].gates.deterministic_beats_every_cheap_baseline_recall and $selection[0].gates.deterministic_perfect_on_every_case),executable_outcome_value_passed:($outcome[0].producer_byte_repeatability_gate and $outcome[0].evidentrail_all_repairs_verified and $outcome[0].evidentrail_all_citations_valid and $outcome[0].evidentrail_all_vds_at_budget),hosted_incremental_value_established:false,real_incident_external_validity_established:false,product_decision:"deterministic_product_value_supported_hosted_and_real_incident_claims_pending"}' \
    > "$RUN_DIR/value-decision.json"
}

write_live_decision() {
  local benchmark_report="$1"
  local production_smoke_status="$2"
  jq -n \
    --slurpfile selection "$RUN_DIR/product-value.json" \
    --slurpfile outcome "$RUN_DIR/executable-value.json" \
    --slurpfile hosted "$benchmark_report" \
    --argjson smoke_status "$production_smoke_status" \
    '($selection[0].gates.deterministic_beats_every_cheap_baseline_recall and $selection[0].gates.deterministic_matches_exact_oracle_recall and $selection[0].gates.deterministic_perfect_on_every_case) as $selection_passed |
     ($outcome[0].producer_byte_repeatability_gate and $outcome[0].evidentrail_all_repairs_verified and $outcome[0].evidentrail_all_citations_valid and $outcome[0].evidentrail_all_vds_at_budget) as $outcome_passed |
     ($hosted[0].pilot.integrity_gate and $hosted[0].pilot.adversarial_preflight_gate and $hosted[0].pilot.valid_response_gate and $hosted[0].pilot.latency_gate and $hosted[0].pilot.cost_gate) as $operations_passed |
     ($hosted[0].scored.qualification_passed // false) as $incremental_value_passed |
     ($smoke_status == 0) as $smoke_passed |
     {schema_version:1,scope:"synthetic_hosted_admission_v1",deterministic_selection_value_passed:$selection_passed,executable_outcome_value_passed:$outcome_passed,hosted_operational_pilot_passed:$operations_passed,hosted_incremental_value_established:$incremental_value_passed,production_path_smoke_passed:$smoke_passed,admission_decision:(if ($selection_passed and $outcome_passed and $operations_passed and $incremental_value_passed and $smoke_passed) then "eligible_for_governed_shadow_review" else "deterministic_only_hosted_not_admitted" end),claim_limit:"synthetic_conformance_only_real_incident_shadow_still_required"}' \
    > "$RUN_DIR/live-decision.json"
}

run_preflight() (
  export EVIDENTRAIL_HOSTED_RANKING_DISABLED=1
  unset OPENAI_API_KEY

  require_clean_checkout
  cargo fmt --all -- --check > "$RUN_DIR/fmt.log" 2>&1
  cargo clippy --workspace --all-targets --all-features -- -D warnings \
    > "$RUN_DIR/clippy.log" 2>&1
  cargo test --workspace --all-targets --all-features \
    > "$RUN_DIR/workspace-tests.log" 2>&1
  RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps \
    > "$RUN_DIR/rustdoc.log" 2>&1
  cargo run -p evidentrail-wire --all-features --bin evidentrail-wire-schema -- --check \
    > "$RUN_DIR/wire-schema.log" 2>&1

  cargo check -p evidentrail-wire --no-default-features --features local-file \
    > "$RUN_DIR/feature-local-file.log" 2>&1
  cargo check -p evidentrail-wire --no-default-features --features ledger \
    > "$RUN_DIR/feature-ledger.log" 2>&1
  cargo check -p evidentrail-wire --no-default-features --features product \
    > "$RUN_DIR/feature-product.log" 2>&1
  cargo check -p evidentrail-wire --no-default-features --features bench \
    > "$RUN_DIR/feature-bench.log" 2>&1
  cargo check -p evidentrail-wire --no-default-features --features all-contracts \
    > "$RUN_DIR/feature-all-contracts.log" 2>&1

  cargo audit > "$RUN_DIR/cargo-audit.log" 2>&1
  cargo test -p evidentrail-cli --test v3_large_incident_corpus --all-features \
    -- --ignored --nocapture > "$RUN_DIR/one-million-record-gate.log" 2>&1

  cargo run --release -p evidentrail-bench-harness --example local_product_performance \
    -- memory records 10000 > "$RUN_DIR/performance-memory-10k.json" \
    2> "$RUN_DIR/performance-memory-10k.log"
  cargo run --release -p evidentrail-bench-harness --example local_product_performance \
    -- memory records 100000 > "$RUN_DIR/performance-memory-100k.json" \
    2> "$RUN_DIR/performance-memory-100k.log"
  cargo run --release -p evidentrail-bench-harness --example local_product_performance \
    -- repository records 10000 > "$RUN_DIR/performance-repository-10k.json" \
    2> "$RUN_DIR/performance-repository-10k.log"
  cargo run --release -p evidentrail-bench-harness --example local_product_performance \
    -- repository records 100000 > "$RUN_DIR/performance-repository-100k.json" \
    2> "$RUN_DIR/performance-repository-100k.log"
  cargo run --release -p evidentrail-bench-harness --example local_product_performance \
    -- repository records 1000000 > "$RUN_DIR/performance-repository-1m.json" \
    2> "$RUN_DIR/performance-repository-1m.log"

  build_live_binaries
  run_product_value_reports
  target/release/evidentrail-production-shadow \
    "$REPO_ROOT/fixtures/production-shadow-example" manifest.json \
    > "$RUN_DIR/deterministic-production-shadow.json"

  jq -n \
    '{schema_version:1,passed:true,hosted_calls:0,one_million_record_gate:true,environment_exclusions:["signed_keychain_restart_requires_provisioned_rebootable_mac","real_incidents_require_case_files_and_independent_labels"]}' \
    > "$RUN_DIR/preflight-summary.json"
)

run_product_smoke() {
  set +e
  target/release/evidentrail-production-shadow \
    "$REPO_ROOT/fixtures/production-shadow-example" hosted-manifest.json \
    > "$RUN_DIR/hosted-production-smoke.json"
  local status=$?
  set -e
  jq empty "$RUN_DIR/hosted-production-smoke.json"
  record_exit "hosted_production_smoke" "$status"
  return "$status"
}

run_live_latency_challenge() {
  require_live_authorization "$LATENCY_CHALLENGE_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
  run_product_value_reports
  unset EVIDENTRAIL_HOSTED_RANKING_DISABLED
  export EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK=1
  export EVIDENTRAIL_HOSTED_RANKING_SHADOW=1

  set +e
  target/release/evidentrail-hosted-ranking-bench challenge-latency \
    > "$RUN_DIR/hosted-latency-challenger.json"
  local status=$?
  set -e
  jq empty "$RUN_DIR/hosted-latency-challenger.json"
  record_exit "hosted_latency_challenger" "$status"
  jq \
    '{schema_version:1,qualification_eligible:false,all_calls_accepted:(.accepted_count == .call_count),within_production_deadline:.observed_within_production_deadline,integrity_passed:.all_integrity_checks_passed,next_step:(if (.accepted_count == .call_count and .observed_within_production_deadline and .all_integrity_checks_passed) then "build_frozen_full_challenger_bakeoff" else "do_not_spend_on_full_challenger_bakeoff" end)}' \
    "$RUN_DIR/hosted-latency-challenger.json" \
    > "$RUN_DIR/latency-challenger-decision.json"
  return "$status"
}

run_live_pilot() {
  require_live_authorization "$PILOT_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
  run_product_value_reports
  unset EVIDENTRAIL_HOSTED_RANKING_DISABLED
  export EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK=1
  export EVIDENTRAIL_HOSTED_RANKING_SHADOW=1

  set +e
  target/release/evidentrail-hosted-ranking-bench pilot \
    > "$RUN_DIR/hosted-ranking-pilot.json"
  local benchmark_status=$?
  set -e
  jq empty "$RUN_DIR/hosted-ranking-pilot.json"
  record_exit "hosted_ranking_pilot" "$benchmark_status"

  local product_status=0
  run_product_smoke || product_status=$?
  write_live_decision "$RUN_DIR/hosted-ranking-pilot.json" "$product_status"
  if (( benchmark_status == 0 && product_status == 0 )); then
    return 0
  fi
  return 2
}

run_live_qualify() {
  require_live_authorization "$QUALIFY_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
  run_product_value_reports
  unset EVIDENTRAIL_HOSTED_RANKING_DISABLED
  export EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK=1
  export EVIDENTRAIL_HOSTED_RANKING_SHADOW=1

  set +e
  target/release/evidentrail-hosted-ranking-bench qualify \
    > "$RUN_DIR/hosted-ranking-qualification.json"
  local benchmark_status=$?
  set -e
  jq empty "$RUN_DIR/hosted-ranking-qualification.json"
  record_exit "hosted_ranking_qualification" "$benchmark_status"

  local product_status=0
  run_product_smoke || product_status=$?
  write_live_decision "$RUN_DIR/hosted-ranking-qualification.json" "$product_status"
  if (( benchmark_status == 0 && product_status == 0 )); then
    return 0
  fi
  return 2
}

run_live_soak() {
  require_live_authorization "$SOAK_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
  unset EVIDENTRAIL_HOSTED_RANKING_DISABLED

  set +e
  target/release/evidentrail-production-shadow \
    "$REPO_ROOT/fixtures/production-shadow-example" hosted-soak-manifest.json \
    > "$RUN_DIR/hosted-production-soak.json"
  local status=$?
  set -e
  jq empty "$RUN_DIR/hosted-production-soak.json"
  record_exit "hosted_production_soak" "$status"
  return "$status"
}

write_run_metadata
case "$MODE" in
  value)
    require_clean_checkout
    build_value_binaries
    run_product_value_reports
    record_exit "product_value" 0
    ;;
  preflight)
    run_preflight
    record_exit "preflight" 0
    ;;
  live-latency-challenge)
    run_live_latency_challenge
    ;;
  live-pilot)
    run_live_pilot
    ;;
  live-qualify)
    run_live_qualify
    ;;
  live-soak)
    run_live_soak
    ;;
  all)
    require_live_authorization "$ALL_GUARD_MICROUSD"
    run_preflight
    record_exit "preflight" 0
    if ! run_live_qualify; then
      echo "EVIDENTRAIL_QUALIFICATION_STOPPED_BEFORE_SOAK" >&2
      exit 2
    fi
    run_live_soak
    ;;
esac

printf '%s\n' "QUALIFICATION_STAGE_PASSED=$MODE"
