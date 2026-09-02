#!/usr/bin/env bash
set -euo pipefail

readonly APPROVAL_SENTINEL="I_APPROVE_OPENAI_RESPONSES_CHARGES_AND_SYNTHETIC_EGRESS"
readonly LATENCY_CHALLENGE_GUARD_MICROUSD=30000
readonly LIVE_RANKING_MEASUREMENT_GUARD_MICROUSD=180000
readonly LIVE_DEMO_PILOT_GUARD_MICROUSD=180000
readonly LIVE_DEMO_GUARD_MICROUSD=1800000
readonly PILOT_GUARD_MICROUSD=210000
readonly QUALIFY_GUARD_MICROUSD=3810000
readonly SOAK_GUARD_MICROUSD=1000000
readonly ALL_GUARD_MICROUSD=4810000
readonly LIVE_CAMPAIGN_GUARD_MICROUSD=6640000

usage() {
  cat >&2 <<'EOF'
usage: scripts/production-qualification.sh <value|preflight|live-latency-challenge|live-ranking-measure|live-demo-pilot|live-demo|live-pilot|live-qualify|live-soak|live-campaign|all>

value          no-cost matched-budget product-value report
preflight      offline product, contract, security, scale, and release checks
live-latency-challenge  3-call dated model screen at the unchanged 800 ms deadline
live-ranking-measure  18-call ranking quality/latency measurement with a 15-second safety ceiling
live-demo-pilot  18-call evaluation-contract pilot with a 15-second deadline
live-demo      180-call paired live-reader product-value demonstration
live-pilot     18-call benchmark pilot plus 3-call production-path smoke
live-qualify   gated pilot, then up to 72 ranking and 288 diagnosis calls, plus smoke
live-soak      100 production-path ranking attempts through one persistent client
live-campaign  full 664-call maximum staged campaign; soak only after qualification
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
  value|preflight|live-latency-challenge|live-ranking-measure|live-demo-pilot|live-demo|live-pilot|live-qualify|live-soak|live-campaign|all) ;;
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
    --bin evidentrail-live-product-demo \
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
  unset EVIDENTRAIL_HOSTED_RANKING_SHADOW
  unset EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK
  unset EVIDENTRAIL_STREAMING_V3

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

run_live_ranking_measurement() {
  require_live_authorization "$LIVE_RANKING_MEASUREMENT_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
  unset EVIDENTRAIL_HOSTED_RANKING_DISABLED
  export EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK=1
  export EVIDENTRAIL_HOSTED_RANKING_SHADOW=1

  echo "LIVE_RANKING_MEASUREMENT_START calls=18 per_call_safety_ceiling_seconds=15"
  set +e
  target/release/evidentrail-hosted-ranking-bench measure \
    > "$RUN_DIR/hosted-ranking-measurement.json"
  local status=$?
  set -e
  jq empty "$RUN_DIR/hosted-ranking-measurement.json"
  record_exit "hosted_ranking_measurement" "$status"
  jq \
    '{schema_version:1,scope:"synthetic_ranking_measurement_only_v2",ranking_attempt_count:.pilot.provider_call_count,valid_response_rate_micros:.pilot.valid_response_rate_micros,p50_end_to_end_nanos:.pilot.p50_end_to_end_nanos,p95_end_to_end_nanos:.pilot.p95_end_to_end_nanos,p99_end_to_end_nanos:.pilot.p99_end_to_end_nanos,p95_cost_microusd:.pilot.p95_cost_microusd,fallbacks:.pilot.fallbacks,integrity_gate:.pilot.integrity_gate,valid_response_gate:.pilot.valid_response_gate,cost_gate:.pilot.cost_gate,legacy_one_second_slo_observation:.pilot.latency_gate,measurement_accepted:(.pilot.integrity_gate and .pilot.adversarial_preflight_gate and .pilot.valid_response_gate and .pilot.cost_gate),production_admission:false,next_step:(if (.pilot.integrity_gate and .pilot.adversarial_preflight_gate and .pilot.valid_response_gate and .pilot.cost_gate) then "review_observed_latency_and_set_product_slo_before_admission" else "repair_validity_integrity_or_cost_before_more_spend" end)}' \
    "$RUN_DIR/hosted-ranking-measurement.json" \
    > "$RUN_DIR/hosted-ranking-measurement-decision.json"
  jq . "$RUN_DIR/hosted-ranking-measurement-decision.json"
  echo "LIVE_RANKING_MEASUREMENT_COMPLETE exit_status=$status"
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

run_live_demo() {
  require_live_authorization "$LIVE_DEMO_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
  run_product_value_reports
  unset EVIDENTRAIL_HOSTED_RANKING_DISABLED
  export EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK=1
  export EVIDENTRAIL_HOSTED_RANKING_SHADOW=1

  set +e
  target/release/evidentrail-live-product-demo full \
    > "$RUN_DIR/live-product-demo.json"
  local status=$?
  set -e
  jq empty "$RUN_DIR/live-product-demo.json"
  record_exit "live_product_demo" "$status"
  jq -n \
    --slurpfile deterministic "$RUN_DIR/value-decision.json" \
    --slurpfile live "$RUN_DIR/live-product-demo.json" \
    '{schema_version:1,scope:"synthetic_live_product_value_v1",deterministic_value_supported:$deterministic[0].deterministic_selection_value_passed,live_reader_value_supported:$live[0].gates.live_value_indication_supported,reader_attempt_count:$live[0].reader_attempt_count,reported_cost_microusd:$live[0].reported_cost_microusd,decision:(if ($deterministic[0].deterministic_selection_value_passed and $live[0].gates.live_value_indication_supported) then "synthetic_live_product_value_supported" else "live_product_value_not_established" end),claim_limit:"synthetic_only_not_real_incident_external_validity"}' \
    > "$RUN_DIR/live-demo-decision.json"
  return "$status"
}

run_live_demo_pilot() {
  require_live_authorization "$LIVE_DEMO_PILOT_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
  unset EVIDENTRAIL_HOSTED_RANKING_DISABLED
  export EVIDENTRAIL_SYNTHETIC_HOSTED_BENCHMARK=1
  export EVIDENTRAIL_HOSTED_RANKING_SHADOW=1

  echo "LIVE_DEMO_PILOT_START calls=18 per_call_deadline_seconds=15"

  set +e
  target/release/evidentrail-live-product-demo pilot \
    > "$RUN_DIR/live-product-demo-pilot.json"
  local status=$?
  set -e
  jq empty "$RUN_DIR/live-product-demo-pilot.json"
  record_exit "live_product_demo_pilot" "$status"
  jq \
    '{schema_version:2,scope:"synthetic_live_evaluation_contract_pilot_v2",full_value_evaluation:.full_value_evaluation,reader_attempt_count:.reader_attempt_count,valid_response_counts:[.arms[].valid_response_count],fallbacks:.fallbacks,evaluation_contract_accepted:.gates.evaluation_contract_accepted,reported_cost_microusd:.reported_cost_microusd,next_step:(if .gates.evaluation_contract_accepted then "eligible_for_full_180_call_live_demo" else "repair_contract_before_more_spend" end)}' \
    "$RUN_DIR/live-product-demo-pilot.json" \
    > "$RUN_DIR/live-demo-pilot-decision.json"
  jq . "$RUN_DIR/live-demo-pilot-decision.json"
  echo "LIVE_DEMO_PILOT_COMPLETE exit_status=$status"
  return "$status"
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

run_live_campaign() {
  require_live_authorization "$LIVE_CAMPAIGN_GUARD_MICROUSD"
  run_preflight
  record_exit "campaign_preflight" 0

  local challenge_status=0
  run_live_latency_challenge || challenge_status=$?
  local demo_status=0
  run_live_demo || demo_status=$?
  local qualification_status=0
  run_live_qualify || qualification_status=$?
  local soak_status=-1
  if (( qualification_status == 0 )); then
    soak_status=0
    run_live_soak || soak_status=$?
  else
    record_exit "hosted_production_soak_skipped" 2
  fi

  jq -n \
    --slurpfile challenge "$RUN_DIR/hosted-latency-challenger.json" \
    --slurpfile demo "$RUN_DIR/live-product-demo.json" \
    --slurpfile qualification "$RUN_DIR/hosted-ranking-qualification.json" \
    --argjson challenge_status "$challenge_status" \
    --argjson demo_status "$demo_status" \
    --argjson qualification_status "$qualification_status" \
    --argjson soak_status "$soak_status" \
    '{schema_version:1,scope:"staged_synthetic_live_campaign_v1",maximum_provider_calls:664,maximum_cost_guard_microusd:6640000,latency_challenger_completed:($challenge_status == 0),live_product_value_supported:$demo[0].gates.live_value_indication_supported,live_demo_reader_attempts:$demo[0].reader_attempt_count,hosted_ranking_qualified:($qualification[0].scored.qualification_passed // false),production_soak_completed:($soak_status == 0),qualification_status:$qualification_status,claim_limit:"synthetic_live_campaign_not_real_incident_external_validity",campaign_decision:(if ($demo_status == 0 and $qualification_status == 0 and $soak_status == 0) then "eligible_for_governed_realistic_shadow_review" elif $demo_status == 0 then "deterministic_product_value_supported_hosted_ranker_not_admitted" else "no_live_product_value_claim" end)}' \
    > "$RUN_DIR/live-campaign-decision.json"

  if (( demo_status == 0 && qualification_status == 0 && soak_status == 0 )); then
    return 0
  fi
  return 2
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
  live-ranking-measure)
    run_live_ranking_measurement
    ;;
  live-demo-pilot)
    run_live_demo_pilot
    ;;
  live-demo)
    run_live_demo
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
  live-campaign)
    run_live_campaign
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
