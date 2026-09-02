#!/usr/bin/env bash
set -euo pipefail

readonly APPROVAL_SENTINEL="I_APPROVE_OPENAI_RESPONSES_CHARGES_AND_SYNTHETIC_EGRESS"
readonly PILOT_GUARD_MICROUSD=210000
readonly QUALIFY_GUARD_MICROUSD=3810000
readonly SOAK_GUARD_MICROUSD=1000000
readonly ALL_GUARD_MICROUSD=4810000

usage() {
  cat >&2 <<'EOF'
usage: scripts/production-qualification.sh <preflight|live-pilot|live-qualify|live-soak|all>

preflight      offline product, contract, security, scale, and release checks
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
  preflight|live-pilot|live-qualify|live-soak|all) ;;
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

run_live_pilot() {
  require_live_authorization "$PILOT_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
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
  if (( benchmark_status == 0 && product_status == 0 )); then
    return 0
  fi
  return 2
}

run_live_qualify() {
  require_live_authorization "$QUALIFY_GUARD_MICROUSD"
  require_clean_checkout
  build_live_binaries
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
  preflight)
    run_preflight
    record_exit "preflight" 0
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
