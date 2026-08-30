#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  printf '%s\n' 'usage: verify-cold-boot-arm-v2.sh STATE_FILE' >&2
  exit 2
fi

state_file=$1
[ -f "$state_file" ] || { printf '%s\n' 'EVIDENTRAIL_COLD_BOOT_STATE_UNAVAILABLE' >&2; exit 2; }

arm="$(jq -er '.arm' "$state_file")"
staged_path="$(jq -er '.staged_path' "$state_file")"
expected_fixture="$(jq -er '.fixture_sha256' "$state_file")"
staging_boot="$(jq -er '.staging_boot_sha256' "$state_file")"
[ -f "$staged_path" ] || { printf '%s\n' 'EVIDENTRAIL_STAGED_FIXTURE_UNAVAILABLE' >&2; exit 2; }

current_fixture="$(shasum -a 256 "$staged_path" | awk '{print $1}')"
current_boot="$(sysctl -n kern.boottime | shasum -a 256 | awk '{print $1}')"
[ "$current_fixture" = "$expected_fixture" ] || { printf '%s\n' 'EVIDENTRAIL_STAGED_FIXTURE_CHANGED' >&2; exit 2; }
[ "$current_boot" != "$staging_boot" ] || { printf '%s\n' 'EVIDENTRAIL_CLEAN_BOOT_NOT_OBSERVED' >&2; exit 2; }

printf '{"contract_version":2,"arm":"%s","fixture_sha256":"%s","execution_boot_sha256":"%s","cold_boot_verified":true}\n' \
  "$arm" "$current_fixture" "$current_boot"
