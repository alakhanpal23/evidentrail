#!/bin/sh
set -eu

if [ "$#" -ne 8 ]; then
  printf '%s\n' 'usage: stage-cold-boot-arm-v3.sh EXECUTABLE FIXTURE STAGED_FIXTURE REPOSITORY STATE_FILE ARM AUTHORITY_MODE SEMANTIC_COMMITMENT' >&2
  exit 2
fi

executable=$1
fixture=$2
staged_fixture=$3
repository=$4
state_file=$5
arm=$6
authority_mode=$7
semantic_commitment=$8

case "$arm" in memory|durable) ;; *) printf '%s\n' 'EVIDENTRAIL_INVALID_QUALIFICATION_ARM' >&2; exit 2 ;; esac
case "$authority_mode" in keychain) ;; *) printf '%s\n' 'EVIDENTRAIL_NONQUALIFYING_AUTHORITY_MODE' >&2; exit 2 ;; esac
[ "${#semantic_commitment}" -eq 64 ] || { printf '%s\n' 'EVIDENTRAIL_INVALID_SEMANTIC_COMMITMENT' >&2; exit 2; }
case "$semantic_commitment" in *[!0-9a-fA-F]*) printf '%s\n' 'EVIDENTRAIL_INVALID_SEMANTIC_COMMITMENT' >&2; exit 2 ;; esac
[ -f "$executable" ] || { printf '%s\n' 'EVIDENTRAIL_EXECUTABLE_UNAVAILABLE' >&2; exit 2; }
[ -f "$fixture" ] || { printf '%s\n' 'EVIDENTRAIL_FIXTURE_UNAVAILABLE' >&2; exit 2; }
[ ! -e "$staged_fixture" ] || { printf '%s\n' 'EVIDENTRAIL_STAGED_FIXTURE_ALREADY_EXISTS' >&2; exit 2; }
[ ! -e "$state_file" ] || { printf '%s\n' 'EVIDENTRAIL_COLD_BOOT_STATE_ALREADY_EXISTS' >&2; exit 2; }

codesign --verify --strict --deep "$executable"
spctl --assess --type execute "$executable"
install -m 600 "$fixture" "$staged_fixture"
executable_digest=$(shasum -a 256 "$executable" | awk '{print $1}')
fixture_digest=$(shasum -a 256 "$staged_fixture" | awk '{print $1}')
boot_digest=$(sysctl -n kern.boottime | shasum -a 256 | awk '{print $1}')
os_version=$(sw_vers -productVersion)
os_build=$(sw_vers -buildVersion)
volume=$(df -P "$(dirname "$repository")" | awk 'NR==2 {print $1}')
filesystem=$(stat -f '%T' "$(dirname "$repository")")
[ "$filesystem" = "apfs" ] || { printf '%s\n' 'EVIDENTRAIL_QUALIFICATION_VOLUME_NOT_APFS' >&2; exit 2; }
state_tmp="${state_file}.new"
[ ! -e "$state_tmp" ] || { printf '%s\n' 'EVIDENTRAIL_COLD_BOOT_TEMP_STATE_EXISTS' >&2; exit 2; }

jq -n \
  --arg executable "$executable" \
  --arg executable_sha256 "$executable_digest" \
  --arg staged_fixture "$staged_fixture" \
  --arg fixture_sha256 "$fixture_digest" \
  --arg repository "$repository" \
  --arg arm "$arm" \
  --arg authority_mode "$authority_mode" \
  --arg semantic_commitment "$semantic_commitment" \
  --arg staging_boot_sha256 "$boot_digest" \
  --arg apfs_volume "$volume" \
  --arg os_version "$os_version" \
  --arg os_build "$os_build" \
  '{contract_version:3, executable:$executable, executable_sha256:$executable_sha256, staged_fixture:$staged_fixture, fixture_sha256:$fixture_sha256, repository:$repository, arm:$arm, authority_mode:$authority_mode, semantic_commitment:$semantic_commitment, staging_boot_sha256:$staging_boot_sha256, apfs_volume:$apfs_volume, filesystem:"apfs", os_version:$os_version, os_build:$os_build, requires_reboot:true}' \
  > "$state_tmp"
chmod 600 "$state_tmp"
mv "$state_tmp" "$state_file"
sync
printf '%s\n' 'V3 fixture and signed executable commitments staged. Reboot before executing this one arm.'
