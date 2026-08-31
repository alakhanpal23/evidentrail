#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  printf '%s\n' 'usage: verify-cold-boot-arm-v3.sh STATE_FILE' >&2
  exit 2
fi

state_file=$1
[ -f "$state_file" ] || { printf '%s\n' 'EVIDENTRAIL_COLD_BOOT_STATE_UNAVAILABLE' >&2; exit 2; }
executable=$(jq -er '.executable' "$state_file")
staged_fixture=$(jq -er '.staged_fixture' "$state_file")
repository=$(jq -er '.repository' "$state_file")
expected_executable=$(jq -er '.executable_sha256' "$state_file")
expected_fixture=$(jq -er '.fixture_sha256' "$state_file")
staging_boot=$(jq -er '.staging_boot_sha256' "$state_file")
expected_volume=$(jq -er '.apfs_volume' "$state_file")
expected_os_version=$(jq -er '.os_version' "$state_file")
expected_os_build=$(jq -er '.os_build' "$state_file")
arm=$(jq -er '.arm' "$state_file")
authority_mode=$(jq -er '.authority_mode' "$state_file")
semantic_commitment=$(jq -er '.semantic_commitment' "$state_file")

[ -f "$executable" ] || { printf '%s\n' 'EVIDENTRAIL_EXECUTABLE_UNAVAILABLE' >&2; exit 2; }
[ -f "$staged_fixture" ] || { printf '%s\n' 'EVIDENTRAIL_STAGED_FIXTURE_UNAVAILABLE' >&2; exit 2; }
[ -d "$repository" ] || { printf '%s\n' 'EVIDENTRAIL_QUALIFICATION_REPOSITORY_UNAVAILABLE' >&2; exit 2; }
codesign --verify --strict --deep "$executable"
spctl --assess --type execute "$executable"
current_executable=$(shasum -a 256 "$executable" | awk '{print $1}')
current_fixture=$(shasum -a 256 "$staged_fixture" | awk '{print $1}')
current_boot=$(sysctl -n kern.boottime | shasum -a 256 | awk '{print $1}')
current_volume=$(df -P "$repository" | awk 'NR==2 {print $1}')
current_filesystem=$(stat -f '%T' "$repository")
current_os_version=$(sw_vers -productVersion)
current_os_build=$(sw_vers -buildVersion)
[ "$current_executable" = "$expected_executable" ] || { printf '%s\n' 'EVIDENTRAIL_EXECUTABLE_CHANGED' >&2; exit 2; }
[ "$current_fixture" = "$expected_fixture" ] || { printf '%s\n' 'EVIDENTRAIL_STAGED_FIXTURE_CHANGED' >&2; exit 2; }
[ "$current_boot" != "$staging_boot" ] || { printf '%s\n' 'EVIDENTRAIL_CLEAN_BOOT_NOT_OBSERVED' >&2; exit 2; }
[ "$current_volume" = "$expected_volume" ] || { printf '%s\n' 'EVIDENTRAIL_APFS_VOLUME_CHANGED' >&2; exit 2; }
[ "$current_filesystem" = "apfs" ] || { printf '%s\n' 'EVIDENTRAIL_QUALIFICATION_VOLUME_NOT_APFS' >&2; exit 2; }
[ "$current_os_version" = "$expected_os_version" ] || { printf '%s\n' 'EVIDENTRAIL_OS_VERSION_CHANGED' >&2; exit 2; }
[ "$current_os_build" = "$expected_os_build" ] || { printf '%s\n' 'EVIDENTRAIL_OS_BUILD_CHANGED' >&2; exit 2; }

repository_digest=$(
  cd "$repository"
  find . -type f -print | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
  done | shasum -a 256 | awk '{print $1}'
)
jq -n \
  --arg arm "$arm" \
  --arg authority_mode "$authority_mode" \
  --arg executable_sha256 "$current_executable" \
  --arg fixture_sha256 "$current_fixture" \
  --arg execution_boot_sha256 "$current_boot" \
  --arg apfs_volume "$current_volume" \
  --arg os_version "$current_os_version" \
  --arg os_build "$current_os_build" \
  --arg repository_sha256 "$repository_digest" \
  --arg semantic_commitment "$semantic_commitment" \
  '{contract_version:3, arm:$arm, authority_mode:$authority_mode, executable_sha256:$executable_sha256, fixture_sha256:$fixture_sha256, execution_boot_sha256:$execution_boot_sha256, apfs_volume:$apfs_volume, filesystem:"apfs", os_version:$os_version, os_build:$os_build, repository_sha256:$repository_sha256, semantic_commitment:$semantic_commitment, cold_boot_verified:true}'
