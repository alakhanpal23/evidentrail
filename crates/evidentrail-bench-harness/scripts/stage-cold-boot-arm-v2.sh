#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  printf '%s\n' 'usage: stage-cold-boot-arm-v2.sh SOURCE STAGED_COPY STATE_FILE ARM' >&2
  exit 2
fi

source_file=$1
staged_copy=$2
state_file=$3
arm=$4

case "$arm" in memory|durable) ;; *) printf '%s\n' 'EVIDENTRAIL_INVALID_QUALIFICATION_ARM' >&2; exit 2 ;; esac
[ -f "$source_file" ] || { printf '%s\n' 'EVIDENTRAIL_FIXTURE_UNAVAILABLE' >&2; exit 2; }
[ ! -e "$staged_copy" ] || { printf '%s\n' 'EVIDENTRAIL_STAGED_FIXTURE_ALREADY_EXISTS' >&2; exit 2; }
[ ! -e "$state_file" ] || { printf '%s\n' 'EVIDENTRAIL_COLD_BOOT_STATE_ALREADY_EXISTS' >&2; exit 2; }

install -m 600 "$source_file" "$staged_copy"
fixture_digest="$(shasum -a 256 "$staged_copy" | awk '{print $1}')"
boot_digest="$(sysctl -n kern.boottime | shasum -a 256 | awk '{print $1}')"
state_tmp="${state_file}.new"
[ ! -e "$state_tmp" ] || { printf '%s\n' 'EVIDENTRAIL_COLD_BOOT_TEMP_STATE_EXISTS' >&2; exit 2; }

cat > "$state_tmp" <<EOF
{"contract_version":2,"arm":"$arm","fixture_sha256":"$fixture_digest","staged_path":"$staged_copy","staging_boot_sha256":"$boot_digest","requires_reboot":true}
EOF
chmod 600 "$state_tmp"
mv "$state_tmp" "$state_file"
sync
printf '%s\n' 'Fixture staged and synced. Reboot the dedicated host before executing this one arm.'
