#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  printf '%s\n' 'EVIDENTRAIL_QUALIFICATION_REQUIRES_MACOS' >&2
  exit 2
fi

hash_text() {
  printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

model="$(sysctl -n hw.model)"
cpu="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.machine)"
memory="$(sysctl -n hw.memsize)"
os_build="$(sw_vers -buildVersion)"
filesystem="$(diskutil info / | awk -F: '/File System Personality/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')"
boot="$(sysctl -n kern.boottime)"
dedicated="${EVIDENTRAIL_DEDICATED_REFERENCE_HOST:-0}"
authority="${EVIDENTRAIL_EXTERNAL_AUTHORITY_VERIFIED:-0}"

if pmset -g therm >/dev/null 2>&1; then thermal=true; else thermal=false; fi
if [ "$dedicated" = 1 ]; then dedicated_json=true; else dedicated_json=false; fi
if [ "$authority" = 1 ]; then authority_class=external_trusted_root; else authority_class=process_conformance_only; fi

cat <<EOF
{
  "contract_version": 2,
  "host_identity_commitment": "$(hash_text "$model|$cpu|$memory")",
  "boot_identity_commitment": "$(hash_text "$boot")",
  "os_build_commitment": "$(hash_text "$os_build")",
  "hardware_commitment": "$(hash_text "$model|$cpu|$memory")",
  "filesystem_commitment": "$(hash_text "$filesystem")",
  "dedicated_reference_host": $dedicated_json,
  "thermal_monitoring_available": $thermal,
  "authority": "$authority_class",
  "raw_nonsecret": {
    "model": "$model",
    "memory_bytes": $memory,
    "os_build": "$os_build",
    "filesystem": "$filesystem"
  }
}
EOF
