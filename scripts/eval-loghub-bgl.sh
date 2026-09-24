#!/usr/bin/env bash
set -euo pipefail

bgl_tmpdir="$(mktemp -d)"
trap 'rm -rf "$bgl_tmpdir"' EXIT
curl --fail --silent --show-error --location \
  'https://raw.githubusercontent.com/logpai/loghub/dd61d0952749ee7963bde24220d1be5ede023033/BGL/BGL_2k.log' \
  --output "$bgl_tmpdir/BGL_2k.log"
EVIDENTRAIL_BGL_2K_PATH="$bgl_tmpdir/BGL_2k.log" \
  cargo test -p evidentrail-cli loghub_bgl_sample_preserves_labeled_alert_lines \
  -- --ignored --nocapture
