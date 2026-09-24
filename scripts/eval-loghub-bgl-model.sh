#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${EVIDENTRAIL_COMPACT_LOCAL_MODEL:-}" && -z "${OPENAI_API_KEY:-}" ]]; then
  echo 'Set EVIDENTRAIL_COMPACT_LOCAL_MODEL (running Ollama) or OPENAI_API_KEY before running this live-model evaluation.' >&2
  exit 2
fi

bgl_tmpdir="$(mktemp -d)"
trap 'rm -rf "$bgl_tmpdir"' EXIT
curl --fail --silent --show-error --location \
  'https://raw.githubusercontent.com/logpai/loghub/dd61d0952749ee7963bde24220d1be5ede023033/BGL/BGL_2k.log' \
  --output "$bgl_tmpdir/BGL_2k.log"
EVIDENTRAIL_BGL_2K_PATH="$bgl_tmpdir/BGL_2k.log" \
EVIDENTRAIL_RUN_BGL_MODEL_EVAL=1 \
  cargo test -p evidentrail-cli --lib loghub_bgl_live_model_selection_eval \
  -- --ignored --nocapture
