# Hosted-ranking test authorization

**Authorization ID:** `evidentrail-hosted-ranking-synthetic-openai-v1`  
**Effective date:** 2026-09-01  
**Status:** active, narrowly scoped project-owner authorization

This authorization governs the frozen synthetic benchmark. Separately approved,
case-scoped governed-incident testing is recorded in
[`HOSTED_PRODUCTION_SHADOW_AUTHORIZATION.md`](HOSTED_PRODUCTION_SHADOW_AUTHORIZATION.md).

## Authorized use

- Purpose: internal shadow testing and explicit opt-in beta evaluation of the
  hosted evidence-ranking path.
- Destination: the OpenAI Responses API through Evidentrail's pinned adapter.
- Data: generated synthetic fixtures and other inputs that the operator has
  affirmatively verified contain no sensitive, personal, customer, secret,
  proprietary, or production-derived content.
- Invocation: only an explicit `--llm-rank`, `--llm-rank-if-contended`, or MCP
  `ranking_mode: "hosted"`/`"hosted_if_contended"` request. Deterministic mode
  remains the default.
- Application retention: no prompt or response persistence; only the closed
  contentless diagnostic record may be emitted.
- Training: not authorized.

## Not authorized

This authorization does not cover real customer or production logs, local
application/IDE/agent histories, credentials, personal data, private source
code, support artifacts, hidden incidents, benchmark labels, or any input that
has not been affirmatively classified as non-sensitive. It does not authorize
another model provider, a public rollout, default-on egress, model training, or
provider-side behavior beyond the configured `store: false` request.

## Technical enforcement and revocation

The existing 32-block and 40-KiB escaped-payload bounds, 800-ms deadline,
strict complete-permutation validation, deterministic fallback, contentless
diagnostics, and memory-only surface remain mandatory. Set
`EVIDENTRAIL_HOSTED_RANKING_DISABLED=1` and restart the process to stop new
hosted calls immediately. Removing or superseding this authorization revokes
future synthetic test use; it grants no authority over previously independent
provider retention obligations.

## Provenance and remaining review

The project owner explicitly approved hosted egress for synthetic/non-sensitive
test logs in the product-development session on 2026-09-01. This records that
scope; it is not a substitute for organizational privacy, security, legal, or
data-processing review. Those reviews and separate case-level consent remain
required before any real or private incident is sent.
