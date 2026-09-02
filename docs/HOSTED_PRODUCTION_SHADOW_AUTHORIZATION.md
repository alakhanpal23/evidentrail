# Hosted production-shadow authorization

**Authorization ID:** `evidentrail-hosted-production-shadow-openai-v1`

**Effective date:** 2026-09-02

**Status:** active, case-scoped project-owner authorization

## Authorized use

The project owner has explicitly authorized real OpenAI API calls for
production-shadow evaluation. A governed incident is in scope only when the
operator deliberately places it in the protected external corpus and its
manifest simultaneously declares:

- `ranking_mode: "hosted"`;
- `local_processing_only: false`;
- `hosted_egress: true`;
- `hosted_egress_authorization: "operator_approved_openai_responses_v1"`;
- `hosted_egress_approved: true` for that individual case.

The only authorized destination is Evidentrail's pinned OpenAI Responses API
adapter. Application processing is memory-only. The provider request uses
`store:false`, no tools or conversation history, strict structured output, and
the production 800 ms deadline without retry. Evidentrail emits only its closed
contentless diagnostic schema.

## Operator responsibility

This authorization records the project owner's instruction to implement and
exercise real hosted calls. It does not establish that the operator owns or may
disclose any particular customer's data, and it is not a substitute for an
organization's privacy, security, legal, contractual, or data-processing
review. The operator must remove secrets and personal data unless their
specific provider agreement and internal approval permit that transfer.

Do not add governed incidents, questions, evidence labels, or reports to this
repository or ordinary CI. Keep them under the protected external corpus root.

## Revocation and admission boundary

Set `EVIDENTRAIL_HOSTED_RANKING_DISABLED=1` and stop the runner to prevent new
calls. Hosted ranking remains default-off and unqualified. This authorization
permits evaluation; it does not permit default-on product rollout or a claim
that model ranking improves accuracy.
