# Evidentrail product goal

Build Evidentrail into a connected log-selection tool for coding agents. A user
connects a read-only logging source once. Evidentrail ingests every record that
source makes accessible under its permissions and retention, keeps a durable
encrypted index up to date, and answers `evidentrail_logs(task, budget)` with a
small set of relevant **original log records** and exact repeat counts. The
user does not export logs or choose a time window. Models may choose which
evidence to inspect and return record IDs; they must never author the log text.

The product learns a versioned service graph from explicit log evidence and
uses it to find related service records. Each edge must link to its supporting
records. Feedback from accepted or expanded results may improve retrieval
only within an authorized tenant and only after measured evaluation; a query
must never silently train on untrusted log instructions.

## Completion contract

1. Ship a usable CLI onboarding flow for a new user: check prerequisites and
   read-only access without exposing secrets; discover and register CloudWatch
   or Datadog sources; show first-backfill progress, coverage, freshness, and
   permission status; guide a first query and expansion; and give actionable
   recovery and disconnect commands. Verify it from a clean installation.
2. Connect, enumerate, revoke, backfill, reconcile, and catch up real
   CloudWatch and Datadog sources. Use source-bound read-only credentials,
   durable checkpoints, deduplication, and explicit coverage/freshness states.
   Treat inaccessible, expired, or uncertain history as partial, and verify
   live credential changes, revocation, pagination, restarts, late arrivals,
   and Datadog Data Access Control behavior in sandbox accounts.
3. Give CLI and MCP the same connected query behavior. Check current source
   authority before selection, return only original source bytes and bounded
   references, and support source-verified expansion. Keep acquisition and
   uncertainty metadata separate from the log body.
4. Freeze independent held-out incidents before selector tuning. At matched
   log budgets, compare first-ID, severity, local-model, and guarded selectors
   with provider-native search and a no-logs control. Report required-evidence
   recall, independently labeled off-task logs, exact-source integrity,
   verified coding-agent fixes, graph ablation, latency, cost, and failures.
   Choose the default and local-only routing from downstream benefit, with
   rollback if a change regresses.
5. Exercise live provider sandboxes and the installed agent workflow, run
   security, scale, and CI tests, and document setup, permissions, cost controls,
   and known coverage limits. Do not call the product production-ready while
   these checks are unavailable or failing.
6. Once the connected path is verified, remove unused RCA/brief code,
   superseded commands, and stale documentation. Preserve exact provenance,
   authorization, retention, and test machinery that the new path needs.

Implementation details and current status live in
[`LOG_ONLY_PRODUCT_PLAN.md`](LOG_ONLY_PRODUCT_PLAN.md). This goal is the target
behavior, not a claim that every item has shipped.

## Execution directive

Work toward the completion contract as one product, not separate RCA and
log-compression tracks. Prioritize correctness of source coverage and access
control before retrieval quality, and retrieval quality before optimizing model
cost. At each change, name the user-visible behavior, test the relevant failure
case, update the implementation-status section of the plan, and keep claims in
the README limited to verified behavior. Use the smallest model that meets
measured quality and latency targets on held-out incidents; retain a local-only
route. Do not infer completeness from a successful page request or infer
current access from a cached credential check.

Only after real connected queries, expansion, revocation, and migration tests
pass should obsolete `brief`, `analyze`, RCA, and supplied-log prototype entry
points be removed. Delete their unreachable implementation, tests, generated
artifacts, and superseded documentation in the same cleanup phase, while
keeping shared source-fidelity, security, and evaluation components. Run the
workspace checks and a fresh installation smoke test after cleanup.
