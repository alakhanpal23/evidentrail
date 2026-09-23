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

1. Connect, enumerate, revoke, backfill, reconcile, and catch up real
   CloudWatch and Datadog sources. Use source-bound read-only credentials,
   durable checkpoints, deduplication, and explicit coverage/freshness states.
   Treat inaccessible, expired, or uncertain history as partial.
2. Give CLI and MCP the same connected query behavior. Check current source
   authority before selection, return only original source bytes and bounded
   references, and support source-verified expansion. Keep acquisition and
   uncertainty metadata separate from the log body.
3. Test frozen labeled corpora against a deterministic baseline at matched
   output budgets. Report required-evidence recall, irrelevant-log rate,
   downstream coding-task success, graph ablation, latency, cost, and failure
   cases. Choose local and hosted model routing from those results.
4. Exercise live provider sandboxes and the installed agent workflow, run
   security tests and CI, and document setup, permissions, cost controls, and
   known coverage limits. Do not call the product production-ready while these
   checks are unavailable or failing.
5. Once the connected path is verified, remove unused RCA/brief code,
   superseded commands, and stale documentation. Preserve exact provenance,
   authorization, retention, and test machinery that the new path needs.

Implementation details and current status live in
[`LOG_ONLY_PRODUCT_PLAN.md`](LOG_ONLY_PRODUCT_PLAN.md). This goal is the target
behavior, not a claim that every item has shipped.
