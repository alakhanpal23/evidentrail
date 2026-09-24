# Connected retrieval learning route

Version 1 is a bounded, source-local challenger. The default connected route is unchanged. Each encrypted corpus stores its own training records and route registry under its tenant and source binding. The connected caller checks registration and provider access before opening that corpus; an inaccessible or disconnected source contributes neither candidates nor learned signals.

## Signals and attribution

- A `useful` or `not_useful` click is an observation tied to a selected record, task digest, and result nonce. It is weak feedback. The legacy feedback snapshots remain inspectable, but they no longer alter connected selection.
- A verified repair is a case outcome tied to a task digest and verifier digest. It does not imply that any particular selected line helped. `record_verified_case_outcome` stores it separately from record labels.
- An independently reviewed record-level `Relevant` or `Irrelevant` label has a case ID, split, and provenance digest. Only development labels enter the memory score. Held-out labels stay excluded from training. The labeling process must be blind to route arm and must exclude held-out cases. There is no automatic conversion from ratings or successful repairs to labels.

The challenger examines at most 256 groups already found by the existing lexical, severity, directory, and graph retrieval. It requires at least two distinct positive cases sharing a query term with the current task. A matching negative case suppresses the boost. The score is capped at four and only reorders candidates; selected output still resolves to original stored records and obeys the existing raw-byte budget. Sparse or conflicting labels yield zero boost. This deliberately cannot rescue a log absent from the candidate pool.

`shadow_memory_candidates` in connected metadata counts matches even when the challenger is inactive. Shadow evaluation does not change the returned pack or call a second model. A promoted route can reorder eligible candidates before the existing selector. Changing labels, revoking a label, deleting a source, or changing the derived parser mapping invalidates its training fingerprint. The connected caller must successfully reauthorize and synchronize the source before any route operation. Rollback changes the active pointer in one SQL transaction; it refuses a stale parent. If the active fingerprint becomes stale, selection immediately falls back to the current route.

## Registry and commands

Each source registry row records a monotonically increasing version, parent version, route selector identity, trial model identity, SHA-256 training fingerprint, SHA-256 evaluation report digest, held-out gate result, and shadow/active/retired status. The selector identity comes from the frozen `challenger_route` field; `model_id` records the pinned repair-agent model used for the paired study. Both exact identities must be present in the study report.

```sh
evidentrail sources route label --source-id SOURCE_ID --case-id CASE --task TEXT --native-id BASE64URL --label relevant --split development --provenance-sha256 ANNOTATION_SHA256
evidentrail sources route outcome --source-id SOURCE_ID --case-id CASE --task TEXT --repaired true --provenance-sha256 VERIFIER_SHA256

python3 scripts/score-learning-route.py --manifest study.json --verify-only > verified-results.jsonl
python3 scripts/score-learning-route.py --manifest study.json --results verified-results.jsonl > report.json

evidentrail sources route evaluate --source-id SOURCE_ID --manifest study.json --results verified-results.jsonl --report report.json
evidentrail sources route inspect --source-id SOURCE_ID --version N
evidentrail sources route promote --source-id SOURCE_ID --version N
evidentrail sources route rollback --source-id SOURCE_ID
```

`evaluate` reruns the bundled verifier and scorer against the frozen workspaces, requires the supplied report to match, and registers a shadow version after checking the numerical held-out gate. It does not activate it. `promote` requires a passing report and an unchanged training fingerprint. The learning study adds a sixth `challenger_no_memory` arm to each Prompt 1 case and a nonempty `challenger_no_memory_route` identity at the manifest top level. Its log pack must be frozen and its repair trial run under the same budget, model, and verifier. Promotion requires this paired memory ablation to beat memory-off at one-sided exact p <= 0.01 with no memory-off-only successes. The operator is responsible for supplying the report produced by the verifier/scorer and reviewing case provenance; the verifier reruns regression commands from the supplied manifest, so evaluate only trusted local study workspaces. Never promote a report assembled from ratings, synthetic retrieval fixtures, or development cases. Scope is one source; every source requires its own evaluation and explicit promotion. A promoted source does not transfer labels to other sources.

The legacy `sources feedback promote` command changes only its feedback snapshot. It has no connected-selection effect. Use `sources route` for the new policy.

## Evaluation contract

Freeze development and held-out tasks before tuning. Use the Prompt 1 manifest and verifier: at least ten held-out cases spanning three projects and three fault families, no development overlap, identical raw-log budgets and coding-agent model, all six paired arms, immutable packs, and exact source bytes. Report log-level evidence recall and irrelevant logs from separately labeled records; report source fidelity, verified repair rate, latency, model calls, and estimated cost for every arm. Compare memory-on against the same challenger with memory disabled to isolate cross-task value. Only verified held-out downstream improvements may qualify for promotion. The frozen synthetic retrieval suite is a development diagnostic, not evidence of repair benefit.
