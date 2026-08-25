# Evidentrail local corpus inventory and admission boundary

**Status:** Metadata-only inventory; not a source approval or data-use grant  
**Snapshot date:** August 24, 2026  
**Applies with:** [Local data policy](./LOCAL_DATA_POLICY.md), [threat model](./THREAT_MODEL.md), and [greenfield execution program](./GREENFIELD_EXECUTION_PROGRAM.md)  
**Machine contract:** [`corpus-manifest-v1alpha1`](../schemas/corpus-manifest-v1alpha1.schema.json)

## Decision

No real local log discovered during this audit is admitted to Evidentrail, EvidentrailBench, ordinary CI, telemetry, a model provider, or model training.

The only committed manifest example is a synthetic-only case. It does not name or authorize a real local path. A row in this inventory is descriptive metadata, not consent. Code MUST NOT treat this document, a repository name, or filesystem proximity as an allowlist.

Wraith, its demos, and its generated assets remain a separate product and separate data boundary. Selected Wraith assets may become **opt-in external dogfood** only through a new, case-specific manifest and approval. Evidentrail has no standing permission to crawl, copy, relabel, publish, benchmark, or train on them.

## Audit method and limitations

The audit recorded path metadata, version-control status, approximate file/record/byte counts, format families, aggregate schema characteristics, and sensitivity-detector outcomes. No source content or excerpt was copied into this repository. Secret values and raw sensitive fields are intentionally absent from this document.

Counts are a point-in-time engineering estimate, not an integrity receipt. Small-file disk allocation can differ greatly from logical byte counts. Before any approved use, a materializer MUST independently regenerate a bounded file manifest and cryptographic receipts without trusting these numbers.

Paths use `~/` to avoid publishing the workstation account name. Every listed real path is inactive unless a later signed manifest says otherwise.

## Classification boundary

Evidentrail applies the classes defined in the local data policy:

| Class | Meaning in this inventory | Repository/CI rule |
| --- | --- | --- |
| C0 | Public material or deliberately authored synthetic fixtures with confirmed provenance and publication rights | May be committed only after review and integrity pinning |
| C1 | Closed-schema, contentless operational facts | May be emitted only through the C1 allowlist; a corpus is not automatically C1 |
| C2 | Sensitive source metadata, identities, paths, cursors, and high-cardinality scope | Local by default; never ordinary telemetry |
| C3 | Raw or derived log/diagnostic content, including redacted content, questions, and evidence | Local encrypted boundary unless separately approved |
| C4 | C2/C3 plus labels, outcomes, provenance, split assignments, consent, and retention terms | Governed external store; never ordinary product CI |

Version control is not proof that a fixture is synthetic, licensed, de-identified, or safe to publish. A tracked Wraith fixture remains external to Evidentrail until ownership, authorship, license, secret scanning, and intended use are attested.

## Audited candidate sources

The following metadata describes potential engineering value and risk. `Quarantined` means no read or reuse by Evidentrail until a separate approval; `Prohibited` means the source category cannot be admitted through the ordinary corpus process.

| Inventory ID | Source family and snapshot metadata | Format/schema characteristics | Risk and provisional class | Suitability and decision |
| --- | --- | --- | --- | --- |
| LC-001 | `~/WraithOnCallEngineer/tests/fixtures/`: 19 tracked files, about 27,412 logical bytes | Small provider-shaped CloudWatch, Datadog, and PagerDuty fixtures | Provenance and publication rights still need attestation; treat as external C3 until proved synthetic C0 | High value for deterministic adapter contracts after case-by-case review; **quarantined external dogfood** |
| LC-002 | `~/WraithOnCallEngineer/packages/replay-cli/src/__tests__/fixtures/`: 3 tracked trace bundles, 12 tracked files; 24 filesystem entries when ignored artifacts are included | JSONL events plus metadata and blob members | Ignored duplicates/artifacts must never enter by directory crawl; external C3 pending provenance review | Good replay and bundle-integrity candidate using tracked members only; **quarantined external dogfood** |
| LC-003 | `~/WraithOnCallEngineer/packages/demo-app-realistic/traces/`: 2 tracked baseline/buggy traces, 10 tracked files, 11 event rows, about 4,976 event bytes | Small paired trace bundles with known scenario structure | Identity-shaped test values were detected in 3 files; redaction and authorship review required | Useful for healthy/incident contrasts after sanitation; **quarantined external dogfood** |
| LC-004 | `~/WraithOnCallEngineer/traces/`: 37,372 untracked files, about 16.6 MB logical bytes and about 146 MB allocated; 12,446 event files with 24,908 rows, 12,446 metadata files, and 12,477 blobs | JSONL event streams, trace metadata, and blobs; 12,221 trace-ID groups reduced to 34 coarse normalized families; 456 older events lacked a trace ID; 111 error objects contained multiline stacks | Generated/untracked provenance is not formalized; blobs and stack data are C3; high duplication can cause split leakage | Useful only for local throughput, small-file, multiline, legacy-schema, and deduplication dogfood; **quarantined and excluded from benchmark/training** |
| LC-005 | `~/wraith-demo/backend/traces/`: 171 event files, 453 rows, about 311,815 event bytes | Trace-bundle JSONL; about 28 coarse normalized content groups | Demo origin does not establish publication or benchmark rights | Potential deterministic stress/deduplication input after approval; **quarantined external dogfood** |
| LC-006 | `~/wraith-demo-stack/services/**/traces/`: 566 event files, 1,132 rows, about 526,838 event bytes, and 695 blobs | Multi-service trace bundles with typed fields and blob payloads | Identity/contact-shaped fields were detected in 251 files; customer-like and cross-service context risk; C3 | Valuable for multi-service correlation only after targeted generation or full sanitation; **restricted quarantine** |
| LC-007 | `~/agenticwraith/tests/eval/`: 21 gold scenarios plus 1 smoke scenario, 91 tracked files, about 91,722 bytes | Scenario definitions, expectations, and derived evaluation material rather than a clean raw-log corpus | Labels and expected outcomes can leak task answers; C4 if joined to evidence | Useful as a taxonomy reference, not as proof of Evidentrail quality and not as a raw-log benchmark; **external design reference only** |
| LC-008 | `~/WraithOnCallEngineer/.wraith/autofix/`: 29 cases, including 25 context objects, 20 patches, and only 2 verification reports | Derived context, code patches, and sparse outcome artifacts | May contain source code, incident context, model output, and unverified fixes; C3/C4 | Unsuitable for a gold benchmark without provenance and verified outcomes; **restricted quarantine** |
| LC-009 | `~/kara-diamond-growth-platform/`: 112 `.log` files, about 175,454 bytes and 5,327 lines; 23 byte-unique files; 46 files parse as JSON objects, with some empty artifacts | Mixed plain text, ANSI terminal output, and JSON status/result objects | Proprietary first-party operational content; may contain business, account, and workflow context; C3 | May test framing locally only under a separate business-owner approval; **excluded by default** |

The normalization counts above are coarse audit signals, not ground-truth templates. They must not be used as labels, parser-quality claims, or split keys without a reproducible derivation and review.

## Explicitly prohibited ambient sources

The following sources MUST NOT be discovered, sampled, globbed, manifested, benchmarked, exported, or used for training through Evidentrail's normal corpus workflow:

- `~/.codex/sessions/**`: 331 JSONL files and approximately 12.7 GB logical bytes at audit time; contains conversations, prompts, tool I/O, and potentially credentials or private data.
- `~/.claude/projects/**`: 1,237 files and approximately 371 MB; contains agent histories and project context.
- `~/.cursor/projects/**` and `~/.cursor/ai-tracking/**`: approximately 450 project-state files/8.7 MB and 196 MB of tracking state; contains IDE and agent context.
- `~/.claude-science/logs/**`: 4 files and approximately 1.85 MB; ambient agent/application diagnostics.
- Any Wraith `.gstack/**` browser or automation logs: approximately 2.7 MB in the audited repository; may contain URLs, page data, browser state, and identities.
- `~/.npm/_logs/**`, Yarn logs, Screen Studio logs, browser logs/profiles, application support logs, crash reports, and `~/Library/Logs/**` unless a future product binding explicitly targets a bounded source for the user's immediate investigation. They are never corpus candidates by discovery.
- Shell histories, clipboard databases, terminal scrollback, chat histories, email stores, browser profiles, cookies, keychains, and credential-manager databases.
- `~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**`, cloud credential/config directories, `.env*`, private keys, certificates with private material, auth tokens, and secret stores.
- Evidentrail's own snapshot, key-envelope, operational-log, telemetry-queue, support-bundle, and temporary directories. This prevents recursive ingestion and privilege elevation.

These are categorical denies even when a file extension looks like a log or JSONL file. The manifest validator SHOULD reject known ambient roots and credential patterns, and the materializer MUST re-check canonical paths after opening each member.

## Wraith boundary: opt-in external dogfood only

Evidentrail and Wraith remain separate products and repositories. The Wraith inventory entries provide no dependency, ownership transfer, license grant, or data-use permission.

A Wraith dogfood case can be admitted only when all of the following happen:

1. A human selects one bounded fixture/case; directory-wide and recursive enrollment remain off.
2. The Wraith owner attests whether it is deliberately synthetic or governed real data and records the authorization basis.
3. The source is materialized outside both products' active runtime stores, with immutable membership and hashes.
4. Secret and personal-data scanning, redaction, and exactness-basis review complete with zero unresolved high-confidence findings.
5. Local processing, persistence, benchmark use, human review, external judging, publication, telemetry content, and model training are decided independently.
6. Variants sharing a generator, incident, trace lineage, or normalized family receive the same `family_id` and cannot cross a split boundary.
7. Revocation can find and disable every derived case, report, annotation, cache, and export through the lineage root.

Until then, Wraith assets may inform a format taxonomy through this aggregate inventory only. They MUST NOT be copied under `fixtures/`, run in ordinary CI, or cited as Evidentrail benchmark results.

## Corpus admission state machine

```text
metadata candidate
  -> explicit bounded proposal
  -> provenance and rights review
  -> purpose-specific consent receipt
  -> isolated materialization
  -> secret/PII scan and policy redaction
  -> integrity + split-leakage checks
  -> approved manifest and governed storage
  -> allowed evaluation use
  -> revoke/expire -> stop use -> destroy keys -> delete derivatives -> receipt
```

No transition may be inferred from successful local processing. A failure or missing receipt returns the case to quarantine.

### Required pre-read boundary

Before approval, tooling may read only metadata explicitly permitted by the local data policy. It MUST NOT sample bytes to guess relevance or format. The proposal must show the canonical root, resolved members, recursion depth, file/record/byte/time caps, storage mode, retention, and requested purposes.

### Required manifest identities

Every admitted case has all of these stable identities:

- `manifest_id` and revision for the policy decision;
- `corpus_id` and `case_id` for evaluation accounting;
- `family_id` for every variant that could leak across splits;
- opaque project, organization, provider, time-bucket, fault-family, and deduplication split keys;
- source-spec, source-artifact, post-policy artifact, schema, redaction-policy, redaction-receipt, privacy-scan, consent-receipt, revocation-state, and annotation hashes;
- one lineage root shared by every derived artifact and export.

Hashes establish identity, not safety or consent. Content-derived hashes are C2/C3 and must not appear in product telemetry.

### Purpose and consent isolation

The schema records separate grants for:

- local processing;
- local persistence;
- benchmark/evaluation use;
- human review;
- remote processing;
- external model judging;
- publication;
- content-bearing telemetry; and
- model training.

All default to denied in product UX. Evaluation permission does not imply training, and model training remains denied during the deterministic product phase. Synthetic authorship is still captured as a policy receipt so the same enforcement path is exercised.

### Revocation and retention

Every manifest carries a revocation status and a hash of the current revocation-state record. Revocation stops new use immediately. Governed storage then destroys access keys before best-effort deletion of source copies, redacted artifacts, annotations, indexes, benchmark caches, reports, and exports. A revoked case remains represented only by the minimum non-content tombstone needed to prevent re-import.

## Split and benchmark rules

Splits are assigned after family and near-duplicate grouping, never by random file. All variants from the same incident, generator seed family, repository change, trace lineage, or deduplication group MUST remain in one split.

The benchmark should hold out along multiple axes:

- project and organization;
- time bucket;
- provider/format family;
- fault family;
- generator family and seed lineage; and
- near-duplicate content family.

`private_test` labels stay outside implementation-owner access. `public_test`, `private_test`, and `conformance` cases cannot grant model-training use. Reports identify the exact manifest revisions and aggregate by case/family so duplicated rows cannot inflate confidence.

Unlabeled dogfood may measure losslessness, framing, format drift, throughput, caps, and partial-result honesty. It does not measure verified diagnosis success without an authentic question, independently verified cause and fix, required-evidence labels, and outcome data.

## Recommended local-first corpus portfolio

1. **Committed synthetic contract fixtures (C0):** deliberately authored cases for byte exactness, invalid UTF-8, multiline blocks, rotation, malformed JSONL, overmerge, secret boundaries, caps, and prompt injection.
2. **Hermetic incident lab (C0/C4 metadata):** reproducible services and controlled faults with generator revision, seed, known impact, exact cause, verified fix, and family-preserving splits.
3. **Pinned public datasets (C0/C4 metadata):** fetched outside the repository with origin, license, version, checksum, notices, and acquisition recipe.
4. **Opt-in external dogfood (C3/C4):** Wraith or other owner-approved cases in encrypted local/governed storage, never ordinary CI and never training by default.
5. **Consented design-partner incidents (C4):** external encrypted store, least privilege, hidden labels, case-level retention/revocation, and only aggregate public reports.

The synthetic and hermetic tiers should carry release gates. External dogfood should initially target adapter correctness and worst-slice discovery. Real incidents should enter only after the deterministic evidence contract and governance machinery pass their release gates.

## Example status

[`fixtures/manifests/synthetic-local-ci-example.manifest.json`](../fixtures/manifests/synthetic-local-ci-example.manifest.json) demonstrates the contract with a generator-only locator, synthetic classification, no real local root, training disabled, family-safe conformance split, and explicit consent/revocation/redaction receipts. It is illustrative metadata, not a materialized log fixture.
