# Evidentrail

Evidentrail is a greenfield diagnostic evidence compiler for coding agents. It turns
one bounded log acquisition into the smallest auditable evidence set that
preserves the debugging outcome, exposes every loss boundary, and expands each
retained reference exactly relative to its declared authorization basis.

The old Evidentrail implementations, including `legacy-drain`, are external benchmark
competitors only. This workspace does not depend on, wrap, copy, or call them.

The product method is specified in
[`docs/GREENFIELD_EXECUTION_PROGRAM.md`](docs/GREENFIELD_EXECUTION_PROGRAM.md),
the primary-source method ledger in
[`docs/RESEARCH_LEDGER.md`](docs/RESEARCH_LEDGER.md),
the current competitor teardown in
[`docs/EVIDENTRAIL_COMPETITIVE_TEARDOWN.md`](docs/EVIDENTRAIL_COMPETITIVE_TEARDOWN.md),
the evaluation in [`docs/EVIDENTRAILBENCH_PROTOCOL.md`](docs/EVIDENTRAILBENCH_PROTOCOL.md),
the output contract in [`docs/LOG_BRIEF_CONTRACT.md`](docs/LOG_BRIEF_CONTRACT.md),
the wire/product contract plan in
[`docs/WIRE_CONTRACT_PLAN.md`](docs/WIRE_CONTRACT_PLAN.md),
the defensibility plan in [`docs/PRODUCT_MOAT.md`](docs/PRODUCT_MOAT.md),
the speed and LLM-assistance roadmap in
[`docs/PRODUCT_ROADMAP.md`](docs/PRODUCT_ROADMAP.md),
and the current engineering truth in
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md).
The benchmark-only executable coding-agent outcome loop is described in
[`docs/EXECUTABLE_INCIDENT_LAB.md`](docs/EXECUTABLE_INCIDENT_LAB.md).

## Current status

This repository contains a tested **deterministic product core**, not a
finished product and not a validated performance claim. It currently provides:

- an internal streaming V3 path with a generic retained-event-store boundary,
  incremental explicit-input parsing up to 1,000,000 records or 1 GiB, packed
  memory retention, checkpoint-sized immutable encrypted durable packs with
  independent page frames and an encrypted exact-lookup directory,
  deterministic
  block-boundary analysis partitions, and a bounded global reducer that avoids
  treating total partition count as `PrimaryBlockCountCap`; rollout remains
  gated because the packed-layout native screen has not yet been rerun (the
  superseded one-object layout failed), and signed-Keychain plus independently
  adjudicated external-corpus certification remain outstanding,
  as recorded in
  [`docs/STREAMING_PRODUCT_V3.md`](docs/STREAMING_PRODUCT_V3.md);

- versioned raw-envelope and fetch-completion vocabulary with typed source,
  member, stream, cursor, timestamp, fragment, cap, completeness, native-ID,
  and closed provider-attestation facts;
- a bounded streaming adapter path whose only payload consumer is an
  acknowledging policy-aware ledger sink;
- an immutable authorized-basis byte ledger with separate acquisition and
  presentation receipts, exact expansion, and contentless diagnostics;
- source-lane-correct atomic block reconciliation, including interleaved
  streams, plus a conservative byte-only framer for common stack traces,
  compiler failures, assertions, and test diffs;
- canonical, byte-exact local-file approval and query-plan schemas that bind one
  literal locator, snapshot, repository, policy, runtime profile, caps, and
  execution interval, plus cooperative deadline semantics;
- deterministic exact passthrough: if the complete authorized result fits the
  full rendered-token budget, it is returned without log reduction;
- a fixed-TTL memory result lifecycle with atomic event references and bounded
  result-scoped expansion, including an atomic retained-result transition from
  a passthrough miss to a whole-render-certified compiled brief and a
  same-question resume path that preserves the original budget and expiry;
- repository-scoped live binding and internal-path registries, plus a
  descriptor-relative, zero-content-read local-file preflight that checks exact
  snapshots, symlinks, hard-link aliases, APFS, expiry, and replacement races,
  followed by retained-descriptor, byte-exact, no-read-ahead streaming in the
  governed test path; `evidentrail doctor --file PATH` now runs a frozen 13-cell
  macOS/APFS host matrix and inspects only metadata for that one explicit file,
  returning a contentless receipt while still denying authorization,
  certification, and production preflight admission;
- three deterministic evidence lanes—lexical plus validated identifiers,
  failure/onset/raw coverage, and narrowly scoped provider-attested
  correlations—compiled onto one exhaustive, event-disjoint primary packet
  universe;
- a one-call deterministic product path that tries exact passthrough first and,
  only when necessary, runs the three lanes, certifies renderer-derived packet
  costs, selects under the complete render budget, and returns a compiled brief
  or an honest retained `needs_more` result; the budget-independent proposal
  universe is receipted before ranking, exposed through a redacted product
  audit, and reused byte-for-byte on same-question resume;
- a label-blind public EvidentrailBench runner, governed hidden-label evaluation, and
  deterministic raw-truncation, grep/head/tail, reserved-quota, and bounded
  fixed-point BM25F-style whole-event baselines with five-dimensional resource
  accounting; producer-proposal evaluation now
  freezes the complete public universe before labels, renders it through one
  reversible canonical byte artifact, binds self-asserted token/time/RSS
  observations to that exact artifact, enforces all five cap axes, and reports
  weighted requirement recall and Pareto relations without a scalar winner;
  a two-stage configured-producer frontier preregisters exact universes, caps,
  method family, acquisition, and measurement environment before labels, keeps
  every infeasible point, and admits only cap-eligible non-dominated points;
  opt-in instrumentation also freezes production-identical Full and exact
  WithoutLexical/WithoutCoverage/WithoutProvider universes while leaving the
  default product path unchanged; the unchanged six-case governed corpus now
  records every proposal, selection, exact render/reference join, oracle budget,
  non-perfect attribution, and matched cheap baseline at the Full arm's selected
  unique authorized-source-byte budget; all oracle-feasible Full cases recover
  their required evidence, while the deliberately tiny partial case remains an
  honest `needs_more`; a separate benchmark-only exact subset oracle evaluates
  the production selection problem whenever it has at most 12 optional packets,
  binds the oracle policy and cap into every case and aggregate receipt, and
  finds zero integer objective regret on all five feasible frozen Full cases.
  The independently joined optimum packet sets preserve the same governed
  evidence outcomes as production (3/3, 5/5, 7/7, 9/9, and 13/13), while the
  sixth case matches production's fixed-overhead `needs_more`; this remains a
  six-case conformance result, not an approximation-factor or population claim.
  A separate label-blind perturbation corpus freezes 13 hand-authored problems
  across seven selector/fault families before its governed join: eight are
  exact-zero regret, two expose deterministic positive regret, two are typed
  `needs_more`, and one exceeds the exact-oracle cap. The positive witnesses are
  a density/knapsack trap (400,000 objective units) and a dynamic breadth-slice
  admission-order trap (500,000 units); they motivate a bounded deterministic
  challenger, not learned ranking or a population claim. That evaluation-only
  challenger now uses exact subsets through 12 optional packets and a bounded
  order-aware beam with production fallback above that cap. Across the frozen
  19-case comparison it fixes both positive-regret witnesses with no objective
  regression, but at higher selected cost. A separate eight-case, seven-family,
  14–65-packet stress corpus therefore holds selected cost and coverage charge
  exactly equal to production: the challenger is objective- and recall-better
  in three cases, equal in five, and worse in none; it matches the structured
  exact DP optimum in all six eligible cases. Production remains unchanged
  pending measured wall/RSS and non-synthetic evidence. A separate frozen
  eight-case/eight-runtime hermetic incident corpus covers six complete
  diagnoses plus one partial and one unknown acquisition that must abstain. At
  identical per-case Full-selected authorized-source-byte budgets, Full and the
  exact subset oracle each score 8.0/8.0 exact recall with 8/8 perfect cases;
  raw truncation scores 1.9/8.0 with 0/8 perfect, grep/head/tail 4.2/8.0 with
  3/8, quota hybrid 4.9/8.0 with 3/8, and BM25F-style 1.9/8.0 with 1/8. This is
  synthetic conformance evidence, not a general incident-quality claim;
- a benchmark-only executable incident episode that runs three deterministic
  fault families twice through the bounded subprocess boundary, freezes exact
  20-KiB-class logs, prepares Evidentrail/grep-head-tail/raw-prefix arms under one
  7,000-byte budget, executes a strict agent protocol, verifies proposed repair
  invariants in a second process, and joins hidden cause/citation/claim truth
  only afterward. The conformance agent repairs all three Evidentrail arms; the raw
  prefix honestly loses the deliberately late database-pool precursor, while
  grep/head-tail repairs that fixture without gaining source-exact citation
  authority. One read-only local Codex CLI exploration also solved all three
  Evidentrail artifacts, but is not preregistered or a comparative quality claim;
- a benchmark-only, shell-free external subprocess harness and reproducible
  smoke runs against one pinned `legacy-drain` executable, including a forced
  compiled-path 200-event case; the same-case proposal bridge freezes the exact
  14-packet first-party production universe and a separately charged eight-group
  Drain occurrence-complete upper bound without calling Drain patterns
  source-exact evidence or an original pre-ranking API; plus a
  governed representation-fidelity bridge that refuses to turn unverified
  patterns or transformed samples into static recall, and a typed matched-run
  envelope that retains both methods' complete five-dimensional resource
  vectors, binds a typed first-party policy identity, and reports repeated
  direct-process wall/RSS observations without a scalar, quality, cold-start,
  child-tree, hosted-Evidentrail, or independent-attestation claim. An actual pinned
  same-case deterministic reader run uses identical reader configuration and
  produces the same 308-byte answer from 29,018 first-party versus 360,361
  Drain prompt-byte units; the first-party answer has two source-exact citations
  while Drain's transformed pattern output has no source-exact citation
  capability. This is one provenance/result checkpoint, not a general quality
  win. A production-owned but default-off compact candidate renderer now has
  exact text, alias, target, byte-range, and reversible-event parity with the
  benchmark representation across nine rendered cases plus two typed
  `needs_more` cases. It reduces 28,261 canonical bytes to 16,834 bytes
  (40.43%); a separate hostile-byte challenge reduces 16,737 to 12,077 bytes
  while preserving 16 citations and 23 exact events. One captured paired reader
  run preserved the exact answer and both citations, but is one-shot,
  self-asserted, direct-process-only evidence with no hosted reader or
  performance ordering. The canonical CLI/MCP output remains unchanged;
- an internal authenticated snapshot-format primitive with fixed-width
  XChaCha20-Poly1305 frames and manifest envelope, canonical AAD, commitment
  chaining, one zeroizing per-result DEK shared by frame and manifest key
  views, a result-wide nonce registry, injected/OS entropy, and
  domain-separated per-result HKDF wrapping/seal keys plus fixed-width AEAD
  DEK-wrap and final manifest/chain-binding envelopes, wrapped by a canonical
  Creating/Sealed result-key record with an authenticated idempotent transition;
  a state-oriented bounded key-provider contract implements atomic create,
  open, seal, list, and crypto-erasing destroy semantics without exposing raw
  keys, while its only current implementation is internal/test-only; an exact
  untrusted `public.v1` cleanup hint, segment catalog, catalog-bound EventId
  expansion index, receipt-ordered source-outcome table, and self-restoring
  acquisition-completion record compose the deterministic core manifest; a
  transactional memory repository derives real frame locators/ranges, rejects
  unindexed authorized-event frames, reconciles the exact catalog and index
  before publication, and authenticates a complete event frame before returning
  zeroizing basis-exact bytes. Authenticated sealed results can also be exported
  and re-imported as one canonical, strictly bounded ciphertext-only bundle: its
  fixed header and contiguous segment/frame directory reject gaps, aliases,
  reordering, substitution, truncation, trailing data, and allocation lies, and
  import authenticates the independently existing sealed key authority and full
  manifest/catalog/frame chain before atomic in-memory publication. This is a
  transport primitive. A Unix ciphertext-only filesystem substrate now adds a
  canonical 0700 root, ResultId-derived 0600 files, same-directory
  create-exclusive temporaries, bounded exact writes, file-sync then atomic
  no-replace rename then directory-sync ordering, strict inode/metadata
  readback, and bounded create-only quarantine recovery. It performs structural
  bundle decoding only; authenticated admission remains the repository import
  boundary, and it makes no sudden-power-loss durability, rollback-prevention,
  cross-process-locking, authenticated-recovery, or product-publication claim. A
  provider-generic post-render retention adapter
  can now migrate a finalized passthrough or compiled memory result into that
  repository, delete the plaintext ledger only after the encrypted result is
  sealed, preserve only store-issued exact capabilities and displayed aliases,
  and serve atomic zeroizing exact expansion until fixed expiry. Frozen vectors
  and adversarial tests cover multi-segment offsets, arbitrary and post-policy
  bytes, forged/cross-result capabilities, cap failure without prefixes,
  substitution, mutation, truncation, destruction, and staged invisibility. A
  domain-tagged encrypted displayed-alias manifest now binds each exact `E<n>`
  to its recomputable store-issued reference, result, expiry, and ordered event
  targets. An authenticated filesystem restart coordinator independently
  preflights provider authority, fully authenticates the canonical bundle and
  alias manifest before visibility, quarantines invalid candidates, and returns
  a narrow exact-alias-only recovered handle after all original product, ledger,
  render, and source owners are dropped. It still makes no Keychain,
  rollback-prevention, cross-process-locking, or sudden-power-loss claim;
  and
- an event-disjoint deterministic selector using production-only facets,
  certified composable cost bounds, and monotone top-k facility coverage with
  density-greedy-plus-best-single selection; provider-attested relations admit
  two half-weight contributions from distinct packets while every other facet
  remains top-one, fixing the frozen corpus's two oracle-feasible objective
  saturation misses without a pair bonus; source/service/time breadth facets
  carry one-quarter diagnostic weight and pure breadth gain is charged to a
  separately audited one-eighth optional-token slice, so coverage sentinels
  cannot crowd out stronger diagnostic evidence; the frozen set is presented
  diagnostic-first with canonical semantic role codes and exact
  presentation-order marginal accounting; and
- a bounded memory-only `evidentrail brief` entry point that reads only explicit
  standard input, preserves arbitrary bytes and source terminators, uses fresh
  result identity randomness, and emits only the canonical passthrough or
  compiled artifact. It does not discover files, inspect ambient logs, persist
  results, or invoke a model; an unfit budget exits honestly as `needs_more`.
  The same library path can instead return a resident memory session that keeps
  exact result-scoped alias expansion available until the fixed TTL, without
  claiming persistence or changing the one-shot binary behavior; and a
  `evidentrail serve-mcp` process exposes that same path as the `evidentrail_logs` and
  `evidentrail_expand` tools over bounded newline-delimited JSON-RPC. It implements
  MCP 2026-07-28 discovery/per-request metadata plus a 2025-11-25 initialize
  fallback, accepts only caller-supplied canonical Base64 log bytes, retains at
  most 32 successful results and 64 MiB of aggregate source bytes for their
  fixed 30-minute TTL, and loses all sessions at process exit. It does not
  discover a path, invoke a model, or claim durable/cross-process expansion.
  Memory remains the default. On macOS, explicit `--retention durable` uses the
  data-protection Keychain authority and authenticated startup reconciliation;
  a provisioned release signature is required and unsigned binaries fail
  closed without falling back to process-only authority.

The legacy bulk-ingestion, path-reopening file adapter, and combined-receipt
compatibility layer have been deleted. The local-file path is still
intentionally frozen at public host-certification admission: its descriptor
engine and 13-cell macOS/APFS evidence matrix are implemented and tested, and
`evidentrail doctor` exposes only their contentless health evidence, but ordinary
callers cannot mint the host certification token or read the file. Release work
still requires Apple-provisioned signing plus the signed/locked/reboot Keychain
matrix and dedicated-host durability/performance gates. It also requires non-synthetic preregistered
outcomes with broader downstream reader/tool-loop evaluation, and
a separately pinned hosted Evidentrail arm when its terms and case policy permit. The
current governed corpus and pinned-engine resource/output artifacts are method,
reproducibility, and trust-boundary evidence—not a general product-quality win.
No objective-saturation or exact selector-regret residual remains in the
original six-case Full corpus. The broader perturbation corpus now exposes two
repeatable selector residuals, but both are deterministic budget/order
pathologies with exact deterministic counterexamples. They justify testing a
bounded exact/DP/beam or order-aware selector before any learned ranker; the
current cost-matched stress checkpoint improves all three affected synthetic
cases without a recorded deterministic regression. The one completed paired
reader case also exposes no answer residual for a learned reader. Broader
reader/outcome evaluation remains required, and custom-model training remains
last.

The pinned external baseline state and comparison gate are recorded in
[`docs/EXTERNAL_BASELINE_STATUS.md`](docs/EXTERNAL_BASELINE_STATUS.md).

Sensitive schema, ingest, and core values use contentless `Debug` summaries.
Errors emit stable codes and numeric context without payloads, questions,
paths, provider identifiers, cursors, hashes, or free-form provider detail.

Run the current memory-only product loop with:

```bash
cargo run -p evidentrail-cli --bin evidentrail -- brief \
  --question "why did request REQ-7 fail?" \
  --token-budget 20000 < app.log
```

Use `--question-file` when the question should not appear in the process
argument list. The log source is intentionally standard input only in this
slice; shell redirection is the caller's explicit source choice. The current
`--token-budget` is a conservative whole-render bound using one UTF-8 output
byte per budget unit, not an OpenAI or other model-token count.

Run the contentless local-file self-check with:

```bash
cargo run -p evidentrail-cli --bin evidentrail -- doctor --file ./app.log
```

Doctor runs the frozen host matrix and inspects only metadata for that exact
file. Success is not approval: it reads no log contents, grants no source
authority, and cannot enable the production preflight path.

Run the process-resident MCP surface with:

```bash
cargo run -p evidentrail-cli --bin evidentrail -- serve-mcp
```

The MCP transport emits only protocol JSON on stdout. Its two tools operate on
explicit caller bytes and result-scoped aliases; this command is not the
durable production source service yet.

Run the checks with:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
