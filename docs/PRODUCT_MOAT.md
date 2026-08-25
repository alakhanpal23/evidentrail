# Product boundary and moat

The current competitor surface and the exact head-to-head falsification plan are
frozen in [`EVIDENTRAIL_COMPETITIVE_TEARDOWN.md`](EVIDENTRAIL_COMPETITIVE_TEARDOWN.md).
Evidentrail's newer action-reduction, local-retrieval, analytics, and policy claims
are treated as benchmark arms; they do not change this product into a generic
agent gateway.

**Date:** August 24, 2026  
**Product:** Greenfield Evidentrail diagnostic evidence compiler

## The wedge

Evidentrail is the read-only evidence layer between large local/CI/production log windows and a coding agent. A developer asks an ordinary debugging question; Evidentrail returns a small, cited Log Brief, an honest coverage bundle, and exact result-local expansion handles.

It does not replace the log store, diagnose autonomously, run remediation, or become a generic prompt compressor. The first polished workflow is deliberately narrow:

```text
approve one local file or CI artifact
  -> ask one debugging question
  -> receive bounded evidence + uncertainty + coverage
  -> expand a cited block or neighborhood exactly
  -> verify diagnosis/fix in the existing coding-agent loop
```

Success means higher verified diagnosis success at lower total episode cost, not the highest byte-compression ratio.

## What compounds into a moat

### 1. Verified evidence-outcome data

With separate explicit consent, Evidentrail can learn from the full chain that generic log products do not observe:

- exact bounded acquisition and completeness;
- which candidate lanes surfaced each clue;
- what was selected, omitted, and expanded;
- independently adjudicated required/precursor/symptom evidence;
- the coding agent's hypotheses and additional reads;
- verified root cause, fix, and executable outcome.

This produces marginal-utility labels for evidence selection rather than noisy “interesting log” labels. Project, organization, time, provider, and fault-family holdouts keep the model from learning duplicates. Revocation and training consent remain first-class lineage, so privacy shortcuts cannot become the data strategy.

### 2. Source-conformance knowledge

Every supported source accumulates a versioned conformance suite for pagination, caps, rotation, partial reads, identity changes, stream ordering, retention, and completeness proofs. This operational knowledge is tedious to reproduce and difficult to bolt onto a summarizer after the fact.

Connector count alone is not defensible. A smaller set of adapters that can prove their acquisition boundary is.

### 3. Trust architecture that is expensive to retrofit

The immutable authorized ledger, source-record authorization receipt, persisted-event presentation receipt, result-scoped exact expansion, ciphertext-only retention, and contentless diagnostics are designed before ranking. Competitors that discard provenance or mutate evidence during compression cannot add these guarantees with a renderer patch.

Trust is only a moat if tests enforce it. Contract, canary, crash, adversarial, and adapter-specific suites are release-blocking.

### 4. EvidentrailBench and the incident lab

The benchmark joins component integrity with the actual customer outcome:

- public reproducible parser/RCA/CI tracks;
- a hermetic multi-service incident lab with known faults and executable fixes;
- rotating hidden consented incidents;
- fixed single-shot, tool-loop, and blinded-human surfaces;
- costed candidate recall and verified diagnosis at total episode budget.

The moat is not a private leaderboard score. It is the ability to reproduce why a release wins, identify which loss boundary failed, and prevent a model from hiding retrieval damage.

### 5. Residual-learning flywheel

Deterministic lanes establish what can be solved cheaply. Only residual ranking failures become model training examples:

```text
more verified incidents
  -> better failure attribution by acquisition / framing / candidate / packer / reader
  -> cleaner marginal-utility labels
  -> smaller, more targeted local ranker
  -> higher VDS@B and fewer broad expansions
  -> more product use and separately consented outcomes
```

The engine contract stays fixed while model estimates improve. This lets Evidentrail compare a learned ranker with deterministic behavior case-by-case, fall back safely, and run customer-owned models without changing the product surface.

### 6. Workflow integration and expansion memory

Repository-to-source bindings, safe provider scopes, result-local references, and consistent expansion relations make Evidentrail the stable evidence interface used by many coding agents. The integration advantage is schema and trust compatibility, not lock-in to one model vendor.

## What is not a moat

- Drain-style template extraction or any single parser;
- a generic LLM summary prompt;
- compression-ratio claims;
- a large connector catalog with unknown completeness;
- embeddings or an off-the-shelf reranker;
- a proprietary LLM without unique verified labels;
- storing customer logs by default;
- an autonomous RCA narrative that cannot prove its evidence.

All of these are reproducible or actively damage trust. They remain baselines, optional features, or explicit non-goals.

## Product sequencing that protects the moat

1. **Trustworthy local walking skeleton:** one explicit file/replay, streaming authorization, encrypted/memory-only ledger, passthrough Log Brief, two tools, exact expansion.
2. **Deterministic evidence advantage:** three active candidate lanes, costed union, monotone packer, honest `needs_more`, strong raw/hybrid/BM25F comparisons.
3. **Production proof:** a few fully conformant CI/cloud sources, incident lab, hidden consented cases, tool-loop VDS@B.
4. **Learned ranking:** train only on verified residual failures; target candidate affinity/role/uncertainty, not generated diagnosis.
5. **Enterprise compounding:** customer-owned evaluation/training options, governance, conformance reports, and organization-specific calibration without centralizing raw content.

Each stage must improve the same outcome metric and preserve the same evidence contract. A feature that increases apparent compression but does not move the verified diagnosis Pareto frontier is not part of the core product.

## Moat scorecard

| Asset | Leading indicator | Release proof |
| --- | --- | --- |
| Evidence/outcome corpus | independently adjudicated, family-distinct consented cases | hidden-family VDS@B lift without worst-slice collapse |
| Source conformance | certified adapter/provider/runtime cells | zero false-complete acquisitions in the conformance suite |
| Trust architecture | contract and security tests | zero unmarked mutation, unaccounted record, plaintext spill, or Evidentrail-owned log-derived action |
| Deterministic engine | lane-unique yield and recall-cost curve | statistically supported Pareto improvement over reserved hybrid and BM25F |
| Expansion loop | clue-bearing expansion rate and avoided broad rereads | lower total episode calls/tokens/time at equal or better diagnosis success |
| Learned ranker | residual errors with actionable labels | incremental hidden VDS@B gain over deterministic Evidentrail with no trust regression |

## The durable claim

> Evidentrail's advantage is not that it can delete more log text. It is that it knows, can prove, and can learn which exact evidence preserves a verified debugging outcome under a real budget—without giving log content authority or silently taking custody of customer data.
