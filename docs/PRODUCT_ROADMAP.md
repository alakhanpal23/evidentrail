# Product roadmap: speed leadership and LLM-assisted evidence

**Date:** August 29, 2026
**Status:** Product direction; release claims remain gated by EvidentrailBench
**Scope:** Extends the deterministic evidence compiler without weakening its
authorization, provenance, exact-expansion, or uncertainty contracts

## North star

Make Evidentrail the fastest trustworthy way for agents and humans to turn very large
logs into the evidence needed to debug a real incident.

"Fastest" means the best measured time-to-useful-evidence and throughput on a
reproducible, same-hardware, same-input, same-budget comparison while preserving
equal or better verified diagnosis, citation correctness, and exact expansion.
It does not mean claiming leadership from compression ratio or a single local
timing. Market baselines are refreshed before any public leadership claim.

The product will support two complementary paths:

1. a deterministic local fast path that is always available, auditable, and
   suitable for sensitive logs; and
2. optional LLM assistance that can improve question understanding, evidence
   ranking, and presentation for a coding agent or a human operator.

Compression remains evidence reduction, not arbitrary token deletion. Exact
authorized source bytes stay available behind every evidence reference.

## Roadmap

### R0 — Establish the performance frontier

- Add reproducible cold-start and warm-run benchmarks at 10K, 100K, and 1M
  records, including small exact-passthrough cases.
- Measure time to first evidence, end-to-end p50/p95/p99 latency, records and
  bytes per second, CPU time, peak RSS, output bytes/tokens, and total episode
  time.
- Run matched baselines for raw truncation, grep/head/tail, BM25F-style
  retrieval, pinned Drain-family tools, the current public Evidentrail surface when
  permitted, and admitted LLM reducers.
- Publish the full quality/speed/cost Pareto frontier. Set numeric performance
  SLOs only after the first controlled baseline is frozen.

Exit gate: the harness is reproducible, competitor versions and hardware are
pinned, and no speed claim hides a diagnosis, citation, completeness, memory,
or cost regression.

### R1 — Build the market-leading deterministic fast path

- Profile the whole acquisition-to-brief pipeline and remove copies,
  allocations, serialization passes, and repeated tokenization from the hot
  path.
- Keep acquisition, framing, and candidate generation streaming and
  bounded-memory; parallelize only independent lanes with deterministic merge
  semantics.
- Preserve the instant exact-passthrough route for inputs that already fit.
- Add incremental compilation and safe reuse for repeated questions over the
  same authorized snapshot.
- Keep a low-latency fallback that never requires a model, network call, or
  warmed cache.

Exit gate: Evidentrail is on the non-dominated latency/throughput frontier against
the refreshed matched market set, with all existing trust and outcome gates
passing. "Fastest on the market" may be used only if the controlled results
actually support it.

### R2 — Define an optional LLM-assistance contract

- Accept an explicit debugging question, audience (`agent` or `human`), output
  budget, and caller-approved context as model inputs.
- Support pluggable local, customer-owned, and separately approved hosted
  models behind one provider-neutral interface.
- Let models propose query expansion, candidate affinity, semantic roles,
  timelines, and cited synopsis text. The deterministic compiler validates the
  proposal and owns the final evidence membership, receipts, and references.
- Run every model or compression technique first as a shadow challenger against
  the deterministic path, generic LLM summaries, and the strongest available
  log-reduction tools.
- Record model identity, prompt/configuration digest, latency, token usage,
  monetary cost, and every accepted or rejected proposal.

Exit gate: LLM assistance improves the held-out verified-diagnosis Pareto
frontier or materially improves human task completion without citation,
privacy, safety, latency, or worst-slice regression.

### R3 — Ship agent and human evidence products

- **Agent Evidence Pack:** compact, stable, machine-readable evidence; typed
  uncertainty; exact citations; and bounded expansion handles optimized for
  tool loops.
- **Human Incident Brief:** a readable failure summary and timeline, likely
  clues clearly separated from facts, coverage/omission warnings, and clickable
  evidence references.
- Allow the same captured result to render both views without reacquisition or
  divergent evidence identities.
- Add an automatic policy-aware router that chooses exact passthrough,
  deterministic compilation, or an admitted LLM-assisted method based on
  audience, budget, privacy policy, expected utility, and latency SLO.

Exit gate: both surfaces beat their appropriate matched baselines in agent
tool-loop and blinded-human evaluation. A faster output that produces a worse
debugging result does not pass.

### R4 — Learn from verified residuals

- Train or calibrate ranking only on separately consented, verified debugging
  outcomes and failures that deterministic improvements do not solve.
- Prefer small local models or distillation when they retain the measured
  benefit at lower latency, cost, and privacy exposure.
- Maintain deterministic fallback, customer-owned model options, revocation,
  versioned evaluation, and per-slice rollback.

Exit gate: the learned path demonstrates incremental held-out value over the
best deterministic release and can be disabled without changing the evidence
contract.

## Product scorecard

| Goal | Primary measures | Guardrails |
| --- | --- | --- |
| Fastest useful result | time to first useful evidence; p50/p95/p99 end-to-end latency | verified diagnosis, citation correctness, honest abstention |
| Highest sustained speed | records/s and bytes/s at 10K, 100K, and 1M records | peak RSS, CPU, bounded backpressure, determinism |
| Best agent input | diagnosis/fix success at total episode budget | tool calls, input/output tokens, expansions, unsupported claims |
| Best human input | time to correct diagnosis and reviewer confidence | source traceability, omission awareness, false certainty |
| Best reduction | source bytes and model tokens avoided at equal outcome | intact blocks, exact expansion, no unmarked mutation |
| Useful LLM lift | incremental held-out outcome gain over deterministic Evidentrail | latency, cost, privacy, worst-slice and safety regressions |

## Non-negotiable boundaries

- LLM output is a proposal or a cited secondary explanation, never the source
  record.
- No model may widen acquisition scope, grant tool authority, suppress required
  receipts, invent completeness, or make exact expansion inexact.
- Hosted model access is explicit and policy-controlled; local deterministic
  operation remains a first-class product.
- Agent and human presentations can differ, but they share one evidence
  identity and one auditable loss account.
- Market leadership is a benchmark result that expires as products and
  versions change, not a permanent architectural assertion.

This roadmap complements the deterministic execution program in
[`GREENFIELD_EXECUTION_PROGRAM.md`](GREENFIELD_EXECUTION_PROGRAM.md), the
evaluation rules in [`EVIDENTRAILBENCH_PROTOCOL.md`](EVIDENTRAILBENCH_PROTOCOL.md), and the
trust strategy in [`PRODUCT_MOAT.md`](PRODUCT_MOAT.md).
